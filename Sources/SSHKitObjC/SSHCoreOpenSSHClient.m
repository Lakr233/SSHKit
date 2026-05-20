#import "SSHCoreOpenSSHClient.h"

#import <SSHKitObjC/SSHKitConfiguration.h>
#import <SSHKitObjC/SSHKitConnection.h>
#import <SSHKitObjC/SSHKitError.h>

#import <TargetConditionals.h>
#import "SSHKitShell+Private.h"

#if TARGET_OS_OSX
#include <errno.h>
#include <math.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <termios.h>
#include <util.h>
#include <unistd.h>

@interface SSHCoreProcessResult : NSObject

@property (nonatomic) int32_t exitStatus;
@property (nonatomic) NSMutableData *standardOutput;
@property (nonatomic) NSMutableData *standardError;

@end

@implementation SSHCoreProcessResult

- (instancetype)init {
    self = [super init];
    if (self) {
        _standardOutput = [[NSMutableData alloc] init];
        _standardError = [[NSMutableData alloc] init];
    }
    return self;
}

@end

@interface SSHCoreOpenSSHShellRuntime : NSObject

- (instancetype)initWithTask:(NSTask *)task
        masterFileDescriptor:(int)masterFileDescriptor
                eventHandler:(SSHKitShellEventHandler)eventHandler
                    onClosed:(SSHCoreShellClosedBlock)onClosed;
- (void)start;
- (void)writeData:(NSData *)data completion:(SSHKitCompletion)completion;
- (void)resizeWithColumns:(uint16_t)columns rows:(uint16_t)rows completion:(SSHKitCompletion)completion;
- (void)closeWithCompletion:(SSHKitCompletion)completion;

@end

@interface SSHCoreOpenSSHShellRuntime ()

@property (nonatomic) NSTask *task;
@property (nonatomic) int masterFileDescriptor;
@property (nonatomic, copy) SSHKitShellEventHandler eventHandler;
@property (nonatomic, copy) SSHCoreShellClosedBlock onClosed;
@property (nonatomic) dispatch_source_t readSource;
@property (nonatomic) dispatch_queue_t eventQueue;
@property (nonatomic) NSLock *lock;
@property (nonatomic) BOOL closed;
@property (nonatomic) BOOL didFinish;

@end

@implementation SSHCoreOpenSSHShellRuntime

- (instancetype)initWithTask:(NSTask *)task
        masterFileDescriptor:(int)masterFileDescriptor
                eventHandler:(SSHKitShellEventHandler)eventHandler
                    onClosed:(SSHCoreShellClosedBlock)onClosed {
    self = [super init];
    if (self) {
        _task = task;
        _masterFileDescriptor = masterFileDescriptor;
        _eventHandler = [eventHandler copy];
        _onClosed = [onClosed copy];
        _lock = [[NSLock alloc] init];
        _eventQueue = dispatch_queue_create("io.github.sshkit.core.openssh-shell.events", DISPATCH_QUEUE_SERIAL);

        __weak SSHCoreOpenSSHShellRuntime *weakSelf = self;
        _task.terminationHandler = ^(NSTask *terminatedTask) {
            [weakSelf finishWithExitStatus:terminatedTask.terminationStatus];
        };
    }
    return self;
}

- (void)start {
    int flags = fcntl(self.masterFileDescriptor, F_GETFL, 0);
    if (flags >= 0) {
        fcntl(self.masterFileDescriptor, F_SETFL, flags | O_NONBLOCK);
    }

    self.readSource = dispatch_source_create(DISPATCH_SOURCE_TYPE_READ,
                                             (uintptr_t)self.masterFileDescriptor,
                                             0,
                                             self.eventQueue);
    dispatch_source_set_event_handler(self.readSource, ^{
        [self drainMasterFileDescriptor];
    });
    dispatch_source_set_cancel_handler(self.readSource, ^{
        [self.lock lock];
        if (self.masterFileDescriptor >= 0) {
            close(self.masterFileDescriptor);
            self.masterFileDescriptor = -1;
        }
        [self.lock unlock];
    });

    dispatch_resume(self.readSource);
}

- (void)drainMasterFileDescriptor {
    uint8_t buffer[4096];
    while (YES) {
        ssize_t bytesRead = read(self.masterFileDescriptor, buffer, sizeof(buffer));
        if (bytesRead > 0) {
            NSData *data = [NSData dataWithBytes:buffer length:(NSUInteger)bytesRead];
            SSHKitShellEvent *event = [[SSHKitShellEvent alloc] initWithKind:SSHKitShellEventKindStandardOutput
                                                                        data:data
                                                                  exitStatus:0];
            self.eventHandler(event);
            continue;
        }

        if (bytesRead == 0) {
            return;
        }

        if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
            return;
        }

        return;
    }
}

- (void)writeData:(NSData *)data completion:(SSHKitCompletion)completion {
    [self.lock lock];
    BOOL isClosed = self.closed;
    int fileDescriptor = self.masterFileDescriptor;

    if (isClosed || fileDescriptor < 0) {
        [self.lock unlock];
        completion(SSHKitMakeError(SSHKitErrorCodeInvalidState, @"SSH shell is closed."));
        return;
    }

    const uint8_t *bytes = data.bytes;
    NSUInteger remaining = data.length;
    while (remaining > 0) {
        ssize_t written = write(fileDescriptor, bytes, remaining);
        if (written < 0 && errno == EINTR) {
            continue;
        }
        if (written < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            if (![self waitForWritableFileDescriptor:fileDescriptor]) {
                [self.lock unlock];
                completion(SSHKitMakeError(SSHKitErrorCodeConnectionFailed, @"Timed out waiting for SSH shell input buffer."));
                return;
            }
            continue;
        }
        if (written <= 0) {
            [self.lock unlock];
            completion(SSHKitMakeError(SSHKitErrorCodeConnectionFailed, @"Unable to write to SSH shell."));
            return;
        }
        bytes += written;
        remaining -= (NSUInteger)written;
    }

    [self.lock unlock];
    completion(nil);
}

- (void)resizeWithColumns:(uint16_t)columns rows:(uint16_t)rows completion:(SSHKitCompletion)completion {
    [self.lock lock];
    BOOL isClosed = self.closed;
    int fileDescriptor = self.masterFileDescriptor;

    if (isClosed || fileDescriptor < 0) {
        [self.lock unlock];
        completion(SSHKitMakeError(SSHKitErrorCodeInvalidState, @"SSH shell is closed."));
        return;
    }

    struct winsize size = {0};
    size.ws_col = columns;
    size.ws_row = rows;
    if (ioctl(fileDescriptor, TIOCSWINSZ, &size) != 0) {
        [self.lock unlock];
        completion(SSHKitMakeError(SSHKitErrorCodeConnectionFailed, @"Unable to resize SSH shell PTY."));
        return;
    }

    [self.lock unlock];
    completion(nil);
}

- (void)closeWithCompletion:(SSHKitCompletion)completion {
    [self.lock lock];
    BOOL alreadyClosed = self.closed;
    self.closed = YES;
    dispatch_source_t readSource = self.readSource;
    self.readSource = nil;
    [self.lock unlock];

    if (!alreadyClosed && readSource) {
        dispatch_source_cancel(readSource);
    }

    if (self.task.isRunning) {
        [self.task terminate];
    }

    completion(nil);
}

- (void)finishWithExitStatus:(int32_t)exitStatus {
    [self.lock lock];
    if (self.didFinish) {
        [self.lock unlock];
        return;
    }
    self.didFinish = YES;
    self.closed = YES;
    dispatch_source_t readSource = self.readSource;
    self.readSource = nil;
    [self.lock unlock];

    if (readSource) {
        dispatch_sync(self.eventQueue, ^{
            [self drainMasterFileDescriptor];
        });
        dispatch_source_cancel(readSource);
    }

    self.onClosed(exitStatus);
}

- (BOOL)waitForWritableFileDescriptor:(int)fileDescriptor {
    fd_set writeSet;
    FD_ZERO(&writeSet);
    FD_SET(fileDescriptor, &writeSet);
    struct timeval timeout = { .tv_sec = 5, .tv_usec = 0 };
    int result = select(fileDescriptor + 1, NULL, &writeSet, NULL, &timeout);
    return result > 0 && FD_ISSET(fileDescriptor, &writeSet);
}

- (void)dealloc {
    [self.lock lock];
    int fileDescriptor = self.masterFileDescriptor;
    self.masterFileDescriptor = -1;
    [self.lock unlock];

    if (fileDescriptor >= 0) {
        close(fileDescriptor);
    }
}

@end

#endif

@interface SSHCoreOpenSSHClient ()

@property (nonatomic, copy) SSHKitConfiguration *configuration;
@property (nonatomic, copy, nullable) NSString *temporaryAskPassScriptPath;
@property (nonatomic, copy, nullable) NSString *temporaryAskPassSecretPath;
@property (nonatomic) NSLock *taskLock;
@property (nonatomic, nullable) id currentTask;
@property (nonatomic) BOOL taskCancelled;

@end

@implementation SSHCoreOpenSSHClient

- (instancetype)initWithConfiguration:(SSHKitConfiguration *)configuration {
    self = [super init];
    if (self) {
        _configuration = [configuration copy];
        _taskLock = [[NSLock alloc] init];
    }
    return self;
}

- (BOOL)verifyConnectionWithError:(NSError **)error {
#if TARGET_OS_OSX
    SSHCoreProcessResult *result = [self runSSHWithRemoteCommand:@"true"
                                                      requestPTY:NO
                                                         timeout:self.configuration.timeout
                                                       operation:@"connect"
                                                           error:error];
    if (!result) {
        return NO;
    }

    if (result.exitStatus == 0) {
        return YES;
    }

    if (error) {
        *error = [self mappedErrorForExitStatus:result.exitStatus standardError:result.standardError operation:@"connect"];
    }
    return NO;
#else
    if (error) {
        *error = SSHKitMakeError(SSHKitErrorCodeUnavailable, @"OpenSSH process backend is available on macOS only.");
    }
    return NO;
#endif
}

- (nullable SSHKitCommandResult *)executeCommand:(NSString *)command error:(NSError **)error {
#if TARGET_OS_OSX
    return [self executeCommand:command requestPTY:NO error:error];
#else
    if (error) {
        *error = SSHKitMakeError(SSHKitErrorCodeUnavailable, @"OpenSSH process backend is available on macOS only.");
    }
    return nil;
#endif
}

- (nullable SSHKitCommandResult *)executePTYCommand:(NSString *)command error:(NSError **)error {
#if TARGET_OS_OSX
    return [self executeCommand:command requestPTY:YES error:error];
#else
    if (error) {
        *error = SSHKitMakeError(SSHKitErrorCodeUnavailable, @"OpenSSH process backend is available on macOS only.");
    }
    return nil;
#endif
}

- (nullable SSHKitShell *)openShellWithTerminalType:(NSString *)terminalType
                                            columns:(uint16_t)columns
                                               rows:(uint16_t)rows
                                       eventHandler:(SSHKitShellEventHandler)eventHandler
                                           onClosed:(SSHCoreShellClosedBlock)onClosed
                                              error:(NSError **)error {
#if TARGET_OS_OSX
    NSTask *task = [[NSTask alloc] init];
    task.executableURL = [NSURL fileURLWithPath:@"/usr/bin/ssh"];
    task.arguments = [[self sshArgumentsWithRemoteCommand:nil requestPTY:YES] copy];

    NSError *environmentError = nil;
    NSMutableDictionary<NSString *, NSString *> *environment = [[self environmentForTaskWithError:&environmentError] mutableCopy];
    if (!environment) {
        if (error) {
            *error = environmentError;
        }
        return nil;
    }
    environment[@"TERM"] = terminalType;
    task.environment = environment;

    int masterFileDescriptor = -1;
    int slaveFileDescriptor = -1;
    struct winsize initialSize = {0};
    initialSize.ws_col = columns;
    initialSize.ws_row = rows;
    if (openpty(&masterFileDescriptor, &slaveFileDescriptor, NULL, NULL, &initialSize) != 0) {
        if (error) {
            *error = SSHKitMakeError(SSHKitErrorCodeConnectionFailed, @"Unable to allocate local PTY for SSH shell.");
        }
        return nil;
    }

    int stdinFileDescriptor = dup(slaveFileDescriptor);
    int stdoutFileDescriptor = dup(slaveFileDescriptor);
    int stderrFileDescriptor = dup(slaveFileDescriptor);
    close(slaveFileDescriptor);
    if (stdinFileDescriptor < 0 || stdoutFileDescriptor < 0 || stderrFileDescriptor < 0) {
        if (stdinFileDescriptor >= 0) {
            close(stdinFileDescriptor);
        }
        if (stdoutFileDescriptor >= 0) {
            close(stdoutFileDescriptor);
        }
        if (stderrFileDescriptor >= 0) {
            close(stderrFileDescriptor);
        }
        close(masterFileDescriptor);
        if (error) {
            *error = SSHKitMakeError(SSHKitErrorCodeConnectionFailed, @"Unable to prepare SSH shell PTY handles.");
        }
        return nil;
    }

    task.standardInput = [[NSFileHandle alloc] initWithFileDescriptor:stdinFileDescriptor closeOnDealloc:YES];
    task.standardOutput = [[NSFileHandle alloc] initWithFileDescriptor:stdoutFileDescriptor closeOnDealloc:YES];
    task.standardError = [[NSFileHandle alloc] initWithFileDescriptor:stderrFileDescriptor closeOnDealloc:YES];

    SSHCoreOpenSSHShellRuntime *runtime = [[SSHCoreOpenSSHShellRuntime alloc] initWithTask:task
                                                                      masterFileDescriptor:masterFileDescriptor
                                                                              eventHandler:eventHandler
                                                                                  onClosed:^(int32_t exitStatus) {
        [self clearCurrentTask:task];
        [self removeAskPassFilesIfNeeded];
        onClosed(exitStatus);
    }];

    [self.taskLock lock];
    self.currentTask = task;
    BOOL wasCancelledBeforeLaunch = self.taskCancelled;
    [self.taskLock unlock];

    if (wasCancelledBeforeLaunch) {
        [self clearCurrentTask:task];
        [self removeAskPassFilesIfNeeded];
        if (error) {
            *error = SSHKitMakeError(SSHKitErrorCodeCancelled, @"SSH shell was cancelled before launch.");
        }
        return nil;
    }

    NSError *launchError = nil;
    if (![task launchAndReturnError:&launchError]) {
        [self clearCurrentTask:task];
        [self removeAskPassFilesIfNeeded];
        if (error) {
            *error = SSHKitMakeError(SSHKitErrorCodeUnavailable, launchError.localizedDescription);
        }
        return nil;
    }

    [runtime start];

    SSHKitShell *shell = [[SSHKitShell alloc] initWithWriteBlock:^(NSData *data, SSHKitCompletion completion) {
        [runtime writeData:data completion:completion];
    } resizeBlock:^(uint16_t resizeColumns, uint16_t resizeRows, SSHKitCompletion completion) {
        [runtime resizeWithColumns:resizeColumns rows:resizeRows completion:completion];
    } closeBlock:^(SSHKitCompletion completion) {
        [runtime closeWithCompletion:completion];
    }];
    return shell;
#else
    if (error) {
        *error = SSHKitMakeError(SSHKitErrorCodeUnavailable, @"OpenSSH process backend is available on macOS only.");
    }
    return nil;
#endif
}

#if TARGET_OS_OSX

- (nullable SSHKitCommandResult *)executeCommand:(NSString *)command
                                      requestPTY:(BOOL)requestPTY
                                           error:(NSError **)error {
    SSHCoreProcessResult *result = [self runSSHWithRemoteCommand:command
                                                      requestPTY:requestPTY
                                                         timeout:self.configuration.timeout
                                                       operation:@"command"
                                                           error:error];
    if (!result) {
        return nil;
    }

    return [[SSHKitCommandResult alloc] initWithStandardOutput:result.standardOutput
                                                standardError:result.standardError
                                                   exitStatus:result.exitStatus];
}

#endif

- (void)cancelCurrentTask {
#if TARGET_OS_OSX
    [self.taskLock lock];
    NSTask *task = self.currentTask;
    self.taskCancelled = YES;
    [self.taskLock unlock];

    if (!task || !task.isRunning) {
        return;
    }

    [task terminate];
#endif
}

#if TARGET_OS_OSX

- (nullable SSHCoreProcessResult *)runSSHWithRemoteCommand:(NSString *)remoteCommand
                                                requestPTY:(BOOL)requestPTY
                                                   timeout:(NSTimeInterval)timeout
                                                 operation:(NSString *)operation
                                                     error:(NSError **)error {
    NSTask *task = [[NSTask alloc] init];
    task.executableURL = [NSURL fileURLWithPath:@"/usr/bin/ssh"];
    task.arguments = [[self sshArgumentsWithRemoteCommand:remoteCommand requestPTY:requestPTY] copy];

    NSError *environmentError = nil;
    NSDictionary<NSString *, NSString *> *environment = [self environmentForTaskWithError:&environmentError];
    if (!environment) {
        if (error) {
            *error = environmentError;
        }
        return nil;
    }
    task.environment = environment;

    NSPipe *standardOutputPipe = [NSPipe pipe];
    NSPipe *standardErrorPipe = [NSPipe pipe];
    task.standardInput = NSFileHandle.fileHandleWithNullDevice;
    task.standardOutput = standardOutputPipe;
    task.standardError = standardErrorPipe;

    SSHCoreProcessResult *result = [[SSHCoreProcessResult alloc] init];
    dispatch_group_t readers = dispatch_group_create();

    [self.taskLock lock];
    self.currentTask = task;
    BOOL wasCancelledBeforeLaunch = self.taskCancelled;
    [self.taskLock unlock];

    if (wasCancelledBeforeLaunch) {
        [self clearCurrentTask:task];
        [self removeAskPassFilesIfNeeded];
        if (error) {
            *error = SSHKitMakeError(SSHKitErrorCodeCancelled, @"SSH operation was cancelled.");
        }
        return nil;
    }

    NSError *launchError = nil;
    if (![task launchAndReturnError:&launchError]) {
        if (error) {
            *error = SSHKitMakeError(SSHKitErrorCodeUnavailable, launchError.localizedDescription);
        }
        [self clearCurrentTask:task];
        [self removeAskPassFilesIfNeeded];
        return nil;
    }

    [self readPipe:standardOutputPipe intoData:result.standardOutput group:readers];
    [self readPipe:standardErrorPipe intoData:result.standardError group:readers];

    [self.taskLock lock];
    BOOL wasCancelledAfterLaunch = self.taskCancelled;
    [self.taskLock unlock];
    if (wasCancelledAfterLaunch) {
        [self cancelCurrentTask];
    }

    if (![self waitForTask:task timeout:timeout]) {
        [self cancelCurrentTask];
        [task waitUntilExit];
        dispatch_group_wait(readers, DISPATCH_TIME_FOREVER);
        [self clearCurrentTask:task];
        [self removeAskPassFilesIfNeeded];
        if (error) {
            *error = SSHKitMakeError(SSHKitErrorCodeConnectionFailed, [NSString stringWithFormat:@"SSH %@ timed out.", operation]);
        }
        return nil;
    }

    dispatch_group_wait(readers, DISPATCH_TIME_FOREVER);
    BOOL wasCancelled = [self clearCurrentTask:task];
    result.exitStatus = task.terminationStatus;
    [self removeAskPassFilesIfNeeded];

    if (wasCancelled) {
        if (error) {
            *error = SSHKitMakeError(SSHKitErrorCodeCancelled, @"SSH operation was cancelled.");
        }
        return nil;
    }

    return result;
}

- (NSMutableArray<NSString *> *)sshArgumentsWithRemoteCommand:(nullable NSString *)remoteCommand requestPTY:(BOOL)requestPTY {
    NSMutableArray<NSString *> *arguments = [[NSMutableArray alloc] init];
    [arguments addObjectsFromArray:@[
        @"-F", @"/dev/null",
        @"-p", [NSString stringWithFormat:@"%hu", self.configuration.port],
        @"-o", [NSString stringWithFormat:@"ConnectTimeout=%ld", (long)ceil(self.configuration.timeout)],
        @"-o", @"NumberOfPasswordPrompts=1",
        @"-o", @"LogLevel=ERROR",
    ]];

    if (requestPTY) {
        [arguments addObject:@"-tt"];
    }

    [self appendHostKeyArgumentsToArguments:arguments];
    [self appendAuthenticationArgumentsToArguments:arguments];

    NSString *destination = [NSString stringWithFormat:@"%@@%@", self.configuration.username, self.configuration.host];
    [arguments addObject:destination];
    if (remoteCommand.length > 0) {
        [arguments addObject:remoteCommand];
    }
    return arguments;
}

- (void)appendHostKeyArgumentsToArguments:(NSMutableArray<NSString *> *)arguments {
    switch (self.configuration.hostKeyPolicyKind) {
        case SSHKitHostKeyPolicyKindKnownHostsFile:
            [arguments addObjectsFromArray:@[
                @"-o", @"StrictHostKeyChecking=yes",
                @"-o", @"GlobalKnownHostsFile=/dev/null",
                @"-o", [NSString stringWithFormat:@"UserKnownHostsFile=%@", self.configuration.knownHostsPath ?: @"/dev/null"],
            ]];
            break;
        case SSHKitHostKeyPolicyKindAcceptAnyVerifiedHostKey:
            [arguments addObjectsFromArray:@[
                @"-o", @"StrictHostKeyChecking=accept-new",
                @"-o", @"GlobalKnownHostsFile=/dev/null",
                @"-o", @"UserKnownHostsFile=/dev/null",
            ]];
            break;
    }
}

- (void)appendAuthenticationArgumentsToArguments:(NSMutableArray<NSString *> *)arguments {
    switch (self.configuration.authenticationKind) {
        case SSHKitAuthenticationKindPassword:
            [arguments addObjectsFromArray:@[
                @"-o", @"PreferredAuthentications=password",
                @"-o", @"PubkeyAuthentication=no",
                @"-o", @"KbdInteractiveAuthentication=no",
            ]];
            break;
        case SSHKitAuthenticationKindPrivateKeyFile:
            [arguments addObjectsFromArray:@[
                @"-o", @"PreferredAuthentications=publickey",
                @"-o", @"IdentitiesOnly=yes",
                @"-i", self.configuration.privateKeyPath ?: @"",
            ]];
            break;
    }
}

- (nullable NSDictionary<NSString *, NSString *> *)environmentForTaskWithError:(NSError **)error {
    NSMutableDictionary<NSString *, NSString *> *environment = [NSProcessInfo.processInfo.environment mutableCopy];
    NSString *secret = [self askPassSecret];
    if (secret.length > 0) {
        NSString *askPassSecretPath = [self createAskPassSecretFileWithSecret:secret error:error];
        if (!askPassSecretPath) {
            [self removeAskPassFilesIfNeeded];
            return nil;
        }

        NSString *askPassScriptPath = [self createAskPassScriptWithError:error];
        if (!askPassScriptPath) {
            [self removeAskPassFilesIfNeeded];
            return nil;
        }
        environment[@"SSH_ASKPASS"] = askPassScriptPath;
        environment[@"SSH_ASKPASS_REQUIRE"] = @"force";
        environment[@"DISPLAY"] = @"localhost:0";
        environment[@"SSHKIT_ASKPASS_SECRET_FILE"] = askPassSecretPath;
    }
    return environment;
}

- (nullable NSString *)askPassSecret {
    switch (self.configuration.authenticationKind) {
        case SSHKitAuthenticationKindPassword:
            return self.configuration.password;
        case SSHKitAuthenticationKindPrivateKeyFile:
            return self.configuration.privateKeyPassphrase;
    }
}

- (nullable NSString *)createAskPassSecretFileWithSecret:(NSString *)secret error:(NSError **)error {
    NSString *path = [NSTemporaryDirectory() stringByAppendingPathComponent:
                      [NSString stringWithFormat:@"sshkit-askpass-secret-%@", NSUUID.UUID.UUIDString]];
    int fileDescriptor = open(path.fileSystemRepresentation, O_CREAT | O_EXCL | O_WRONLY, 0600);
    if (fileDescriptor < 0) {
        if (error) {
            *error = SSHKitMakeError(SSHKitErrorCodeUnavailable, @"Unable to create temporary SSH askpass secret file.");
        }
        return nil;
    }

    NSData *secretData = [[secret stringByAppendingString:@"\n"] dataUsingEncoding:NSUTF8StringEncoding];
    ssize_t bytesWritten = write(fileDescriptor, secretData.bytes, secretData.length);
    close(fileDescriptor);

    if (bytesWritten != (ssize_t)secretData.length) {
        [NSFileManager.defaultManager removeItemAtPath:path error:nil];
        if (error) {
            *error = SSHKitMakeError(SSHKitErrorCodeUnavailable, @"Unable to write temporary SSH askpass secret file.");
        }
        return nil;
    }

    self.temporaryAskPassSecretPath = path;
    return path;
}

- (nullable NSString *)createAskPassScriptWithError:(NSError **)error {
    NSString *path = [NSTemporaryDirectory() stringByAppendingPathComponent:
                      [NSString stringWithFormat:@"sshkit-askpass-%@.sh", NSUUID.UUID.UUIDString]];
    NSString *script = @"#!/bin/sh\ncat \"$SSHKIT_ASKPASS_SECRET_FILE\"\nrm -f \"$SSHKIT_ASKPASS_SECRET_FILE\"\n";
    NSError *writeError = nil;
    if (![script writeToFile:path atomically:YES encoding:NSUTF8StringEncoding error:&writeError]) {
        if (error) {
            *error = SSHKitMakeError(SSHKitErrorCodeUnavailable, writeError.localizedDescription);
        }
        return nil;
    }

    if (chmod(path.fileSystemRepresentation, 0700) != 0) {
        if (error) {
            *error = SSHKitMakeError(SSHKitErrorCodeUnavailable, @"Unable to secure temporary SSH askpass helper.");
        }
        [NSFileManager.defaultManager removeItemAtPath:path error:nil];
        return nil;
    }

    self.temporaryAskPassScriptPath = path;
    return path;
}

- (void)removeAskPassFilesIfNeeded {
    NSArray<NSString *> *paths = @[self.temporaryAskPassScriptPath ?: @"", self.temporaryAskPassSecretPath ?: @""];
    for (NSString *path in paths) {
        if (path.length > 0 && [path.lastPathComponent hasPrefix:@"sshkit-askpass"]) {
            [NSFileManager.defaultManager removeItemAtPath:path error:nil];
        }
    }
    self.temporaryAskPassScriptPath = nil;
    self.temporaryAskPassSecretPath = nil;
}

- (void)readPipe:(NSPipe *)pipe intoData:(NSMutableData *)data group:(dispatch_group_t)group {
    dispatch_group_enter(group);
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
        NSData *pipeData = [pipe.fileHandleForReading readDataToEndOfFile];
        @synchronized (data) {
            [data appendData:pipeData];
        }
        dispatch_group_leave(group);
    });
}

- (NSError *)mappedErrorForExitStatus:(int32_t)exitStatus
                        standardError:(NSData *)standardError
                            operation:(NSString *)operation {
    NSString *message = [[NSString alloc] initWithData:standardError encoding:NSUTF8StringEncoding] ?: @"SSH operation failed.";
    if ([message rangeOfString:@"Permission denied" options:NSCaseInsensitiveSearch].location != NSNotFound) {
        return SSHKitMakeError(SSHKitErrorCodeAuthenticationFailed, message);
    }

    if ([message rangeOfString:@"Host key verification failed" options:NSCaseInsensitiveSearch].location != NSNotFound ||
        [message rangeOfString:@"REMOTE HOST IDENTIFICATION HAS CHANGED" options:NSCaseInsensitiveSearch].location != NSNotFound) {
        return SSHKitMakeError(SSHKitErrorCodeHostKeyVerificationFailed, message);
    }

    NSString *fallback = [NSString stringWithFormat:@"SSH %@ failed with exit status %d: %@", operation, exitStatus, message];
    return SSHKitMakeError(SSHKitErrorCodeConnectionFailed, fallback);
}

- (BOOL)waitForTask:(NSTask *)task timeout:(NSTimeInterval)timeout {
    if (!task.isRunning) {
        return YES;
    }

    dispatch_semaphore_t semaphore = dispatch_semaphore_create(0);
    task.terminationHandler = ^(NSTask *terminatedTask) {
        dispatch_semaphore_signal(semaphore);
    };
    if (!task.isRunning) {
        dispatch_semaphore_signal(semaphore);
    }

    dispatch_time_t deadline = dispatch_time(DISPATCH_TIME_NOW, (int64_t)(timeout * NSEC_PER_SEC));
    return dispatch_semaphore_wait(semaphore, deadline) == 0;
}

- (BOOL)clearCurrentTask:(NSTask *)task {
    [self.taskLock lock];
    BOOL wasCancelled = self.taskCancelled;
    if (self.currentTask == task) {
        self.currentTask = nil;
        self.taskCancelled = NO;
    }
    [self.taskLock unlock];
    return wasCancelled;
}

#endif

@end
