#import "SSHCoreOpenSSHClient.h"

#import <SSHKitObjC/SSHKitConfiguration.h>
#import <SSHKitObjC/SSHKitConnection.h>
#import <SSHKitObjC/SSHKitError.h>

#import <TargetConditionals.h>

#if TARGET_OS_OSX
#include <math.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/stat.h>
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
    SSHCoreProcessResult *result = [self runSSHWithRemoteCommand:command
                                                         timeout:self.configuration.timeout
                                                       operation:@"command"
                                                           error:error];
    if (!result) {
        return nil;
    }

    return [[SSHKitCommandResult alloc] initWithStandardOutput:result.standardOutput
                                                standardError:result.standardError
                                                   exitStatus:result.exitStatus];
#else
    if (error) {
        *error = SSHKitMakeError(SSHKitErrorCodeUnavailable, @"OpenSSH process backend is available on macOS only.");
    }
    return nil;
#endif
}

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
                                                   timeout:(NSTimeInterval)timeout
                                                 operation:(NSString *)operation
                                                     error:(NSError **)error {
    NSTask *task = [[NSTask alloc] init];
    task.executableURL = [NSURL fileURLWithPath:@"/usr/bin/ssh"];
    task.arguments = [[self sshArgumentsWithRemoteCommand:remoteCommand] copy];

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

- (NSMutableArray<NSString *> *)sshArgumentsWithRemoteCommand:(NSString *)remoteCommand {
    NSMutableArray<NSString *> *arguments = [[NSMutableArray alloc] init];
    [arguments addObjectsFromArray:@[
        @"-F", @"/dev/null",
        @"-p", [NSString stringWithFormat:@"%hu", self.configuration.port],
        @"-o", [NSString stringWithFormat:@"ConnectTimeout=%ld", (long)ceil(self.configuration.timeout)],
        @"-o", @"NumberOfPasswordPrompts=1",
        @"-o", @"LogLevel=ERROR",
    ]];

    [self appendHostKeyArgumentsToArguments:arguments];
    [self appendAuthenticationArgumentsToArguments:arguments];

    NSString *destination = [NSString stringWithFormat:@"%@@%@", self.configuration.username, self.configuration.host];
    [arguments addObject:destination];
    [arguments addObject:remoteCommand];
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
