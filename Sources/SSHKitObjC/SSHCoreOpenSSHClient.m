#import "SSHCoreOpenSSHClient.h"

#import <CLibSSH/CLibSSH.h>
#import <SSHKitObjC/SSHKitConfiguration.h>
#import <SSHKitObjC/SSHKitConnection.h>
#import <SSHKitObjC/SSHKitError.h>
#import "SSHCoreSessionWorker.h"
#import "SSHCoreSocketHandle.h"
#import "SSHKitCommand+Private.h"
#import "SSHKitSFTPClient+Private.h"
#import "SSHKitShell+Private.h"
#import "SSHKitTunnelChannel+Private.h"

#include <objc/message.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <math.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

@class SSHCoreOpenSSHClient;

static const int32_t SSHCoreAbnormalExitStatus = -1;

static NSString *SSHCoreStringFromCString(const char *string) {
    return string != NULL ? [NSString stringWithUTF8String:string] : @"";
}

static NSString *_Nullable SSHCoreNullableStringFromCString(const char *string) {
    return string != NULL ? [NSString stringWithUTF8String:string] : nil;
}

static NSArray<NSNumber *> *SSHCoreAuthenticationMethodsFromMask(int methodMask) {
    NSMutableArray<NSNumber *> *methods = [[NSMutableArray alloc] init];
    if ((methodMask & SSH_AUTH_METHOD_NONE) != 0) {
        [methods addObject:@(SSHKitAuthenticationMethodNone)];
    }
    if ((methodMask & SSH_AUTH_METHOD_PASSWORD) != 0) {
        [methods addObject:@(SSHKitAuthenticationMethodPassword)];
    }
    if ((methodMask & SSH_AUTH_METHOD_PUBLICKEY) != 0) {
        [methods addObject:@(SSHKitAuthenticationMethodPublicKey)];
    }
    if ((methodMask & SSH_AUTH_METHOD_HOSTBASED) != 0) {
        [methods addObject:@(SSHKitAuthenticationMethodHostBased)];
    }
    if ((methodMask & SSH_AUTH_METHOD_INTERACTIVE) != 0) {
        [methods addObject:@(SSHKitAuthenticationMethodKeyboardInteractive)];
    }
    if ((methodMask & SSH_AUTH_METHOD_GSSAPI_MIC) != 0 || (methodMask & SSH_AUTH_METHOD_GSSAPI_KEYEX) != 0) {
        [methods addObject:@(SSHKitAuthenticationMethodGSSAPI)];
    }
    return methods;
}

static NSString *SSHCoreAuthenticationName(SSHKitAuthenticationKind kind) {
    switch (kind) {
        case SSHKitAuthenticationKindPassword:
            return @"password";
        case SSHKitAuthenticationKindPrivateKeyFile:
            return @"privateKeyFile";
        case SSHKitAuthenticationKindKeyboardInteractive:
            return @"keyboardInteractive";
    }
}

static NSString *SSHCoreHostKeyPolicyName(SSHKitHostKeyPolicyKind kind) {
    switch (kind) {
        case SSHKitHostKeyPolicyKindInsecureAcceptAnyHostKey:
            return @"insecureAcceptAnyHostKey";
        case SSHKitHostKeyPolicyKindKnownHostsFile:
            return @"knownHostsFile";
    }
}

@interface SSHCoreLibSSHCommandRuntime : NSObject

- (instancetype)initWithChannel:(ssh_channel)channel
                    workerQueue:(dispatch_queue_t)workerQueue
                    eventHandler:(SSHKitCommandEventHandler)eventHandler
                        onClosed:(SSHCoreCommandClosedBlock)onClosed;
- (void)start;
- (void)writeData:(NSData *)data completion:(SSHKitCompletion)completion;
- (void)sendEOFWithCompletion:(SSHKitCompletion)completion;
- (void)closeWithCompletion:(SSHKitCompletion)completion;
- (void)invalidateOnWorkerQueue;

@end

@interface SSHCoreLibSSHCommandRuntime ()

@property (nonatomic) ssh_channel channel;
@property (nonatomic) dispatch_queue_t workerQueue;
@property (nonatomic, copy) SSHKitCommandEventHandler eventHandler;
@property (nonatomic, copy) SSHCoreCommandClosedBlock onClosed;
@property (nonatomic) BOOL finished;
@property (nonatomic) BOOL didSendEOF;

@end

@implementation SSHCoreLibSSHCommandRuntime

- (instancetype)initWithChannel:(ssh_channel)channel
                    workerQueue:(dispatch_queue_t)workerQueue
                    eventHandler:(SSHKitCommandEventHandler)eventHandler
                        onClosed:(SSHCoreCommandClosedBlock)onClosed {
    NSParameterAssert(channel != NULL);
    NSParameterAssert(workerQueue != nil);

    self = [super init];
    if (self) {
        _channel = channel;
        _workerQueue = workerQueue;
        _eventHandler = [eventHandler copy];
        _onClosed = [onClosed copy];
    }
    return self;
}

- (void)start {
    dispatch_async(self.workerQueue, ^{
        [self readAvailableDataAndScheduleNextRead];
    });
}

- (void)writeData:(NSData *)data completion:(SSHKitCompletion)completion {
    dispatch_async(self.workerQueue, ^{
        if (self.finished || self.didSendEOF || self.channel == NULL) {
            completion(SSHKitMakeError(SSHKitErrorCodeInvalidState, @"SSH command input is closed."));
            return;
        }

        const uint8_t *bytes = data.bytes;
        NSUInteger remaining = data.length;
        while (remaining > 0) {
            uint32_t chunkLength = remaining > UINT32_MAX ? UINT32_MAX : (uint32_t)remaining;
            int written = ssh_channel_write(self.channel, bytes, chunkLength);
            if (written == SSH_ERROR) {
                completion(SSHKitMakeError(SSHKitErrorCodeConnectionFailed, @"Unable to write to SSH command."));
                return;
            }
            if (written <= 0) {
                completion(SSHKitMakeError(SSHKitErrorCodeConnectionFailed, @"SSH command write made no progress."));
                return;
            }
            bytes += written;
            remaining -= (NSUInteger)written;
        }

        completion(nil);
    });
}

- (void)sendEOFWithCompletion:(SSHKitCompletion)completion {
    dispatch_async(self.workerQueue, ^{
        if (self.finished || self.didSendEOF || self.channel == NULL) {
            completion(SSHKitMakeError(SSHKitErrorCodeInvalidState, @"SSH command input is closed."));
            return;
        }

        if (ssh_channel_send_eof(self.channel) != SSH_OK) {
            completion(SSHKitMakeError(SSHKitErrorCodeConnectionFailed, @"Unable to send SSH command EOF."));
            return;
        }

        self.didSendEOF = YES;
        completion(nil);
    });
}

- (void)closeWithCompletion:(SSHKitCompletion)completion {
    dispatch_async(self.workerQueue, ^{
        if (self.finished) {
            completion(nil);
            return;
        }

        [self finishWithExitStatus:SSHCoreAbnormalExitStatus];
        completion(nil);
    });
}

- (void)readAvailableDataAndScheduleNextRead {
    if (self.finished || self.channel == NULL) {
        return;
    }

    if (![self drainStream:0 eventKind:SSHKitCommandEventKindStandardOutput] ||
        ![self drainStream:1 eventKind:SSHKitCommandEventKindStandardError]) {
        [self finishWithExitStatus:-1];
        return;
    }

    if (ssh_channel_is_eof(self.channel) || ssh_channel_is_closed(self.channel)) {
        [self finishWithExitStatus:[self exitStatus]];
        return;
    }

    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 50 * NSEC_PER_MSEC), self.workerQueue, ^{
        [self readAvailableDataAndScheduleNextRead];
    });
}

- (BOOL)drainStream:(int)isStderr eventKind:(SSHKitCommandEventKind)eventKind {
    char buffer[32768];
    while (YES) {
        int byteCount = ssh_channel_read_nonblocking(self.channel, buffer, sizeof(buffer), isStderr);
        if (byteCount == SSH_ERROR) {
            return NO;
        }
        if (byteCount <= 0) {
            return YES;
        }

        NSData *data = [NSData dataWithBytes:buffer length:(NSUInteger)byteCount];
        SSHKitCommandEvent *event = [[SSHKitCommandEvent alloc] initWithKind:eventKind data:data exitStatus:0];
        self.eventHandler(event);
    }
}

- (int32_t)exitStatus {
    uint32_t exitCode = 0;
    if (self.channel == NULL) {
        return SSHCoreAbnormalExitStatus;
    }

    int exitState = ssh_channel_get_exit_state(self.channel, &exitCode, NULL, NULL);
    if (exitState != SSH_OK) {
        return SSHCoreAbnormalExitStatus;
    }

    return (int32_t)exitCode;
}

- (void)finishWithExitStatus:(int32_t)exitStatus {
    if (self.finished) {
        return;
    }

    self.finished = YES;
    ssh_channel channel = self.channel;
    self.channel = NULL;
    if (channel != NULL) {
        ssh_channel_send_eof(channel);
        ssh_channel_close(channel);
        ssh_channel_free(channel);
    }

    self.onClosed(exitStatus);
}

- (void)invalidateOnWorkerQueue {
    if (self.finished) {
        return;
    }

    self.finished = YES;
    ssh_channel channel = self.channel;
    self.channel = NULL;
    if (channel != NULL) {
        ssh_channel_send_eof(channel);
        ssh_channel_close(channel);
        ssh_channel_free(channel);
    }
}

- (void)dealloc {
    ssh_channel channel = self.channel;
    if (channel == NULL) {
        return;
    }
    dispatch_async(self.workerQueue, ^{
        ssh_channel_send_eof(channel);
        ssh_channel_close(channel);
        ssh_channel_free(channel);
    });
}

@end

@interface SSHCoreLibSSHShellRuntime : NSObject

- (instancetype)initWithChannel:(ssh_channel)channel
                    workerQueue:(dispatch_queue_t)workerQueue
                    eventHandler:(SSHKitShellEventHandler)eventHandler
                        onClosed:(SSHCoreShellClosedBlock)onClosed;
- (void)start;
- (void)writeData:(NSData *)data completion:(SSHKitCompletion)completion;
- (void)resizeWithColumns:(uint16_t)columns rows:(uint16_t)rows completion:(SSHKitCompletion)completion;
- (void)closeWithCompletion:(SSHKitCompletion)completion;
- (void)invalidateOnWorkerQueue;

@end

@interface SSHCoreLibSSHShellRuntime ()

@property (nonatomic) ssh_channel channel;
@property (nonatomic) dispatch_queue_t workerQueue;
@property (nonatomic, copy) SSHKitShellEventHandler eventHandler;
@property (nonatomic, copy) SSHCoreShellClosedBlock onClosed;
@property (nonatomic) BOOL finished;

@end

@implementation SSHCoreLibSSHShellRuntime

- (instancetype)initWithChannel:(ssh_channel)channel
                    workerQueue:(dispatch_queue_t)workerQueue
                    eventHandler:(SSHKitShellEventHandler)eventHandler
                        onClosed:(SSHCoreShellClosedBlock)onClosed {
    NSParameterAssert(channel != NULL);
    NSParameterAssert(workerQueue != nil);

    self = [super init];
    if (self) {
        _channel = channel;
        _workerQueue = workerQueue;
        _eventHandler = [eventHandler copy];
        _onClosed = [onClosed copy];
    }
    return self;
}

- (void)start {
    dispatch_async(self.workerQueue, ^{
        [self readAvailableDataAndScheduleNextRead];
    });
}

- (void)writeData:(NSData *)data completion:(SSHKitCompletion)completion {
    dispatch_async(self.workerQueue, ^{
        if (self.finished || self.channel == NULL) {
            completion(SSHKitMakeError(SSHKitErrorCodeInvalidState, @"SSH shell is closed."));
            return;
        }

        const uint8_t *bytes = data.bytes;
        NSUInteger remaining = data.length;
        while (remaining > 0) {
            uint32_t chunkLength = remaining > UINT32_MAX ? UINT32_MAX : (uint32_t)remaining;
            int written = ssh_channel_write(self.channel, bytes, chunkLength);
            if (written == SSH_ERROR) {
                completion(SSHKitMakeError(SSHKitErrorCodeConnectionFailed, @"Unable to write to SSH shell."));
                return;
            }
            if (written <= 0) {
                completion(SSHKitMakeError(SSHKitErrorCodeConnectionFailed, @"SSH shell write made no progress."));
                return;
            }
            bytes += written;
            remaining -= (NSUInteger)written;
        }

        completion(nil);
    });
}

- (void)resizeWithColumns:(uint16_t)columns rows:(uint16_t)rows completion:(SSHKitCompletion)completion {
    dispatch_async(self.workerQueue, ^{
        if (self.finished || self.channel == NULL) {
            completion(SSHKitMakeError(SSHKitErrorCodeInvalidState, @"SSH shell is closed."));
            return;
        }

        if (ssh_channel_change_pty_size(self.channel, columns, rows) != SSH_OK) {
            completion(SSHKitMakeError(SSHKitErrorCodeConnectionFailed, @"Unable to resize SSH shell PTY."));
            return;
        }

        completion(nil);
    });
}

- (void)closeWithCompletion:(SSHKitCompletion)completion {
    dispatch_async(self.workerQueue, ^{
        if (self.finished) {
            completion(nil);
            return;
        }

        [self finishWithExitStatus:SSHCoreAbnormalExitStatus];
        completion(nil);
    });
}

- (void)readAvailableDataAndScheduleNextRead {
    if (self.finished || self.channel == NULL) {
        return;
    }

    if (![self drainStream:0 eventKind:SSHKitShellEventKindStandardOutput] ||
        ![self drainStream:1 eventKind:SSHKitShellEventKindStandardError]) {
        [self finishWithExitStatus:-1];
        return;
    }

    if (ssh_channel_is_eof(self.channel) || ssh_channel_is_closed(self.channel)) {
        [self finishWithExitStatus:[self exitStatus]];
        return;
    }

    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 50 * NSEC_PER_MSEC), self.workerQueue, ^{
        [self readAvailableDataAndScheduleNextRead];
    });
}

- (BOOL)drainStream:(int)isStderr eventKind:(SSHKitShellEventKind)eventKind {
    char buffer[32768];
    while (YES) {
        int byteCount = ssh_channel_read_nonblocking(self.channel, buffer, sizeof(buffer), isStderr);
        if (byteCount == SSH_ERROR) {
            return NO;
        }
        if (byteCount <= 0) {
            return YES;
        }

        NSData *data = [NSData dataWithBytes:buffer length:(NSUInteger)byteCount];
        SSHKitShellEvent *event = [[SSHKitShellEvent alloc] initWithKind:eventKind data:data exitStatus:0];
        self.eventHandler(event);
    }
}

- (int32_t)exitStatus {
    uint32_t exitCode = 0;
    if (self.channel == NULL) {
        return SSHCoreAbnormalExitStatus;
    }

    int exitState = ssh_channel_get_exit_state(self.channel, &exitCode, NULL, NULL);
    if (exitState != SSH_OK) {
        return SSHCoreAbnormalExitStatus;
    }

    return (int32_t)exitCode;
}

- (void)finishWithExitStatus:(int32_t)exitStatus {
    if (self.finished) {
        return;
    }

    self.finished = YES;
    ssh_channel channel = self.channel;
    self.channel = NULL;
    if (channel != NULL) {
        ssh_channel_send_eof(channel);
        ssh_channel_close(channel);
        ssh_channel_free(channel);
    }

    self.onClosed(exitStatus);
}

- (void)invalidateOnWorkerQueue {
    if (self.finished) {
        return;
    }

    self.finished = YES;
    ssh_channel channel = self.channel;
    self.channel = NULL;
    if (channel != NULL) {
        ssh_channel_send_eof(channel);
        ssh_channel_close(channel);
        ssh_channel_free(channel);
    }
}

- (void)dealloc {
    ssh_channel channel = self.channel;
    if (channel == NULL) {
        return;
    }
    dispatch_async(self.workerQueue, ^{
        ssh_channel_send_eof(channel);
        ssh_channel_close(channel);
        ssh_channel_free(channel);
    });
}

@end

@interface SSHCoreLibSSHSFTPRuntime : NSObject

- (instancetype)initWithSession:(sftp_session)sftp
                    workerQueue:(dispatch_queue_t)workerQueue
                    closeHandler:(SSHCoreSFTPCloseHandler)closeHandler
                          client:(SSHCoreOpenSSHClient *)client;
- (void)listDirectory:(NSString *)path completion:(SSHKitSFTPListCompletion)completion;
- (void)downloadFileAtPath:(NSString *)remotePath toLocalPath:(NSString *)localPath completion:(SSHKitCompletion)completion;
- (void)uploadFileAtPath:(NSString *)localPath toRemotePath:(NSString *)remotePath completion:(SSHKitCompletion)completion;
- (void)closeWithCompletion:(SSHKitCompletion)completion;
- (void)invalidateOnWorkerQueue;

@end

@interface SSHCoreLibSSHSFTPRuntime ()

@property (nonatomic) sftp_session sftp;
@property (nonatomic) dispatch_queue_t workerQueue;
@property (nonatomic, copy) SSHCoreSFTPCloseHandler closeHandler;
@property (nonatomic, weak) SSHCoreOpenSSHClient *client;
@property (nonatomic) BOOL closed;
@property (nonatomic) BOOL runningOperation;
@property (nonatomic) BOOL didCallCloseHandler;

@end

@interface SSHCoreLibSSHTunnelRuntime : NSObject

- (instancetype)initWithChannel:(ssh_channel)channel
                    workerQueue:(dispatch_queue_t)workerQueue
                    closeHandler:(SSHCoreTunnelCloseHandler)closeHandler;
- (void)readDataWithMaximumLength:(NSUInteger)maximumLength completion:(SSHKitTunnelReadCompletion)completion;
- (void)writeData:(NSData *)data completion:(SSHKitCompletion)completion;
- (void)closeWithCompletion:(SSHKitCompletion)completion;
- (void)invalidateOnWorkerQueue;

@end

@interface SSHCoreLibSSHTunnelRuntime ()

@property (nonatomic) ssh_channel channel;
@property (nonatomic) dispatch_queue_t workerQueue;
@property (nonatomic, copy) SSHCoreTunnelCloseHandler closeHandler;
@property (nonatomic) BOOL closed;
@property (nonatomic) BOOL didCallCloseHandler;

@end

@implementation SSHCoreLibSSHTunnelRuntime

- (instancetype)initWithChannel:(ssh_channel)channel
                    workerQueue:(dispatch_queue_t)workerQueue
                    closeHandler:(SSHCoreTunnelCloseHandler)closeHandler {
    NSParameterAssert(channel != NULL);
    NSParameterAssert(workerQueue != nil);

    self = [super init];
    if (self) {
        _channel = channel;
        _workerQueue = workerQueue;
        _closeHandler = [closeHandler copy];
    }
    return self;
}

- (void)readDataWithMaximumLength:(NSUInteger)maximumLength completion:(SSHKitTunnelReadCompletion)completion {
    dispatch_async(self.workerQueue, ^{
        if (self.closed || self.channel == NULL) {
            completion(nil, SSHKitMakeError(SSHKitErrorCodeInvalidState, @"SSH tunnel channel is closed."));
            return;
        }

        uint32_t boundedLength = (uint32_t)MIN(maximumLength, (NSUInteger)32768);
        NSMutableData *data = [NSMutableData dataWithLength:(NSUInteger)boundedLength];
        int byteCount = ssh_channel_read_timeout(self.channel, data.mutableBytes, boundedLength, 0, 10000);
        if (byteCount == SSH_AGAIN) {
            completion(nil, SSHKitMakeError(SSHKitErrorCodeConnectionFailed, @"Timed out waiting for SSH tunnel channel data."));
            return;
        }
        if (byteCount == SSH_ERROR) {
            completion(nil, SSHKitMakeError(SSHKitErrorCodeConnectionFailed, @"Unable to read SSH tunnel channel."));
            return;
        }
        if (byteCount == 0) {
            [self invalidateOnWorkerQueue];
            [self callCloseHandlerIfNeeded];
            completion(nil, SSHKitMakeError(SSHKitErrorCodeConnectionFailed, @"SSH tunnel channel reached EOF."));
            return;
        }

        data.length = (NSUInteger)byteCount;
        completion(data, nil);
    });
}

- (void)writeData:(NSData *)data completion:(SSHKitCompletion)completion {
    dispatch_async(self.workerQueue, ^{
        if (self.closed || self.channel == NULL) {
            completion(SSHKitMakeError(SSHKitErrorCodeInvalidState, @"SSH tunnel channel is closed."));
            return;
        }

        const uint8_t *bytes = data.bytes;
        NSUInteger remaining = data.length;
        while (remaining > 0) {
            uint32_t chunkLength = remaining > UINT32_MAX ? UINT32_MAX : (uint32_t)remaining;
            int written = ssh_channel_write(self.channel, bytes, chunkLength);
            if (written == SSH_ERROR) {
                completion(SSHKitMakeError(SSHKitErrorCodeConnectionFailed, @"Unable to write SSH tunnel channel."));
                return;
            }
            if (written <= 0) {
                completion(SSHKitMakeError(SSHKitErrorCodeConnectionFailed, @"SSH tunnel write made no progress."));
                return;
            }
            bytes += written;
            remaining -= (NSUInteger)written;
        }

        completion(nil);
    });
}

- (void)closeWithCompletion:(SSHKitCompletion)completion {
    dispatch_async(self.workerQueue, ^{
        [self invalidateOnWorkerQueue];
        [self callCloseHandlerIfNeeded];
        completion(nil);
    });
}

- (void)invalidateOnWorkerQueue {
    if (self.closed) {
        return;
    }

    self.closed = YES;
    ssh_channel channel = self.channel;
    self.channel = NULL;
    if (channel != NULL) {
        ssh_channel_send_eof(channel);
        ssh_channel_close(channel);
        ssh_channel_free(channel);
    }
}

- (void)callCloseHandlerIfNeeded {
    if (self.didCallCloseHandler) {
        return;
    }
    self.didCallCloseHandler = YES;
    self.closeHandler();
}

- (void)dealloc {
    ssh_channel channel = self.channel;
    if (channel == NULL) {
        return;
    }
    dispatch_async(self.workerQueue, ^{
        ssh_channel_send_eof(channel);
        ssh_channel_close(channel);
        ssh_channel_free(channel);
    });
}

@end

@interface SSHCoreOpenSSHClient ()

- (NSError *)sftpErrorForOperation:(NSString *)operation sftp:(sftp_session)sftp;

@end

@implementation SSHCoreLibSSHSFTPRuntime

- (instancetype)initWithSession:(sftp_session)sftp
                    workerQueue:(dispatch_queue_t)workerQueue
                    closeHandler:(SSHCoreSFTPCloseHandler)closeHandler
                          client:(SSHCoreOpenSSHClient *)client {
    NSParameterAssert(sftp != NULL);
    NSParameterAssert(workerQueue != nil);

    self = [super init];
    if (self) {
        _sftp = sftp;
        _workerQueue = workerQueue;
        _closeHandler = [closeHandler copy];
        _client = client;
    }
    return self;
}

- (void)listDirectory:(NSString *)path completion:(SSHKitSFTPListCompletion)completion {
    dispatch_async(self.workerQueue, ^{
        NSError *startError = nil;
        if (![self beginOperationWithError:&startError]) {
            completion(nil, startError);
            return;
        }

        NSMutableArray<SSHKitSFTPEntry *> *entries = [[NSMutableArray alloc] init];
        sftp_dir directory = sftp_opendir(self.sftp, path.UTF8String);
        if (directory == NULL) {
            NSError *error = [self.client sftpErrorForOperation:@"SFTP list" sftp:self.sftp];
            [self endOperation];
            completion(nil, error);
            return;
        }

        while (YES) {
            sftp_attributes attributes = sftp_readdir(self.sftp, directory);
            if (attributes == NULL) {
                break;
            }

            if (attributes->name != NULL) {
                NSString *filename = [NSString stringWithUTF8String:attributes->name];
                [entries addObject:[[SSHKitSFTPEntry alloc] initWithFilename:filename]];
            }
            sftp_attributes_free(attributes);
        }

        BOOL reachedEOF = sftp_dir_eof(directory) != 0;
        sftp_closedir(directory);
        [self endOperation];
        if (!reachedEOF) {
            completion(nil, [self.client sftpErrorForOperation:@"SFTP list" sftp:self.sftp]);
            return;
        }

        completion(entries, nil);
    });
}

- (void)downloadFileAtPath:(NSString *)remotePath toLocalPath:(NSString *)localPath completion:(SSHKitCompletion)completion {
    dispatch_async(self.workerQueue, ^{
        NSError *startError = nil;
        if (![self beginOperationWithError:&startError]) {
            completion(startError);
            return;
        }

        NSError *error = [self downloadRemotePath:remotePath toLocalPath:localPath];
        [self endOperation];
        completion(error);
    });
}

- (void)uploadFileAtPath:(NSString *)localPath toRemotePath:(NSString *)remotePath completion:(SSHKitCompletion)completion {
    dispatch_async(self.workerQueue, ^{
        NSError *startError = nil;
        if (![self beginOperationWithError:&startError]) {
            completion(startError);
            return;
        }

        NSError *error = [self uploadLocalPath:localPath toRemotePath:remotePath];
        [self endOperation];
        completion(error);
    });
}

- (void)closeWithCompletion:(SSHKitCompletion)completion {
    dispatch_async(self.workerQueue, ^{
        if (self.closed) {
            completion(nil);
            return;
        }

        self.closed = YES;
        sftp_session sftp = self.sftp;
        self.sftp = NULL;
        if (sftp != NULL) {
            sftp_free(sftp);
        }
        [self callCloseHandlerIfNeeded];
        completion(nil);
    });
}

- (BOOL)beginOperationWithError:(NSError **)error {
    if (self.closed || self.sftp == NULL) {
        if (error) {
            *error = SSHKitMakeError(SSHKitErrorCodeInvalidState, @"SFTP client is closed.");
        }
        return NO;
    }
    if (self.runningOperation) {
        if (error) {
            *error = SSHKitMakeError(SSHKitErrorCodeInvalidState, @"SFTP client is already running an operation.");
        }
        return NO;
    }

    self.runningOperation = YES;
    return YES;
}

- (void)endOperation {
    self.runningOperation = NO;
}

- (NSError *)downloadRemotePath:(NSString *)remotePath toLocalPath:(NSString *)localPath {
    sftp_file remoteFile = sftp_open(self.sftp, remotePath.UTF8String, O_RDONLY, 0);
    if (remoteFile == NULL) {
        return [self.client sftpErrorForOperation:@"SFTP download open" sftp:self.sftp];
    }

    int localFileDescriptor = open(localPath.fileSystemRepresentation, O_CREAT | O_TRUNC | O_WRONLY, 0600);
    if (localFileDescriptor < 0) {
        sftp_close(remoteFile);
        return SSHKitMakeError(SSHKitErrorCodeUnavailable, [NSString stringWithFormat:@"Unable to open local download file: %s", strerror(errno)]);
    }

    char buffer[32768];
    while (YES) {
        ssize_t bytesRead = sftp_read(remoteFile, buffer, sizeof(buffer));
        if (bytesRead < 0) {
            close(localFileDescriptor);
            sftp_close(remoteFile);
            return [self.client sftpErrorForOperation:@"SFTP download read" sftp:self.sftp];
        }
        if (bytesRead == 0) {
            break;
        }

        ssize_t bytesWritten = write(localFileDescriptor, buffer, (size_t)bytesRead);
        if (bytesWritten != bytesRead) {
            close(localFileDescriptor);
            sftp_close(remoteFile);
            return SSHKitMakeError(SSHKitErrorCodeUnavailable, [NSString stringWithFormat:@"Unable to write local download file: %s", strerror(errno)]);
        }
    }

    if (close(localFileDescriptor) != 0) {
        sftp_close(remoteFile);
        return SSHKitMakeError(SSHKitErrorCodeUnavailable, [NSString stringWithFormat:@"Unable to close local download file: %s", strerror(errno)]);
    }
    if (sftp_close(remoteFile) != SSH_OK) {
        return [self.client sftpErrorForOperation:@"SFTP download close" sftp:self.sftp];
    }
    return nil;
}

- (NSError *)uploadLocalPath:(NSString *)localPath toRemotePath:(NSString *)remotePath {
    int localFileDescriptor = open(localPath.fileSystemRepresentation, O_RDONLY);
    if (localFileDescriptor < 0) {
        return SSHKitMakeError(SSHKitErrorCodeUnavailable, [NSString stringWithFormat:@"Unable to open local upload file: %s", strerror(errno)]);
    }

    sftp_file remoteFile = sftp_open(self.sftp, remotePath.UTF8String, O_CREAT | O_TRUNC | O_WRONLY, 0600);
    if (remoteFile == NULL) {
        close(localFileDescriptor);
        return [self.client sftpErrorForOperation:@"SFTP upload open" sftp:self.sftp];
    }

    char buffer[32768];
    while (YES) {
        ssize_t bytesRead = read(localFileDescriptor, buffer, sizeof(buffer));
        if (bytesRead < 0) {
            close(localFileDescriptor);
            sftp_close(remoteFile);
            return SSHKitMakeError(SSHKitErrorCodeUnavailable, [NSString stringWithFormat:@"Unable to read local upload file: %s", strerror(errno)]);
        }
        if (bytesRead == 0) {
            break;
        }

        ssize_t writtenTotal = 0;
        while (writtenTotal < bytesRead) {
            ssize_t bytesWritten = sftp_write(remoteFile, buffer + writtenTotal, (size_t)(bytesRead - writtenTotal));
            if (bytesWritten < 0) {
                close(localFileDescriptor);
                sftp_close(remoteFile);
                return [self.client sftpErrorForOperation:@"SFTP upload write" sftp:self.sftp];
            }
            if (bytesWritten == 0) {
                close(localFileDescriptor);
                sftp_close(remoteFile);
                return SSHKitMakeError(SSHKitErrorCodeConnectionFailed, @"SFTP upload write made no progress.");
            }
            writtenTotal += bytesWritten;
        }
    }

    if (close(localFileDescriptor) != 0) {
        sftp_close(remoteFile);
        return SSHKitMakeError(SSHKitErrorCodeUnavailable, [NSString stringWithFormat:@"Unable to close local upload file: %s", strerror(errno)]);
    }
    if (sftp_close(remoteFile) != SSH_OK) {
        return [self.client sftpErrorForOperation:@"SFTP upload close" sftp:self.sftp];
    }
    return nil;
}

- (void)callCloseHandlerIfNeeded {
    if (self.didCallCloseHandler) {
        return;
    }
    self.didCallCloseHandler = YES;
    self.closeHandler();
}

- (void)invalidateOnWorkerQueue {
    self.closed = YES;
    sftp_session sftp = self.sftp;
    self.sftp = NULL;
    if (sftp != NULL) {
        sftp_free(sftp);
    }
    [self callCloseHandlerIfNeeded];
}

- (void)dealloc {
    sftp_session sftp = self.sftp;
    if (sftp == NULL) {
        return;
    }
    dispatch_async(self.workerQueue, ^{
        sftp_free(sftp);
    });
}

@end

@interface SSHCoreOpenSSHClient ()

@property (nonatomic, copy) SSHKitConfiguration *configuration;
@property (nonatomic) SSHCoreSessionWorker *worker;
@property (nonatomic) NSLock *taskLock;
@property (nonatomic, nullable) id currentTask;
@property (nonatomic) BOOL taskCancelled;
@property (nonatomic) ssh_session session;

@end

@implementation SSHCoreOpenSSHClient

- (instancetype)initWithConfiguration:(SSHKitConfiguration *)configuration worker:(SSHCoreSessionWorker *)worker {
    NSParameterAssert(worker != nil);

    self = [super init];
    if (self) {
        _configuration = [configuration copy];
        _worker = worker;
        _taskLock = [[NSLock alloc] init];
    }
    return self;
}

- (BOOL)verifyConnectionWithError:(NSError **)error {
    return [self connectLibSSHSessionWithError:error];
}

- (NSDictionary<NSString *, NSString *> *)baseLogMetadata {
    return @{
        @"host": self.configuration.host,
        @"port": [NSString stringWithFormat:@"%hu", self.configuration.port],
        @"username": self.configuration.username,
        @"authentication": SSHCoreAuthenticationName(self.configuration.authenticationKind),
        @"hostKeyPolicy": SSHCoreHostKeyPolicyName(self.configuration.hostKeyPolicyKind),
    };
}

- (void)emitLogLevel:(SSHKitLogLevel)level
               phase:(NSString *)phase
             message:(NSString *)message
            metadata:(NSDictionary<NSString *, NSString *> *)metadata {
    SSHKitLogHandler handler = self.configuration.logHandler;
    if (handler == nil) {
        return;
    }

    NSMutableDictionary<NSString *, NSString *> *mergedMetadata = [[self baseLogMetadata] mutableCopy];
    [metadata enumerateKeysAndObjectsUsingBlock:^(NSString *key, NSString *value, BOOL *stop) {
        (void)stop;
        mergedMetadata[key] = value;
    }];
    SSHKitLogEvent *event = [[SSHKitLogEvent alloc] initWithLevel:level
                                                            phase:phase
                                                          message:message
                                                         metadata:mergedMetadata];
    handler(event);
}

- (nullable SSHKitAuthenticationDiscoveryResult *)discoverAuthenticationMethodsWithError:(NSError **)error {
    [self emitLogLevel:SSHKitLogLevelInfo phase:@"authDiscovery" message:@"SSH authentication discovery started." metadata:@{}];
    if (![self connectLibSSHSessionWithoutAuthenticationWithError:error]) {
        return nil;
    }

    [self.taskLock lock];
    ssh_session session = self.session;
    [self.taskLock unlock];

    int noneStatus = ssh_userauth_none(session, NULL);
    int methodMask = noneStatus == SSH_AUTH_SUCCESS ? SSH_AUTH_METHOD_NONE : ssh_userauth_list(session, NULL);
    if (methodMask == SSH_AUTH_METHOD_UNKNOWN && noneStatus != SSH_AUTH_SUCCESS) {
        if (error) {
            *error = [self libSSHErrorWithSession:session code:SSHKitErrorCodeAuthenticationFailed fallback:@"Unable to discover SSH authentication methods."];
        }
        [self emitLogLevel:SSHKitLogLevelError phase:@"authDiscovery" message:@"SSH authentication discovery failed." metadata:@{}];
        return nil;
    }

    char *issueBanner = ssh_get_issue_banner(session);
    NSString *issueBannerString = issueBanner != NULL ? [NSString stringWithUTF8String:issueBanner] : nil;
    free(issueBanner);

    const char *serverBanner = ssh_get_serverbanner(session);
    NSArray<NSNumber *> *methods = SSHCoreAuthenticationMethodsFromMask(methodMask);
    [self emitLogLevel:SSHKitLogLevelInfo
                 phase:@"authDiscovery"
               message:@"SSH authentication discovery succeeded."
              metadata:@{@"methodCount": [NSString stringWithFormat:@"%lu", (unsigned long)methods.count]}];
    return [[SSHKitAuthenticationDiscoveryResult alloc] initWithMethods:methods
                                                            issueBanner:issueBannerString
                                                           serverBanner:SSHCoreNullableStringFromCString(serverBanner)];
}

- (nullable SSHKitCommandResult *)executeCommand:(NSString *)command error:(NSError **)error {
    return [self executeLibSSHCommand:command requestPTY:NO error:error];
}

- (nullable SSHKitCommandResult *)executePTYCommand:(NSString *)command error:(NSError **)error {
    return [self executeLibSSHCommand:command requestPTY:YES error:error];
}

- (nullable SSHKitCommand *)openCommand:(NSString *)command
                           eventHandler:(SSHKitCommandEventHandler)eventHandler
                               onClosed:(SSHCoreCommandClosedBlock)onClosed
                                  error:(NSError **)error {
    [self emitLogLevel:SSHKitLogLevelInfo phase:@"command" message:@"SSH streaming command open started." metadata:@{}];
    ssh_channel channel = [self openSessionChannelWithError:error];
    if (channel == NULL) {
        return nil;
    }

    if (ssh_channel_request_exec(channel, command.UTF8String) != SSH_OK) {
        if (error) {
            *error = [self libSSHErrorWithCode:SSHKitErrorCodeCommandFailed fallback:@"Unable to execute SSH command."];
        }
        ssh_channel_close(channel);
        ssh_channel_free(channel);
        return nil;
    }

    __weak SSHCoreOpenSSHClient *weakSelf = self;
    SSHCoreLibSSHCommandRuntime *runtime = [[SSHCoreLibSSHCommandRuntime alloc] initWithChannel:channel
                                                                                   workerQueue:self.worker.queue
                                                                                   eventHandler:eventHandler
                                                                                       onClosed:^(int32_t exitStatus) {
        [weakSelf clearCurrentTask];
        onClosed(exitStatus);
    }];
    [self.taskLock lock];
    self.currentTask = runtime;
    BOOL wasCancelled = self.taskCancelled;
    [self.taskLock unlock];
    if (wasCancelled) {
        [runtime closeWithCompletion:^(NSError *closeError) {
            (void)closeError;
        }];
        if (error) {
            *error = SSHKitMakeError(SSHKitErrorCodeCancelled, @"SSH command was cancelled before start.");
        }
        return nil;
    }

    [self emitLogLevel:SSHKitLogLevelInfo phase:@"command" message:@"SSH streaming command opened." metadata:@{}];
    return [[SSHKitCommand alloc] initWithWriteBlock:^(NSData *data, SSHKitCompletion completion) {
        [runtime writeData:data completion:completion];
    } eofBlock:^(SSHKitCompletion completion) {
        [runtime sendEOFWithCompletion:completion];
    } closeBlock:^(SSHKitCompletion completion) {
        [runtime closeWithCompletion:completion];
    } startBlock:^{
        [runtime start];
    }];
}

- (nullable SSHKitShell *)openShellWithTerminalType:(NSString *)terminalType
                                            columns:(uint16_t)columns
                                               rows:(uint16_t)rows
                                       eventHandler:(SSHKitShellEventHandler)eventHandler
                                           onClosed:(SSHCoreShellClosedBlock)onClosed
                                              error:(NSError **)error {
    [self emitLogLevel:SSHKitLogLevelInfo
                 phase:@"shell"
               message:@"SSH shell open started."
              metadata:@{@"terminalType": terminalType,
                         @"columns": [NSString stringWithFormat:@"%hu", columns],
                         @"rows": [NSString stringWithFormat:@"%hu", rows]}];
    ssh_channel channel = [self openSessionChannelWithError:error];
    if (channel == NULL) {
        return nil;
    }

    if (ssh_channel_request_pty_size(channel, terminalType.UTF8String, columns, rows) != SSH_OK) {
        if (error) {
            *error = [self libSSHErrorWithCode:SSHKitErrorCodeConnectionFailed fallback:@"Unable to request SSH shell PTY."];
        }
        ssh_channel_close(channel);
        ssh_channel_free(channel);
        return nil;
    }

    if (ssh_channel_request_shell(channel) != SSH_OK) {
        if (error) {
            *error = [self libSSHErrorWithCode:SSHKitErrorCodeConnectionFailed fallback:@"Unable to request SSH shell."];
        }
        ssh_channel_close(channel);
        ssh_channel_free(channel);
        return nil;
    }

    __weak SSHCoreOpenSSHClient *weakSelf = self;
    SSHCoreLibSSHShellRuntime *runtime = [[SSHCoreLibSSHShellRuntime alloc] initWithChannel:channel
                                                                                workerQueue:self.worker.queue
                                                                                eventHandler:eventHandler
                                                                                    onClosed:^(int32_t exitStatus) {
        [weakSelf clearCurrentTask];
        onClosed(exitStatus);
    }];
    [self.taskLock lock];
    self.currentTask = runtime;
    BOOL wasCancelled = self.taskCancelled;
    [self.taskLock unlock];
    if (wasCancelled) {
        [runtime closeWithCompletion:^(NSError *closeError) {
            (void)closeError;
        }];
        if (error) {
            *error = SSHKitMakeError(SSHKitErrorCodeCancelled, @"SSH shell was cancelled before start.");
        }
        return nil;
    }

    [self emitLogLevel:SSHKitLogLevelInfo phase:@"shell" message:@"SSH shell opened." metadata:@{}];
    return [[SSHKitShell alloc] initWithWriteBlock:^(NSData *data, SSHKitCompletion completion) {
        [runtime writeData:data completion:completion];
    } resizeBlock:^(uint16_t resizeColumns, uint16_t resizeRows, SSHKitCompletion completion) {
        [runtime resizeWithColumns:resizeColumns rows:resizeRows completion:completion];
    } closeBlock:^(SSHKitCompletion completion) {
        [runtime closeWithCompletion:completion];
    } startBlock:^{
        [runtime start];
    }];
}

- (nullable SSHKitSFTPClient *)openSFTPWithCloseHandler:(SSHCoreSFTPCloseHandler)closeHandler error:(NSError **)error {
    [self emitLogLevel:SSHKitLogLevelInfo phase:@"sftp" message:@"SSH SFTP open started." metadata:@{}];
    if (self.session == NULL) {
        if (error) {
            *error = SSHKitMakeError(SSHKitErrorCodeInvalidState, @"SSH session is not connected.");
        }
        return nil;
    }

    sftp_session sftp = sftp_new(self.session);
    if (sftp == NULL) {
        if (error) {
            *error = [self libSSHErrorWithCode:SSHKitErrorCodeConnectionFailed fallback:@"Unable to allocate SFTP session."];
        }
        return nil;
    }

    if (sftp_init(sftp) != SSH_OK) {
        if (error) {
            *error = [self sftpErrorForOperation:@"SFTP init" sftp:sftp];
        }
        sftp_free(sftp);
        return nil;
    }

    __weak SSHCoreOpenSSHClient *weakSelf = self;
    SSHCoreLibSSHSFTPRuntime *runtime = [[SSHCoreLibSSHSFTPRuntime alloc] initWithSession:sftp
                                                                              workerQueue:self.worker.queue
                                                                             closeHandler:^{
        [weakSelf clearCurrentTask];
        closeHandler();
    }
                                                                                   client:self];
    [self.taskLock lock];
    self.currentTask = runtime;
    [self.taskLock unlock];
    [self emitLogLevel:SSHKitLogLevelInfo phase:@"sftp" message:@"SSH SFTP opened." metadata:@{}];
    return [[SSHKitSFTPClient alloc] initWithListBlock:^(NSString *path, SSHKitSFTPListCompletion completion) {
        [runtime listDirectory:path completion:completion];
    } downloadBlock:^(NSString *remotePath, NSString *localPath, SSHKitCompletion completion) {
        [runtime downloadFileAtPath:remotePath toLocalPath:localPath completion:completion];
    } uploadBlock:^(NSString *localPath, NSString *remotePath, SSHKitCompletion completion) {
        [runtime uploadFileAtPath:localPath toRemotePath:remotePath completion:completion];
    } closeBlock:^(SSHKitCompletion completion) {
        [runtime closeWithCompletion:completion];
    }];
}

- (nullable SSHKitTunnelChannel *)openDirectTCPChannelToHost:(NSString *)host
                                                        port:(uint16_t)port
                                                closeHandler:(SSHCoreTunnelCloseHandler)closeHandler
                                                       error:(NSError **)error {
    [self emitLogLevel:SSHKitLogLevelInfo
                 phase:@"tunnel"
               message:@"SSH direct TCP channel open started."
              metadata:@{@"targetHost": host,
                         @"targetPort": [NSString stringWithFormat:@"%hu", port]}];
    if (self.session == NULL) {
        if (error) {
            *error = SSHKitMakeError(SSHKitErrorCodeInvalidState, @"SSH session is not connected.");
        }
        return nil;
    }

    ssh_channel channel = ssh_channel_new(self.session);
    if (channel == NULL) {
        if (error) {
            *error = [self libSSHErrorWithCode:SSHKitErrorCodeConnectionFailed fallback:@"Unable to allocate SSH tunnel channel."];
        }
        return nil;
    }

    if (ssh_channel_open_forward(channel, host.UTF8String, port, self.configuration.host.UTF8String, 0) != SSH_OK) {
        if (error) {
            *error = [self libSSHErrorWithCode:SSHKitErrorCodeConnectionFailed fallback:@"Unable to open SSH direct TCP channel."];
        }
        ssh_channel_free(channel);
        return nil;
    }

    __weak SSHCoreOpenSSHClient *weakSelf = self;
    SSHCoreLibSSHTunnelRuntime *runtime = [[SSHCoreLibSSHTunnelRuntime alloc] initWithChannel:channel
                                                                                  workerQueue:self.worker.queue
                                                                                 closeHandler:^{
        [weakSelf clearCurrentTask];
        closeHandler();
    }];
    [self.taskLock lock];
    self.currentTask = runtime;
    [self.taskLock unlock];

    [self emitLogLevel:SSHKitLogLevelInfo
                 phase:@"tunnel"
               message:@"SSH direct TCP channel opened."
              metadata:@{@"targetHost": host,
                         @"targetPort": [NSString stringWithFormat:@"%hu", port]}];
    return [[SSHKitTunnelChannel alloc] initWithReadBlock:^(NSUInteger maximumLength, SSHKitTunnelReadCompletion completion) {
        [runtime readDataWithMaximumLength:maximumLength completion:completion];
    } writeBlock:^(NSData *data, SSHKitCompletion completion) {
        [runtime writeData:data completion:completion];
    } closeBlock:^(SSHKitCompletion completion) {
        [runtime closeWithCompletion:completion];
    }];
}

- (void)cancelCurrentTask {
    SSHCoreSessionState workerState = self.worker.state;
    [self.taskLock lock];
    id taskObject = self.currentTask;
    ssh_session session = self.session;
    BOOL shouldShutdownSocket = taskObject != nil || [self.worker isActiveJobState:workerState];
    if (taskObject || session != NULL) {
        self.taskCancelled = YES;
    }
    [self.taskLock unlock];

    if ([taskObject respondsToSelector:@selector(closeWithCompletion:)]) {
        void (*closeMessage)(id, SEL, SSHKitCompletion) = (void *)objc_msgSend;
        closeMessage(taskObject, @selector(closeWithCompletion:), ^(NSError *error) {
            (void)error;
        });
    }
    if (shouldShutdownSocket) {
        [self.worker.socketHandle shutdownNow];
    }
}

- (void)cancelCurrentTaskAndWaitUntilExit {
    [self cancelCurrentTask];
}

- (void)closeSession {
    [self emitLogLevel:SSHKitLogLevelInfo phase:@"close" message:@"SSH session close started." metadata:@{}];
    [self.taskLock lock];
    ssh_session session = self.session;
    self.session = NULL;
    self.currentTask = nil;
    self.taskCancelled = NO;
    [self.taskLock unlock];

    if (session != NULL) {
        ssh_disconnect(session);
        ssh_free(session);
    }
    [self closeWorkerSocketHandle];
    [self emitLogLevel:SSHKitLogLevelInfo phase:@"close" message:@"SSH session close finished." metadata:@{}];
}

- (BOOL)connectLibSSHSessionWithError:(NSError **)error {
    if (![self connectLibSSHSessionWithoutAuthenticationWithError:error]) {
        return NO;
    }

    [self.taskLock lock];
    ssh_session session = self.session;
    [self.taskLock unlock];
    [self emitLogLevel:SSHKitLogLevelInfo phase:@"auth" message:@"SSH authentication started." metadata:@{}];
    if (![self authenticateLibSSHSession:session error:error]) {
        [self emitLogLevel:SSHKitLogLevelError phase:@"auth" message:@"SSH authentication failed." metadata:@{}];
        [self clearLibSSHSession:session];
        return NO;
    }

    [self emitLogLevel:SSHKitLogLevelInfo phase:@"auth" message:@"SSH authentication succeeded." metadata:@{}];
    return YES;
}

- (BOOL)connectLibSSHSessionWithoutAuthenticationWithError:(NSError **)error {
    [self emitLogLevel:SSHKitLogLevelInfo phase:@"connect" message:@"SSH connect started." metadata:@{}];
    if ([self isTaskCancelled]) {
        if (error) {
            *error = SSHKitMakeError(SSHKitErrorCodeCancelled, @"SSH connection was cancelled before connect.");
        }
        [self emitLogLevel:SSHKitLogLevelWarning phase:@"connect" message:@"SSH connect cancelled before socket open." metadata:@{}];
        return NO;
    }

    ssh_session session = ssh_new();
    if (session == NULL) {
        if (error) {
            *error = SSHKitMakeError(SSHKitErrorCodeUnavailable, @"Unable to allocate libssh session.");
        }
        return NO;
    }

    if (![self configureLibSSHSession:session error:error]) {
        ssh_free(session);
        return NO;
    }

    int fileDescriptor = [self openSocketWithError:error];
    if (fileDescriptor < 0) {
        ssh_free(session);
        return NO;
    }

    socket_t sshFileDescriptor = fileDescriptor;
    if (ssh_options_set(session, SSH_OPTIONS_FD, &sshFileDescriptor) != SSH_OK) {
        if (error) {
            *error = [self libSSHErrorWithSession:session code:SSHKitErrorCodeConnectionFailed fallback:@"Unable to attach socket to libssh session."];
        }
        ssh_free(session);
        [self closeWorkerSocketHandle];
        return NO;
    }

    [self.taskLock lock];
    self.session = session;
    BOOL wasCancelledBeforeConnect = self.taskCancelled;
    [self.taskLock unlock];
    if (wasCancelledBeforeConnect) {
        [self clearLibSSHSession:session];
        if (error) {
            *error = SSHKitMakeError(SSHKitErrorCodeCancelled, @"SSH connection was cancelled before connect.");
        }
        return NO;
    }

    if (ssh_connect(session) != SSH_OK) {
        if (error) {
            if ([self isTaskCancelled]) {
                *error = SSHKitMakeError(SSHKitErrorCodeCancelled, @"SSH connection was cancelled.");
            } else {
                *error = [self libSSHErrorWithSession:session code:SSHKitErrorCodeConnectionFailed fallback:@"SSH connect failed."];
            }
        }
        [self emitLogLevel:SSHKitLogLevelError phase:@"connect" message:@"SSH transport connect failed." metadata:@{}];
        [self clearLibSSHSession:session];
        return NO;
    }

    if (![self verifyLibSSHHostKeyForSession:session error:error]) {
        [self clearLibSSHSession:session];
        return NO;
    }

    [self emitLogLevel:SSHKitLogLevelInfo phase:@"connect" message:@"SSH transport connect succeeded." metadata:@{}];
    return YES;
}

- (BOOL)configureLibSSHSession:(ssh_session)session error:(NSError **)error {
    int port = self.configuration.port;
    long timeout = (long)ceil(self.configuration.timeout);
    const char *host = self.configuration.host.UTF8String;
    const char *username = self.configuration.username.UTF8String;

    if (ssh_options_set(session, SSH_OPTIONS_HOST, host) != SSH_OK ||
        ssh_options_set(session, SSH_OPTIONS_PORT, &port) != SSH_OK ||
        ssh_options_set(session, SSH_OPTIONS_USER, username) != SSH_OK ||
        ssh_options_set(session, SSH_OPTIONS_TIMEOUT, &timeout) != SSH_OK) {
        if (error) {
            *error = [self libSSHErrorWithSession:session code:SSHKitErrorCodeConnectionFailed fallback:@"Unable to configure libssh session."];
        }
        return NO;
    }

    if (self.configuration.hostKeyPolicyKind == SSHKitHostKeyPolicyKindKnownHostsFile) {
        if (self.configuration.knownHostsPath.length == 0) {
            if (error) {
                *error = SSHKitMakeError(SSHKitErrorCodeHostKeyVerificationFailed, @"Known hosts policy requires a known hosts file path.");
            }
            return NO;
        }

        const char *knownHostsPath = self.configuration.knownHostsPath.UTF8String;
        if (ssh_options_set(session, SSH_OPTIONS_KNOWNHOSTS, knownHostsPath) != SSH_OK) {
            if (error) {
                *error = [self libSSHErrorWithSession:session code:SSHKitErrorCodeHostKeyVerificationFailed fallback:@"Unable to configure known hosts file."];
            }
            return NO;
        }
    }

    return YES;
}

- (int)openSocketWithError:(NSError **)error {
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    NSString *port = [NSString stringWithFormat:@"%hu", self.configuration.port];
    struct addrinfo *addresses = NULL;
    int result = getaddrinfo(self.configuration.host.UTF8String, port.UTF8String, &hints, &addresses);
    if (result != 0) {
        if (error) {
            *error = SSHKitMakeError(SSHKitErrorCodeConnectionFailed, [NSString stringWithFormat:@"Unable to resolve SSH host: %s", gai_strerror(result)]);
        }
        return -1;
    }

    NSError *lastError = nil;
    for (struct addrinfo *address = addresses; address != NULL; address = address->ai_next) {
        int fileDescriptor = socket(address->ai_family, address->ai_socktype, address->ai_protocol);
        if (fileDescriptor < 0) {
            lastError = SSHKitMakeError(SSHKitErrorCodeConnectionFailed, [NSString stringWithFormat:@"Unable to create SSH socket: %s", strerror(errno)]);
            continue;
        }

        self.worker.socketHandle = [[SSHCoreSocketHandle alloc] initWithFileDescriptor:fileDescriptor];
        if ([self connectSocket:fileDescriptor address:address error:&lastError]) {
            freeaddrinfo(addresses);
            return fileDescriptor;
        }

        [self closeWorkerSocketHandle];
    }

    freeaddrinfo(addresses);
    if (error) {
        *error = lastError ?: SSHKitMakeError(SSHKitErrorCodeConnectionFailed, @"Unable to connect SSH socket.");
    }
    return -1;
}

- (BOOL)connectSocket:(int)fileDescriptor address:(struct addrinfo *)address error:(NSError **)error {
    int originalFlags = fcntl(fileDescriptor, F_GETFL, 0);
    if (originalFlags < 0 || fcntl(fileDescriptor, F_SETFL, originalFlags | O_NONBLOCK) != 0) {
        if (error) {
            *error = SSHKitMakeError(SSHKitErrorCodeConnectionFailed, [NSString stringWithFormat:@"Unable to configure SSH socket: %s", strerror(errno)]);
        }
        return NO;
    }

    int connectResult = connect(fileDescriptor, address->ai_addr, address->ai_addrlen);
    if (connectResult == 0) {
        fcntl(fileDescriptor, F_SETFL, originalFlags);
        return YES;
    }

    if (errno != EINPROGRESS) {
        if (error) {
            *error = SSHKitMakeError(SSHKitErrorCodeConnectionFailed, [NSString stringWithFormat:@"SSH socket connect failed: %s", strerror(errno)]);
        }
        return NO;
    }

    fd_set writeSet;
    FD_ZERO(&writeSet);
    FD_SET(fileDescriptor, &writeSet);

    NSTimeInterval timeoutInterval = self.configuration.timeout;
    struct timeval timeout;
    timeout.tv_sec = (long)timeoutInterval;
    timeout.tv_usec = (int)((timeoutInterval - floor(timeoutInterval)) * 1000000);

    int selectResult = select(fileDescriptor + 1, NULL, &writeSet, NULL, &timeout);
    if (selectResult <= 0) {
        if (error) {
            *error = [self isTaskCancelled]
                ? SSHKitMakeError(SSHKitErrorCodeCancelled, @"SSH socket connect was cancelled.")
                : SSHKitMakeError(SSHKitErrorCodeConnectionFailed, @"SSH socket connect timed out.");
        }
        return NO;
    }

    int socketError = 0;
    socklen_t socketErrorLength = sizeof(socketError);
    if (getsockopt(fileDescriptor, SOL_SOCKET, SO_ERROR, &socketError, &socketErrorLength) != 0 || socketError != 0) {
        if (error) {
            int reportedError = socketError != 0 ? socketError : errno;
            *error = SSHKitMakeError(SSHKitErrorCodeConnectionFailed, [NSString stringWithFormat:@"SSH socket connect failed: %s", strerror(reportedError)]);
        }
        return NO;
    }

    fcntl(fileDescriptor, F_SETFL, originalFlags);
    return YES;
}

- (BOOL)verifyLibSSHHostKeyForSession:(ssh_session)session error:(NSError **)error {
    [self emitLogLevel:SSHKitLogLevelInfo phase:@"trust" message:@"SSH host key verification started." metadata:@{}];
    if (self.configuration.hostKeyPolicyKind == SSHKitHostKeyPolicyKindInsecureAcceptAnyHostKey) {
        [self emitLogLevel:SSHKitLogLevelWarning
                     phase:@"trust"
                   message:@"SSH host key accepted by insecure policy."
                  metadata:@{@"policy": @"insecureAcceptAnyHostKey"}];
        return YES;
    }

    enum ssh_known_hosts_e state = ssh_session_is_known_server(session);
    if (state == SSH_KNOWN_HOSTS_OK) {
        [self emitLogLevel:SSHKitLogLevelInfo
                     phase:@"trust"
                   message:@"SSH host key verification succeeded."
                  metadata:@{@"knownHostsState": [NSString stringWithFormat:@"%d", state]}];
        return YES;
    }

    if (error) {
        NSString *message = [NSString stringWithFormat:@"Host key verification failed with libssh known-hosts state %d.", state];
        *error = SSHKitMakeError(SSHKitErrorCodeHostKeyVerificationFailed, message);
    }
    [self emitLogLevel:SSHKitLogLevelError
                 phase:@"trust"
               message:@"SSH host key verification failed."
              metadata:@{@"knownHostsState": [NSString stringWithFormat:@"%d", state]}];
    return NO;
}

- (BOOL)authenticateLibSSHSession:(ssh_session)session error:(NSError **)error {
    [self emitLogLevel:SSHKitLogLevelDebug
                 phase:@"auth"
               message:@"SSH authentication method selected."
              metadata:@{@"method": SSHCoreAuthenticationName(self.configuration.authenticationKind)}];
    int rc = SSH_AUTH_DENIED;
    switch (self.configuration.authenticationKind) {
        case SSHKitAuthenticationKindPassword:
            if (self.configuration.password.length == 0) {
                if (error) {
                    *error = SSHKitMakeError(SSHKitErrorCodeAuthenticationFailed, @"Password authentication requires a password.");
                }
                return NO;
            }
            rc = ssh_userauth_password(session, NULL, self.configuration.password.UTF8String);
            break;
        case SSHKitAuthenticationKindPrivateKeyFile: {
            if (self.configuration.privateKeyPath.length == 0) {
                if (error) {
                    *error = SSHKitMakeError(SSHKitErrorCodeAuthenticationFailed, @"Private key authentication requires a key file path.");
                }
                return NO;
            }
            ssh_key privateKey = NULL;
            const char *passphrase = self.configuration.privateKeyPassphrase.length > 0 ? self.configuration.privateKeyPassphrase.UTF8String : NULL;
            if (ssh_pki_import_privkey_file(self.configuration.privateKeyPath.UTF8String, passphrase, NULL, NULL, &privateKey) != SSH_OK) {
                if (error) {
                    *error = [self libSSHErrorWithSession:session code:SSHKitErrorCodeAuthenticationFailed fallback:@"Unable to import private key."];
                }
                return NO;
            }
            rc = ssh_userauth_publickey(session, NULL, privateKey);
            ssh_key_free(privateKey);
            break;
        }
        case SSHKitAuthenticationKindKeyboardInteractive:
            return [self authenticateKeyboardInteractiveSession:session error:error];
    }

    if (rc == SSH_AUTH_SUCCESS) {
        return YES;
    }

    if (error) {
        *error = [self libSSHErrorWithSession:session code:SSHKitErrorCodeAuthenticationFailed fallback:@"SSH authentication failed."];
    }
    return NO;
}

- (BOOL)authenticateKeyboardInteractiveSession:(ssh_session)session error:(NSError **)error {
    SSHKitKeyboardInteractiveResponder responder = self.configuration.keyboardInteractiveResponder;
    if (responder == nil) {
        if (error) {
            *error = SSHKitMakeError(SSHKitErrorCodeAuthenticationFailed, @"Keyboard-interactive authentication requires a response provider.");
        }
        return NO;
    }

    int rc = ssh_userauth_kbdint(session, NULL, NULL);
    while (rc == SSH_AUTH_INFO) {
        NSString *name = SSHCoreStringFromCString(ssh_userauth_kbdint_getname(session));
        NSString *instruction = SSHCoreStringFromCString(ssh_userauth_kbdint_getinstruction(session));
        int promptCount = ssh_userauth_kbdint_getnprompts(session);
        if (promptCount < 0) {
            if (error) {
                *error = [self libSSHErrorWithSession:session code:SSHKitErrorCodeAuthenticationFailed fallback:@"Unable to read keyboard-interactive prompts."];
            }
            return NO;
        }

        NSMutableArray<SSHKitKeyboardInteractivePrompt *> *prompts = [[NSMutableArray alloc] initWithCapacity:(NSUInteger)promptCount];
        for (int index = 0; index < promptCount; index++) {
            char echo = 0;
            const char *prompt = ssh_userauth_kbdint_getprompt(session, (unsigned int)index, &echo);
            [prompts addObject:[[SSHKitKeyboardInteractivePrompt alloc] initWithPrompt:SSHCoreStringFromCString(prompt) echo:echo != 0]];
        }

        NSArray<NSString *> *answers = responder(name, instruction, prompts);
        if (answers.count != prompts.count) {
            if (error) {
                *error = SSHKitMakeError(SSHKitErrorCodeAuthenticationFailed, @"Keyboard-interactive response count does not match prompt count.");
            }
            return NO;
        }

        for (NSUInteger index = 0; index < answers.count; index++) {
            if (ssh_userauth_kbdint_setanswer(session, (unsigned int)index, answers[index].UTF8String) != SSH_OK) {
                if (error) {
                    *error = [self libSSHErrorWithSession:session code:SSHKitErrorCodeAuthenticationFailed fallback:@"Unable to send keyboard-interactive answer."];
                }
                return NO;
            }
        }

        rc = ssh_userauth_kbdint(session, NULL, NULL);
    }

    if (rc == SSH_AUTH_SUCCESS) {
        return YES;
    }

    if (error) {
        NSString *fallback = rc == SSH_AUTH_PARTIAL ? @"Keyboard-interactive authentication requires additional methods." : @"Keyboard-interactive authentication failed.";
        *error = [self libSSHErrorWithSession:session code:SSHKitErrorCodeAuthenticationFailed fallback:fallback];
    }
    return NO;
}

- (nullable SSHKitCommandResult *)executeLibSSHCommand:(NSString *)command requestPTY:(BOOL)requestPTY error:(NSError **)error {
    [self emitLogLevel:SSHKitLogLevelInfo
                 phase:requestPTY ? @"shell" : @"command"
               message:requestPTY ? @"SSH PTY command started." : @"SSH command started."
              metadata:@{}];
    ssh_channel channel = [self openSessionChannelWithError:error];
    if (channel == NULL) {
        return nil;
    }

    if (requestPTY && ssh_channel_request_pty(channel) != SSH_OK) {
        if (error) {
            *error = [self libSSHErrorWithCode:SSHKitErrorCodeConnectionFailed fallback:@"Unable to request PTY."];
        }
        ssh_channel_close(channel);
        ssh_channel_free(channel);
        return nil;
    }

    if (ssh_channel_request_exec(channel, command.UTF8String) != SSH_OK) {
        if (error) {
            *error = [self libSSHErrorWithCode:SSHKitErrorCodeCommandFailed fallback:@"Unable to execute SSH command."];
        }
        ssh_channel_close(channel);
        ssh_channel_free(channel);
        return nil;
    }

    NSMutableData *standardOutput = [[NSMutableData alloc] init];
    NSMutableData *standardError = [[NSMutableData alloc] init];
    if (![self readLibSSHChannel:channel standardOutput:standardOutput standardError:standardError error:error]) {
        ssh_channel_close(channel);
        ssh_channel_free(channel);
        return nil;
    }

    uint32_t exitStatus = 0;
    int exitState = ssh_channel_get_exit_state(channel, &exitStatus, NULL, NULL);
    if (exitState != SSH_OK) {
        if (error) {
            *error = SSHKitMakeError(SSHKitErrorCodeCommandFailed, @"SSH command finished without an exit status.");
        }
        ssh_channel_send_eof(channel);
        ssh_channel_close(channel);
        ssh_channel_free(channel);
        return nil;
    }

    ssh_channel_send_eof(channel);
    ssh_channel_close(channel);
    ssh_channel_free(channel);
    [self emitLogLevel:SSHKitLogLevelInfo
                 phase:requestPTY ? @"shell" : @"command"
               message:requestPTY ? @"SSH PTY command finished." : @"SSH command finished."
              metadata:@{@"exitStatus": [NSString stringWithFormat:@"%d", (int32_t)exitStatus]}];
    return [[SSHKitCommandResult alloc] initWithStandardOutput:standardOutput
                                                standardError:standardError
                                                   exitStatus:(int32_t)exitStatus];
}

- (nullable ssh_channel)openSessionChannelWithError:(NSError **)error {
    if (self.session == NULL) {
        if (error) {
            *error = SSHKitMakeError(SSHKitErrorCodeInvalidState, @"SSH session is not connected.");
        }
        return NULL;
    }

    ssh_channel channel = ssh_channel_new(self.session);
    if (channel == NULL) {
        if (error) {
            *error = [self libSSHErrorWithCode:SSHKitErrorCodeConnectionFailed fallback:@"Unable to allocate SSH channel."];
        }
        return NULL;
    }

    if (ssh_channel_open_session(channel) != SSH_OK) {
        if (error) {
            *error = [self libSSHErrorWithCode:SSHKitErrorCodeConnectionFailed fallback:@"Unable to open SSH channel."];
        }
        ssh_channel_free(channel);
        return NULL;
    }

    return channel;
}

- (BOOL)readLibSSHChannel:(ssh_channel)channel
           standardOutput:(NSMutableData *)standardOutput
            standardError:(NSMutableData *)standardError
                    error:(NSError **)error {
    char buffer[32768];
    while (ssh_channel_is_eof(channel) == 0) {
        int stdoutCount = ssh_channel_read_timeout(channel, buffer, sizeof(buffer), 0, 100);
        if (stdoutCount == SSH_ERROR) {
            if (error) {
                *error = [self isTaskCancelled] ? SSHKitMakeError(SSHKitErrorCodeCancelled, @"SSH command was cancelled.") : SSHKitMakeError(SSHKitErrorCodeCommandFailed, @"Failed reading SSH command stdout.");
            }
            return NO;
        }
        if (stdoutCount > 0) {
            [standardOutput appendBytes:buffer length:(NSUInteger)stdoutCount];
        }

        int stderrCount = ssh_channel_read_timeout(channel, buffer, sizeof(buffer), 1, 0);
        if (stderrCount == SSH_ERROR) {
            if (error) {
                *error = [self isTaskCancelled] ? SSHKitMakeError(SSHKitErrorCodeCancelled, @"SSH command was cancelled.") : SSHKitMakeError(SSHKitErrorCodeCommandFailed, @"Failed reading SSH command stderr.");
            }
            return NO;
        }
        if (stderrCount > 0) {
            [standardError appendBytes:buffer length:(NSUInteger)stderrCount];
        }
    }

    for (;;) {
        int stderrCount = ssh_channel_read_timeout(channel, buffer, sizeof(buffer), 1, 0);
        if (stderrCount == SSH_ERROR) {
            if (error) {
                *error = [self isTaskCancelled] ? SSHKitMakeError(SSHKitErrorCodeCancelled, @"SSH command was cancelled.") : SSHKitMakeError(SSHKitErrorCodeCommandFailed, @"Failed draining SSH command stderr.");
            }
            return NO;
        }
        if (stderrCount == 0) {
            return YES;
        }
        [standardError appendBytes:buffer length:(NSUInteger)stderrCount];
    }
}

- (NSError *)libSSHErrorWithCode:(SSHKitErrorCode)code fallback:(NSString *)fallback {
    [self.taskLock lock];
    const char *message = self.session != NULL ? ssh_get_error(self.session) : NULL;
    NSString *errorMessage = message != NULL && strlen(message) > 0 ? [NSString stringWithUTF8String:message] : nil;
    [self.taskLock unlock];

    if (errorMessage.length > 0) {
        return SSHKitMakeError(code, errorMessage);
    }
    return SSHKitMakeError(code, fallback);
}

- (NSError *)libSSHErrorWithSession:(ssh_session)session code:(SSHKitErrorCode)code fallback:(NSString *)fallback {
    const char *message = session != NULL ? ssh_get_error(session) : NULL;
    if (message != NULL && strlen(message) > 0) {
        return SSHKitMakeError(code, [NSString stringWithUTF8String:message]);
    }
    return SSHKitMakeError(code, fallback);
}

- (NSError *)sftpErrorForOperation:(NSString *)operation sftp:(sftp_session)sftp {
    int status = sftp != NULL ? sftp_get_error(sftp) : SSH_ERROR;
    NSString *message = [NSString stringWithFormat:@"%@ failed with SFTP status %d.", operation, status];
    return SSHKitMakeError(SSHKitErrorCodeCommandFailed, message);
}

- (void)clearLibSSHSession:(ssh_session)session {
    [self.taskLock lock];
    if (self.session == session) {
        self.session = NULL;
    }
    [self.taskLock unlock];

    if (session != NULL) {
        ssh_disconnect(session);
        ssh_free(session);
    }
    [self closeWorkerSocketHandle];
}

- (void)closeWorkerSocketHandle {
    SSHCoreSocketHandle *socketHandle = self.worker.socketHandle;
    int fileDescriptor = socketHandle ? [socketHandle takeFileDescriptorForClose] : -1;
    if (fileDescriptor >= 0) {
        close(fileDescriptor);
    }
    self.worker.socketHandle = nil;
}

- (BOOL)isTaskCancelled {
    [self.taskLock lock];
    BOOL cancelled = self.taskCancelled;
    [self.taskLock unlock];
    return cancelled;
}

- (void)clearCurrentTask {
    [self.taskLock lock];
    self.currentTask = nil;
    self.taskCancelled = NO;
    [self.taskLock unlock];
}

- (void)dealloc {
    [self.taskLock lock];
    ssh_session session = self.session;
    self.session = NULL;
    id taskObject = self.currentTask;
    self.currentTask = nil;
    SSHCoreSocketHandle *socketHandle = self.worker.socketHandle;
    self.worker.socketHandle = nil;
    dispatch_queue_t workerQueue = self.worker.queue;
    [self.taskLock unlock];

    if (session == NULL && socketHandle == nil && taskObject == nil) {
        return;
    }

    dispatch_async(workerQueue, ^{
        if ([taskObject respondsToSelector:@selector(invalidateOnWorkerQueue)]) {
            void (*invalidateMessage)(id, SEL) = (void *)objc_msgSend;
            invalidateMessage(taskObject, @selector(invalidateOnWorkerQueue));
        }

        if (session != NULL) {
            ssh_disconnect(session);
            ssh_free(session);
        }

        int fileDescriptor = socketHandle ? [socketHandle takeFileDescriptorForClose] : -1;
        if (fileDescriptor >= 0) {
            close(fileDescriptor);
        }
    });
}

@end
