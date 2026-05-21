#import "SSHCoreOpenSSHClient.h"

#import <CLibSSH/CLibSSH.h>
#import <SSHKitObjC/SSHKitConfiguration.h>
#import <SSHKitObjC/SSHKitConnection.h>
#import <SSHKitObjC/SSHKitError.h>
#include <libssh/callbacks.h>
#import "SSHCoreSessionWorker.h"
#import "SSHCoreSocketHandle.h"
#import "SSHKitCommand+Private.h"
#import "SSHKitPortForward+Private.h"
#import "SSHKitSFTPClient+Private.h"
#import "SSHKitShell+Private.h"
#import "SSHKitTunnelChannel+Private.h"
#import "SSHCoreLibSSHCommandRuntime.h"
#import "SSHCoreLibSSHHelpers.h"
#import "SSHCoreLibSSHLocalForwardRuntime.h"
#import "SSHCoreLibSSHRemoteForwardRuntime.h"
#import "SSHCoreLibSSHSFTPFileRuntime.h"
#import "SSHCoreLibSSHSFTPRuntime.h"
#import "SSHCoreLibSSHShellRuntime.h"
#import "SSHCoreLibSSHTunnelRuntime.h"
#import "SSHCoreOpenSSHClient+Internal.h"
#import "SSHCoreOpenSSHClient+Connect.h"

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

// Public SSHCoreOpenSSHClient methods are implemented across SSHCoreOpenSSHClient+*.m
// category files. Silence the resulting -Wincomplete-implementation noise on this
// primary @implementation.
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wincomplete-implementation"

@implementation SSHCoreOpenSSHClient

- (instancetype)initWithConfiguration:(SSHKitConfiguration *)configuration worker:(SSHCoreSessionWorker *)worker {
    NSParameterAssert(worker != nil);

    self = [super init];
    if (self) {
        _configuration = [configuration copy];
        _worker = worker;
        _taskLock = [[NSLock alloc] init];
        _proxyJumpCallbackPointers = [[NSMutableArray alloc] init];
        _proxyJumpCallbackConfigurations = @[];
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

- (void)cancelCurrentTask {
    SSHCoreSocketHandle *socketHandle = self.worker.socketHandle;
    [self.taskLock lock];
    id taskObject = self.currentTask;
    ssh_session session = self.session;
    BOOL shouldShutdownSocket = taskObject != nil || session != NULL || socketHandle != nil;
    if (shouldShutdownSocket) {
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
        [socketHandle shutdownNow];
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
    return [self sftpErrorForOperation:operation status:status];
}

- (NSError *)sftpErrorForOperation:(NSString *)operation status:(int)status {
    SSHKitErrorCode code = SSHKitErrorCodeSFTPFailure;
    switch (status) {
        case SSH_FX_NO_SUCH_FILE:
            code = SSHKitErrorCodeSFTPFileNotFound;
            break;
        case SSH_FX_PERMISSION_DENIED:
            code = SSHKitErrorCodeSFTPPermissionDenied;
            break;
        default:
            break;
    }
    NSString *message = [NSString stringWithFormat:@"%@ failed with SFTP status %d.", operation, status];
    return SSHKitMakeError(code, message);
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
    [self freeProxyJumpCallbacks];
    [self closeWorkerSocketHandle];
}

- (void)freeProxyJumpCallbacks {
    for (NSValue *value in self.proxyJumpCallbackPointers) {
        free([value pointerValue]);
    }
    [self.proxyJumpCallbackPointers removeAllObjects];
    self.proxyJumpCallbackConfigurations = @[];
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
    NSArray<NSValue *> *proxyJumpCallbackPointers = [self.proxyJumpCallbackPointers copy];
    [self.proxyJumpCallbackPointers removeAllObjects];
    self.proxyJumpCallbackConfigurations = @[];
    [self.taskLock unlock];

    if (session == NULL && socketHandle == nil && taskObject == nil && proxyJumpCallbackPointers.count == 0) {
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
        for (NSValue *value in proxyJumpCallbackPointers) {
            free([value pointerValue]);
        }

        int fileDescriptor = socketHandle ? [socketHandle takeFileDescriptorForClose] : -1;
        if (fileDescriptor >= 0) {
            close(fileDescriptor);
        }
    });
}

@end

#pragma clang diagnostic pop
