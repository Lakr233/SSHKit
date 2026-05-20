#import <SSHKitObjC/SSHKitError.h>
#import <SSHKitObjC/SSHKitConnection.h>
#import "SSHCoreOpenSSHClient.h"
#import "SSHCoreSessionWorker.h"
#import "SSHKitShell+Private.h"

@interface SSHKitConnection ()

@property (nonatomic, copy, readwrite) SSHKitConfiguration *configuration;
@property (nonatomic) SSHCoreSessionWorker *worker;
@property (nonatomic) SSHCoreOpenSSHClient *client;

@end

@implementation SSHKitCommandResult

- (instancetype)initWithStandardOutput:(NSData *)standardOutput
                         standardError:(NSData *)standardError
                            exitStatus:(int32_t)exitStatus {
    self = [super init];
    if (self) {
        _standardOutput = [standardOutput copy];
        _standardError = [standardError copy];
        _exitStatus = exitStatus;
    }
    return self;
}

@end

@implementation SSHKitShellEvent

- (instancetype)initWithKind:(SSHKitShellEventKind)kind data:(NSData *)data exitStatus:(int32_t)exitStatus {
    self = [super init];
    if (self) {
        _kind = kind;
        _data = [data copy];
        _exitStatus = exitStatus;
    }
    return self;
}

@end

@implementation SSHKitShell

- (instancetype)initWithWriteBlock:(SSHKitShellDataBlock)writeBlock
                       resizeBlock:(SSHKitShellResizeBlock)resizeBlock
                        closeBlock:(SSHKitShellCloseBlock)closeBlock {
    self = [super init];
    if (self) {
        _writeBlock = [writeBlock copy];
        _resizeBlock = [resizeBlock copy];
        _closeBlock = [closeBlock copy];
    }
    return self;
}

- (void)writeData:(NSData *)data completion:(SSHKitCompletion)completion {
    NSParameterAssert(data.length > 0);
    self.writeBlock(data, completion);
}

- (void)resizeWithColumns:(uint16_t)columns rows:(uint16_t)rows completion:(SSHKitCompletion)completion {
    NSParameterAssert(columns > 0);
    NSParameterAssert(rows > 0);
    self.resizeBlock(columns, rows, completion);
}

- (void)closeWithCompletion:(SSHKitCompletion)completion {
    self.closeBlock(completion);
}

@end

@implementation SSHKitConnection

- (instancetype)initWithConfiguration:(SSHKitConfiguration *)configuration {
    self = [super init];
    if (self) {
        _configuration = [configuration copy];
        _worker = [[SSHCoreSessionWorker alloc] init];
        _client = [[SSHCoreOpenSSHClient alloc] initWithConfiguration:_configuration];
    }
    return self;
}

- (void)connectWithCompletion:(SSHKitCompletion)completion {
    [self.worker async:^{
        if (self.worker.state != SSHCoreSessionStateIdle) {
            NSError *error = SSHKitMakeError(SSHKitErrorCodeCancelled, @"SSH connection was cancelled before connect began.");
            [self completeOnDefaultQueue:completion error:error];
            return;
        }

        [self.worker transitionToState:SSHCoreSessionStateConnecting];
        NSError *error = nil;
        if ([self.client verifyConnectionWithError:&error]) {
            [self.worker transitionToState:SSHCoreSessionStateReady];
            [self completeOnDefaultQueue:completion error:nil];
            return;
        }

        [self.worker transitionToState:SSHCoreSessionStateClosed];
        [self completeOnDefaultQueue:completion error:error];
    }];
}

- (void)executeCommand:(NSString *)command completion:(SSHKitCommandCompletion)completion {
    NSParameterAssert(command.length > 0);
    [self executeCommand:command requestPTY:NO completion:completion];
}

- (void)executePTYCommand:(NSString *)command completion:(SSHKitCommandCompletion)completion {
    NSParameterAssert(command.length > 0);
    [self executeCommand:command requestPTY:YES completion:completion];
}

- (void)executeCommand:(NSString *)command requestPTY:(BOOL)requestPTY completion:(SSHKitCommandCompletion)completion {

    [self.worker async:^{
        if (self.worker.state != SSHCoreSessionStateReady) {
            NSError *error = SSHKitMakeError(SSHKitErrorCodeInvalidState, @"SSH session is not connected.");
            [self completeCommandOnDefaultQueue:completion result:nil error:error];
            return;
        }

        [self.worker transitionToState:SSHCoreSessionStateRunningCommand];
        NSError *error = nil;
        SSHKitCommandResult *result = requestPTY
            ? [self.client executePTYCommand:command error:&error]
            : [self.client executeCommand:command error:&error];
        [self.worker transitionToState:SSHCoreSessionStateReady];
        [self completeCommandOnDefaultQueue:completion result:result error:error];
    }];
}

- (void)openShellWithTerminalType:(NSString *)terminalType
                           columns:(uint16_t)columns
                              rows:(uint16_t)rows
                      eventHandler:(SSHKitShellEventHandler)eventHandler
                        completion:(SSHKitShellCompletion)completion {
    NSParameterAssert(terminalType.length > 0);
    NSParameterAssert(columns > 0);
    NSParameterAssert(rows > 0);

    [self.worker async:^{
        if (self.worker.state != SSHCoreSessionStateReady) {
            NSError *error = SSHKitMakeError(SSHKitErrorCodeInvalidState, @"SSH session is not connected.");
            [self completeShellOnDefaultQueue:completion shell:nil error:error];
            return;
        }

        [self.worker transitionToState:SSHCoreSessionStateRunningShell];
        NSError *error = nil;
        SSHKitShell *shell = [self.client openShellWithTerminalType:terminalType
                                                            columns:columns
                                                               rows:rows
                                                       eventHandler:eventHandler
                                                           onClosed:^(int32_t exitStatus) {
            [self.worker async:^{
                if (self.worker.state == SSHCoreSessionStateRunningShell) {
                    [self.worker transitionToState:SSHCoreSessionStateReady];
                }
                SSHKitShellEvent *event = [[SSHKitShellEvent alloc] initWithKind:SSHKitShellEventKindClosed
                                                                            data:[NSData data]
                                                                      exitStatus:exitStatus];
                eventHandler(event);
            }];
        } error:&error];

        if (!shell) {
            [self.worker transitionToState:SSHCoreSessionStateReady];
            [self completeShellOnDefaultQueue:completion shell:nil error:error];
            return;
        }

        completion(shell, nil);
    }];
}

- (void)disconnectWithCompletion:(SSHKitCompletion)completion {
    [self.client cancelCurrentTask];
    [self.worker requestClose];
    [self.worker async:^{
        [self completeOnDefaultQueue:completion error:nil];
    }];
}

- (void)completeOnDefaultQueue:(SSHKitCompletion)completion error:(NSError *)error {
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_DEFAULT, 0), ^{
        completion(error);
    });
}

- (void)completeCommandOnDefaultQueue:(SSHKitCommandCompletion)completion
                               result:(SSHKitCommandResult *)result
                                error:(NSError *)error {
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_DEFAULT, 0), ^{
        completion(result, error);
    });
}

- (void)completeShellOnDefaultQueue:(SSHKitShellCompletion)completion
                              shell:(SSHKitShell *)shell
                              error:(NSError *)error {
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_DEFAULT, 0), ^{
        completion(shell, error);
    });
}

@end
