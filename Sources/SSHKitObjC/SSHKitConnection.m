#import <SSHKitObjC/SSHKitError.h>
#import <SSHKitObjC/SSHKitConnection.h>
#import "SSHCoreSessionWorker.h"

@interface SSHKitConnection ()

@property (nonatomic, copy, readwrite) SSHKitConfiguration *configuration;
@property (nonatomic) SSHCoreSessionWorker *worker;

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

@implementation SSHKitConnection

- (instancetype)initWithConfiguration:(SSHKitConfiguration *)configuration {
    self = [super init];
    if (self) {
        _configuration = [configuration copy];
        _worker = [[SSHCoreSessionWorker alloc] init];
    }
    return self;
}

- (void)connectWithCompletion:(SSHKitCompletion)completion {
    [self.worker async:^{
        [self.worker transitionToState:SSHCoreSessionStateConnecting];
        NSError *error = SSHKitMakeError(
            SSHKitErrorCodeUnavailable,
            @"libssh source target is not wired into SSHKitObjC yet."
        );
        [self.worker transitionToState:SSHCoreSessionStateClosed];
        [self completeOnDefaultQueue:completion error:error];
    }];
}

- (void)executeCommand:(NSString *)command completion:(SSHKitCommandCompletion)completion {
    [self.worker async:^{
        if (self.worker.state != SSHCoreSessionStateReady) {
            NSError *error = SSHKitMakeError(SSHKitErrorCodeInvalidState, @"SSH session is not connected.");
            [self completeCommandOnDefaultQueue:completion result:nil error:error];
            return;
        }

        NSError *error = SSHKitMakeError(
            SSHKitErrorCodeUnavailable,
            @"libssh command execution is not wired into SSHKitObjC yet."
        );
        [self completeCommandOnDefaultQueue:completion result:nil error:error];
    }];
}

- (void)disconnectWithCompletion:(SSHKitCompletion)completion {
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

@end
