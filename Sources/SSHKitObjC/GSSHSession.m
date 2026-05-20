#import <SSHKitObjC/GSSHError.h>
#import <SSHKitObjC/GSSHSession.h>

@interface GSSHSession ()

@property (nonatomic, copy, readwrite) GSSHSessionConfiguration *configuration;
@property (nonatomic) dispatch_queue_t queue;
@property (nonatomic) BOOL connected;

@end

@implementation GSSHCommandResult

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

@implementation GSSHSession

- (instancetype)initWithConfiguration:(GSSHSessionConfiguration *)configuration {
    self = [super init];
    if (self) {
        _configuration = [configuration copy];
        NSString *label = [NSString stringWithFormat:@"io.github.sshkit.session.%p", self];
        _queue = dispatch_queue_create(label.UTF8String, DISPATCH_QUEUE_SERIAL);
    }
    return self;
}

- (void)connectWithCompletion:(GSSHCompletion)completion {
    dispatch_async(self.queue, ^{
        NSError *error = GSSHMakeError(
            GSSHErrorCodeUnavailable,
            @"libssh source target is not wired into SSHKitObjC yet."
        );
        [self completeOnDefaultQueue:completion error:error];
    });
}

- (void)executeCommand:(NSString *)command completion:(GSSHCommandCompletion)completion {
    dispatch_async(self.queue, ^{
        if (!self.connected) {
            NSError *error = GSSHMakeError(GSSHErrorCodeInvalidState, @"SSH session is not connected.");
            [self completeCommandOnDefaultQueue:completion result:nil error:error];
            return;
        }

        NSError *error = GSSHMakeError(
            GSSHErrorCodeUnavailable,
            @"libssh command execution is not wired into SSHKitObjC yet."
        );
        [self completeCommandOnDefaultQueue:completion result:nil error:error];
    });
}

- (void)disconnectWithCompletion:(GSSHCompletion)completion {
    dispatch_async(self.queue, ^{
        self.connected = NO;
        [self completeOnDefaultQueue:completion error:nil];
    });
}

- (void)completeOnDefaultQueue:(GSSHCompletion)completion error:(NSError *)error {
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_DEFAULT, 0), ^{
        completion(error);
    });
}

- (void)completeCommandOnDefaultQueue:(GSSHCommandCompletion)completion
                               result:(GSSHCommandResult *)result
                                error:(NSError *)error {
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_DEFAULT, 0), ^{
        completion(result, error);
    });
}

@end
