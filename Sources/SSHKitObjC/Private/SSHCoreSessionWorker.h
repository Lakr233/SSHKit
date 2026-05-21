#import <Foundation/Foundation.h>

@class SSHCoreCancellationToken;
@class SSHCoreSocketHandle;

NS_ASSUME_NONNULL_BEGIN

typedef NS_ENUM(NSInteger, SSHCoreSessionState) {
    SSHCoreSessionStateIdle = 0,
    SSHCoreSessionStateConnecting = 1,
    SSHCoreSessionStateReady = 2,
    SSHCoreSessionStateRunningCommand = 3,
    SSHCoreSessionStateRunningShell = 4,
    SSHCoreSessionStateRunningSFTP = 5,
    SSHCoreSessionStateRunningTunnel = 6,
    SSHCoreSessionStateClosing = 7,
    SSHCoreSessionStateClosed = 8,
};

@interface SSHCoreSessionWorker : NSObject

@property (nonatomic, readonly) dispatch_queue_t queue;
@property (nonatomic, readonly) SSHCoreSessionState state;
@property (atomic, nullable) SSHCoreSocketHandle *socketHandle;
@property (nonatomic, readonly) SSHCoreCancellationToken *cancellationToken;

- (void)async:(dispatch_block_t)block;
- (void)assertOnWorkerQueue;
- (void)transitionToState:(SSHCoreSessionState)state;
- (void)requestClose;
- (BOOL)isActiveJobState:(SSHCoreSessionState)state;

@end

NS_ASSUME_NONNULL_END
