#import "SSHCoreSessionWorker.h"
#import "SSHCoreCancellationToken.h"
#import "SSHCoreSocketHandle.h"

#include <unistd.h>

static void *SSHCoreSessionWorkerQueueKey = &SSHCoreSessionWorkerQueueKey;

@interface SSHCoreSessionWorker ()

@property (nonatomic, readwrite) dispatch_queue_t queue;
@property (nonatomic) SSHCoreSessionState mutableState;
@property (nonatomic, readwrite) SSHCoreCancellationToken *cancellationToken;

@end

@implementation SSHCoreSessionWorker

- (instancetype)init {
    self = [super init];
    if (self) {
        NSString *label = [NSString stringWithFormat:@"io.github.sshkit.core.session-worker.%p", self];
        _queue = dispatch_queue_create(label.UTF8String, DISPATCH_QUEUE_SERIAL);
        dispatch_queue_set_specific(_queue, SSHCoreSessionWorkerQueueKey, (__bridge void *)self, NULL);
        _mutableState = SSHCoreSessionStateIdle;
        _cancellationToken = [[SSHCoreCancellationToken alloc] init];
    }
    return self;
}

- (void)dealloc {
    SSHCoreSocketHandle *socketHandle = _socketHandle;
    if (!socketHandle) {
        return;
    }

    void (^closeSocket)(void) = ^{
        int fileDescriptor = [socketHandle takeFileDescriptorForClose];
        if (fileDescriptor >= 0) {
            close(fileDescriptor);
        }
    };

    if (dispatch_get_specific(SSHCoreSessionWorkerQueueKey) == (__bridge void *)self) {
        closeSocket();
        return;
    }

    dispatch_sync(_queue, closeSocket);
}

- (SSHCoreSessionState)state {
    __block SSHCoreSessionState state;
    if (dispatch_get_specific(SSHCoreSessionWorkerQueueKey) == (__bridge void *)self) {
        return self.mutableState;
    }
    dispatch_sync(self.queue, ^{
        state = self.mutableState;
    });
    return state;
}

- (void)async:(dispatch_block_t)block {
    dispatch_async(self.queue, block);
}

- (void)assertOnWorkerQueue {
    NSAssert(dispatch_get_specific(SSHCoreSessionWorkerQueueKey) == (__bridge void *)self,
             @"SSHCoreSessionWorker accessed outside its worker queue.");
}

- (void)transitionToState:(SSHCoreSessionState)state {
    [self assertOnWorkerQueue];
    if (![self canTransitionFromState:self.mutableState toState:state]) {
        [NSException raise:NSInternalInconsistencyException
                    format:@"Invalid SSHCoreSessionWorker state transition: %ld -> %ld",
         (long)self.mutableState,
         (long)state];
    }
    self.mutableState = state;
}

- (void)requestClose {
    SSHCoreSocketHandle *socketHandle = self.socketHandle;
    [self.cancellationToken cancel];
    [socketHandle shutdownNow];

    [self async:^{
        if (self.mutableState == SSHCoreSessionStateClosed) {
            return;
        }

        if (self.mutableState != SSHCoreSessionStateClosing) {
            [self transitionToState:SSHCoreSessionStateClosing];
        }

        SSHCoreSocketHandle *socketHandle = self.socketHandle;
        int fileDescriptor = socketHandle ? [socketHandle takeFileDescriptorForClose] : -1;
        if (fileDescriptor >= 0) {
            close(fileDescriptor);
        }

        self.socketHandle = nil;
        [self transitionToState:SSHCoreSessionStateClosed];
    }];
}

- (BOOL)isActiveJobState:(SSHCoreSessionState)state {
    return state == SSHCoreSessionStateConnecting ||
        state == SSHCoreSessionStateRunningCommand ||
        state == SSHCoreSessionStateRunningShell ||
        state == SSHCoreSessionStateRunningSFTP ||
        state == SSHCoreSessionStateRunningTunnel;
}

- (BOOL)canTransitionFromState:(SSHCoreSessionState)fromState toState:(SSHCoreSessionState)toState {
    if (fromState == toState && (toState == SSHCoreSessionStateClosing || toState == SSHCoreSessionStateClosed)) {
        return YES;
    }

    if ([self isActiveJobState:fromState] && toState == SSHCoreSessionStateClosing) {
        return YES;
    }

    switch (fromState) {
        case SSHCoreSessionStateIdle:
            return toState == SSHCoreSessionStateConnecting ||
                toState == SSHCoreSessionStateClosing;
        case SSHCoreSessionStateConnecting:
            return toState == SSHCoreSessionStateReady ||
                toState == SSHCoreSessionStateClosed;
        case SSHCoreSessionStateReady:
            return toState == SSHCoreSessionStateRunningCommand ||
                toState == SSHCoreSessionStateRunningShell ||
                toState == SSHCoreSessionStateRunningSFTP ||
                toState == SSHCoreSessionStateRunningTunnel ||
                toState == SSHCoreSessionStateClosing;
        case SSHCoreSessionStateRunningCommand:
        case SSHCoreSessionStateRunningShell:
        case SSHCoreSessionStateRunningSFTP:
        case SSHCoreSessionStateRunningTunnel:
            return toState == SSHCoreSessionStateReady;
        case SSHCoreSessionStateClosing:
            return toState == SSHCoreSessionStateClosed;
        case SSHCoreSessionStateClosed:
            return NO;
    }
}

@end
