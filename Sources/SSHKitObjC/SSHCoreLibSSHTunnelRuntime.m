#import "SSHCoreLibSSHTunnelRuntime.h"

#import <SSHKitObjC/SSHKitError.h>

#import "SSHKitTunnelChannel+Private.h"

@interface SSHCoreLibSSHTunnelRuntime ()

@property (nonatomic) ssh_channel channel;
@property (nonatomic) dispatch_queue_t workerQueue;
@property (nonatomic, copy) SSHCoreTunnelCloseHandler closeHandler;
@property (nonatomic, copy) BOOL (^isCancelled)(void);
@property (nonatomic) BOOL closed;
@property (nonatomic) BOOL didCallCloseHandler;

@end

@implementation SSHCoreLibSSHTunnelRuntime

- (instancetype)initWithChannel:(ssh_channel)channel
                    workerQueue:(dispatch_queue_t)workerQueue
                    isCancelled:(BOOL (^)(void))isCancelled
                    closeHandler:(SSHCoreTunnelCloseHandler)closeHandler {
    NSParameterAssert(channel != NULL);
    NSParameterAssert(workerQueue != nil);

    self = [super init];
    if (self) {
        _channel = channel;
        _workerQueue = workerQueue;
        _isCancelled = [isCancelled copy];
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
            BOOL cancelled = [self isTunnelCancelled];
            if (cancelled) {
                [self closeAfterTerminalTunnelFailure];
            }
            completion(nil, [self tunnelErrorWithCode:SSHKitErrorCodeConnectionFailed fallback:@"Timed out waiting for SSH tunnel channel data." cancelled:cancelled]);
            return;
        }
        if (byteCount == SSH_ERROR) {
            BOOL cancelled = [self isTunnelCancelled];
            [self closeAfterTerminalTunnelFailure];
            completion(nil, [self tunnelErrorWithCode:SSHKitErrorCodeConnectionFailed fallback:@"Unable to read SSH tunnel channel." cancelled:cancelled]);
            return;
        }
        if (byteCount == 0) {
            BOOL cancelled = [self isTunnelCancelled];
            [self closeAfterTerminalTunnelFailure];
            completion(nil, [self tunnelErrorWithCode:SSHKitErrorCodeConnectionFailed fallback:@"SSH tunnel channel reached EOF." cancelled:cancelled]);
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
                BOOL cancelled = [self isTunnelCancelled];
                [self closeAfterTerminalTunnelFailure];
                completion([self tunnelErrorWithCode:SSHKitErrorCodeConnectionFailed fallback:@"Unable to write SSH tunnel channel." cancelled:cancelled]);
                return;
            }
            if (written <= 0) {
                BOOL cancelled = [self isTunnelCancelled];
                [self closeAfterTerminalTunnelFailure];
                completion([self tunnelErrorWithCode:SSHKitErrorCodeConnectionFailed fallback:@"SSH tunnel write made no progress." cancelled:cancelled]);
                return;
            }
            bytes += written;
            remaining -= (NSUInteger)written;
        }

        completion(nil);
    });
}

- (BOOL)isTunnelCancelled {
    return self.isCancelled ? self.isCancelled() : NO;
}

- (NSError *)tunnelErrorWithCode:(SSHKitErrorCode)code fallback:(NSString *)fallback cancelled:(BOOL)cancelled {
    return cancelled ? SSHKitMakeError(SSHKitErrorCodeCancelled, @"SSH tunnel channel was cancelled.") : SSHKitMakeError(code, fallback);
}

- (void)closeWithCompletion:(SSHKitCompletion)completion {
    dispatch_async(self.workerQueue, ^{
        [self invalidateOnWorkerQueue];
        [self callCloseHandlerIfNeeded];
        completion(nil);
    });
}

- (void)closeAfterTerminalTunnelFailure {
    [self invalidateOnWorkerQueue];
    [self callCloseHandlerIfNeeded];
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
