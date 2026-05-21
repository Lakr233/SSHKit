#import "SSHCoreLibSSHCommandRuntime.h"

#import <SSHKitObjC/SSHKitError.h>

#import "SSHCoreLibSSHHelpers.h"
#import "SSHKitCommand+Private.h"

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

        [self finishWithExitStatus:SSHCoreAbnormalExitStatus exitSignal:nil];
        completion(nil);
    });
}

- (void)readAvailableDataAndScheduleNextRead {
    if (self.finished || self.channel == NULL) {
        return;
    }

    if (![self drainStream:0 eventKind:SSHKitCommandEventKindStandardOutput] ||
        ![self drainStream:1 eventKind:SSHKitCommandEventKindStandardError]) {
        [self finishWithExitStatus:SSHCoreAbnormalExitStatus exitSignal:nil];
        return;
    }

    if (ssh_channel_is_eof(self.channel) || ssh_channel_is_closed(self.channel)) {
        int32_t exitStatus = SSHCoreAbnormalExitStatus;
        NSString *exitSignal = nil;
        [self getExitStatus:&exitStatus exitSignal:&exitSignal];
        [self finishWithExitStatus:exitStatus exitSignal:exitSignal];
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

- (BOOL)getExitStatus:(int32_t *)exitStatus exitSignal:(NSString **)exitSignal {
    uint32_t exitCode = 0;
    char *rawExitSignal = NULL;
    if (self.channel == NULL) {
        if (exitStatus != NULL) {
            *exitStatus = SSHCoreAbnormalExitStatus;
        }
        if (exitSignal != NULL) {
            *exitSignal = nil;
        }
        return NO;
    }

    int exitState = ssh_channel_get_exit_state(self.channel, &exitCode, &rawExitSignal, NULL);
    if (exitState != SSH_OK) {
        free(rawExitSignal);
        if (exitStatus != NULL) {
            *exitStatus = SSHCoreAbnormalExitStatus;
        }
        if (exitSignal != NULL) {
            *exitSignal = nil;
        }
        return NO;
    }

    if (exitStatus != NULL) {
        *exitStatus = (int32_t)exitCode;
    }
    if (exitSignal != NULL) {
        *exitSignal = rawExitSignal != NULL ? [NSString stringWithUTF8String:rawExitSignal] : nil;
    }
    free(rawExitSignal);
    return YES;
}

- (void)finishWithExitStatus:(int32_t)exitStatus exitSignal:(NSString *)exitSignal {
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

    self.onClosed(exitStatus, exitSignal);
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
