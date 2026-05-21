#import "SSHCoreLibSSHShellRuntime.h"

#import <SSHKitObjC/SSHKitError.h>

#import "SSHCoreLibSSHHelpers.h"
#import "SSHKitShell+Private.h"

static NSDictionary<NSString *, NSString *> *SSHCoreByteShapeMetadata(const void *bytes, NSUInteger length) {
    const uint8_t *cursor = bytes;
    NSUInteger carriageReturns = 0;
    NSUInteger lineFeeds = 0;
    NSUInteger carriageReturnLineFeeds = 0;
    NSUInteger bareLineFeeds = 0;
    NSUInteger escapeBytes = 0;
    NSUInteger deleteBytes = 0;
    NSUInteger tabBytes = 0;
    NSUInteger printableASCIIBytes = 0;
    BOOL previousByteWasCarriageReturn = NO;

    for (NSUInteger index = 0; index < length; index++) {
        uint8_t byte = cursor[index];
        if (byte == 0x0D) {
            carriageReturns += 1;
        }
        if (byte == 0x0A) {
            lineFeeds += 1;
            if (previousByteWasCarriageReturn) {
                carriageReturnLineFeeds += 1;
            } else {
                bareLineFeeds += 1;
            }
        }
        if (byte == 0x1B) {
            escapeBytes += 1;
        }
        if (byte == 0x08 || byte == 0x7F) {
            deleteBytes += 1;
        }
        if (byte == 0x09) {
            tabBytes += 1;
        }
        if (byte >= 0x20 && byte <= 0x7E) {
            printableASCIIBytes += 1;
        }
        previousByteWasCarriageReturn = byte == 0x0D;
    }

    return @{
        @"byteCount": [NSString stringWithFormat:@"%lu", (unsigned long)length],
        @"carriageReturns": [NSString stringWithFormat:@"%lu", (unsigned long)carriageReturns],
        @"lineFeeds": [NSString stringWithFormat:@"%lu", (unsigned long)lineFeeds],
        @"carriageReturnLineFeeds": [NSString stringWithFormat:@"%lu", (unsigned long)carriageReturnLineFeeds],
        @"bareLineFeeds": [NSString stringWithFormat:@"%lu", (unsigned long)bareLineFeeds],
        @"escapeBytes": [NSString stringWithFormat:@"%lu", (unsigned long)escapeBytes],
        @"deleteBytes": [NSString stringWithFormat:@"%lu", (unsigned long)deleteBytes],
        @"tabBytes": [NSString stringWithFormat:@"%lu", (unsigned long)tabBytes],
        @"printableASCIIBytes": [NSString stringWithFormat:@"%lu", (unsigned long)printableASCIIBytes],
    };
}

static NSMutableDictionary<NSString *, NSString *> *SSHCoreMutableByteShapeMetadata(const void *bytes, NSUInteger length) {
    return [SSHCoreByteShapeMetadata(bytes, length) mutableCopy];
}

@interface SSHCoreLibSSHShellRuntime ()

@property (nonatomic) ssh_channel channel;
@property (nonatomic) dispatch_queue_t workerQueue;
@property (nonatomic, copy) SSHKitShellEventHandler eventHandler;
@property (nonatomic, copy) SSHCoreShellClosedBlock onClosed;
@property (nonatomic, copy) SSHCoreRuntimeLogBlock logBlock;
@property (nonatomic) BOOL finished;
@property (nonatomic) NSUInteger readPollsToLogAfterWrite;
@property (nonatomic) NSUInteger bytesReadInCurrentPoll;

@end

@implementation SSHCoreLibSSHShellRuntime

- (instancetype)initWithChannel:(ssh_channel)channel
                    workerQueue:(dispatch_queue_t)workerQueue
                    eventHandler:(SSHKitShellEventHandler)eventHandler
                        onClosed:(SSHCoreShellClosedBlock)onClosed
                         logBlock:(SSHCoreRuntimeLogBlock)logBlock {
    NSParameterAssert(channel != NULL);
    NSParameterAssert(workerQueue != nil);

    self = [super init];
    if (self) {
        _channel = channel;
        _workerQueue = workerQueue;
        _eventHandler = [eventHandler copy];
        _onClosed = [onClosed copy];
        _logBlock = [logBlock copy];
    }
    return self;
}

- (void)start {
    dispatch_async(self.workerQueue, ^{
        [self logLevel:SSHKitLogLevelDebug phase:@"shell" message:@"SSH shell read loop started." metadata:@{}];
        [self readAvailableDataAndScheduleNextRead];
    });
}

- (void)writeData:(NSData *)data completion:(SSHKitCompletion)completion {
    dispatch_async(self.workerQueue, ^{
        if (self.finished || self.channel == NULL) {
            completion(SSHKitMakeError(SSHKitErrorCodeInvalidState, @"SSH shell is closed."));
            return;
        }

        NSMutableDictionary<NSString *, NSString *> *metadata = SSHCoreMutableByteShapeMetadata(data.bytes, data.length);
        metadata[@"channelOpen"] = ssh_channel_is_open(self.channel) ? @"true" : @"false";
        metadata[@"channelEOF"] = ssh_channel_is_eof(self.channel) ? @"true" : @"false";
        [self logLevel:SSHKitLogLevelDebug phase:@"shell" message:@"SSH shell write requested." metadata:metadata];

        const uint8_t *bytes = data.bytes;
        NSUInteger remaining = data.length;
        NSUInteger totalWritten = 0;
        while (remaining > 0) {
            uint32_t chunkLength = remaining > UINT32_MAX ? UINT32_MAX : (uint32_t)remaining;
            int written = ssh_channel_write(self.channel, bytes, chunkLength);
            if (written == SSH_ERROR) {
                [self logLevel:SSHKitLogLevelError phase:@"shell" message:@"SSH shell write failed." metadata:metadata];
                completion(SSHKitMakeError(SSHKitErrorCodeConnectionFailed, @"Unable to write to SSH shell."));
                return;
            }
            if (written <= 0) {
                [self logLevel:SSHKitLogLevelError phase:@"shell" message:@"SSH shell write made no progress." metadata:metadata];
                completion(SSHKitMakeError(SSHKitErrorCodeConnectionFailed, @"SSH shell write made no progress."));
                return;
            }
            bytes += written;
            remaining -= (NSUInteger)written;
            totalWritten += (NSUInteger)written;
        }

        self.readPollsToLogAfterWrite = MAX(self.readPollsToLogAfterWrite, 8);
        metadata[@"writtenBytes"] = [NSString stringWithFormat:@"%lu", (unsigned long)totalWritten];
        metadata[@"pendingEchoReadPollLogs"] = [NSString stringWithFormat:@"%lu", (unsigned long)self.readPollsToLogAfterWrite];
        [self logLevel:SSHKitLogLevelDebug phase:@"shell" message:@"SSH shell write completed." metadata:metadata];
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

    self.bytesReadInCurrentPoll = 0;
    if (![self drainStream:0 eventKind:SSHKitShellEventKindStandardOutput] ||
        ![self drainStream:1 eventKind:SSHKitShellEventKindStandardError]) {
        [self logLevel:SSHKitLogLevelError phase:@"shell" message:@"SSH shell read failed." metadata:@{}];
        [self finishWithExitStatus:-1];
        return;
    }

    if (self.bytesReadInCurrentPoll == 0 && self.readPollsToLogAfterWrite > 0) {
        self.readPollsToLogAfterWrite -= 1;
        [self logLevel:SSHKitLogLevelDebug phase:@"shell" message:@"SSH shell read poll returned no data after recent input." metadata:@{
            @"remainingLoggedPolls": [NSString stringWithFormat:@"%lu", (unsigned long)self.readPollsToLogAfterWrite],
            @"channelOpen": ssh_channel_is_open(self.channel) ? @"true" : @"false",
            @"channelEOF": ssh_channel_is_eof(self.channel) ? @"true" : @"false",
        }];
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
        self.bytesReadInCurrentPoll += (NSUInteger)byteCount;
        NSMutableDictionary<NSString *, NSString *> *metadata = SSHCoreMutableByteShapeMetadata(buffer, (NSUInteger)byteCount);
        metadata[@"stream"] = isStderr ? @"stderr" : @"stdout";
        metadata[@"channelOpen"] = ssh_channel_is_open(self.channel) ? @"true" : @"false";
        metadata[@"channelEOF"] = ssh_channel_is_eof(self.channel) ? @"true" : @"false";
        [self logLevel:SSHKitLogLevelDebug phase:@"shell" message:@"SSH shell read delivered data." metadata:metadata];
        SSHKitShellEvent *event = [[SSHKitShellEvent alloc] initWithKind:eventKind data:data exitStatus:0];
        self.eventHandler(event);
    }
}

- (void)logLevel:(SSHKitLogLevel)level
           phase:(NSString *)phase
         message:(NSString *)message
        metadata:(NSDictionary<NSString *, NSString *> *)metadata {
    if (!self.logBlock) {
        return;
    }
    self.logBlock(level, phase, message, metadata);
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
