#import "SSHCoreLibSSHLocalForwardRuntime.h"
#import "SSHCoreLibSSHLocalForwardRuntime+Internal.h"

#import <SSHKitObjC/SSHKitError.h>

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>

#import "SSHCoreLibSSHHelpers.h"
#import "SSHCoreOpenSSHClient+Internal.h"
#import "SSHKitPortForward+Private.h"

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wincomplete-implementation"

@implementation SSHCoreLibSSHLocalForwardRuntime

- (instancetype)initWithSession:(ssh_session)session
                  listenerSocket:(int)listenerSocket
                       boundHost:(NSString *)boundHost
                       boundPort:(uint16_t)boundPort
                      targetHost:(NSString *)targetHost
                      targetPort:(uint16_t)targetPort
                    socksUsername:(NSString *)socksUsername
                    socksPassword:(NSString *)socksPassword
                     workerQueue:(dispatch_queue_t)workerQueue
                    closeHandler:(SSHCoreTunnelCloseHandler)closeHandler
                          client:(SSHCoreOpenSSHClient *)client {
    NSParameterAssert(session != NULL);
    NSParameterAssert(listenerSocket >= 0);
    NSParameterAssert(workerQueue != nil);

    self = [super init];
    if (self) {
        _session = session;
        _listenerSocket = listenerSocket;
        _activeSocket = -1;
        _boundHost = [boundHost copy];
        _boundPort = boundPort;
        _targetHost = [targetHost copy];
        _targetPort = targetPort;
        _socksUsername = [socksUsername copy];
        _socksPassword = [socksPassword copy];
        _workerQueue = workerQueue;
        _closeHandler = [closeHandler copy];
        _client = client;
        _lock = [[NSLock alloc] init];
        _closeCompletions = [[NSMutableArray alloc] init];
    }
    return self;
}

- (BOOL)readExactly:(void *)buffer length:(NSUInteger)length fromSocket:(int)socket {
    uint8_t *cursor = buffer;
    NSUInteger remaining = length;
    while (remaining > 0) {
        ssize_t bytesRead = read(socket, cursor, remaining);
        if (bytesRead < 0 && errno == EINTR) {
            continue;
        }
        if (bytesRead <= 0) {
            return NO;
        }
        cursor += bytesRead;
        remaining -= (NSUInteger)bytesRead;
    }
    return YES;
}

- (BOOL)writeBytes:(const char *)bytes length:(size_t)length toChannel:(ssh_channel)channel {
    size_t offset = 0;
    while (offset < length) {
        int chunkLength = (int)MIN(length - offset, (size_t)UINT32_MAX);
        int written = ssh_channel_write(channel, bytes + offset, (uint32_t)chunkLength);
        if (written <= 0) {
            return NO;
        }
        offset += (size_t)written;
    }
    return YES;
}

- (BOOL)writeBytes:(const char *)bytes length:(size_t)length toSocket:(int)socket {
    size_t offset = 0;
    while (offset < length) {
        ssize_t written = write(socket, bytes + offset, length - offset);
        if (written < 0 && errno == EINTR) {
            continue;
        }
        if (written <= 0) {
            return NO;
        }
        offset += (size_t)written;
    }
    return YES;
}

- (NSString *)peerHostForSocket:(int)socket port:(int *)port {
    struct sockaddr_storage address;
    socklen_t addressLength = sizeof(address);
    if (getpeername(socket, (struct sockaddr *)&address, &addressLength) != 0) {
        *port = 0;
        return self.boundHost;
    }
    char hostBuffer[NI_MAXHOST];
    if (address.ss_family == AF_INET) {
        *port = ntohs(((struct sockaddr_in *)&address)->sin_port);
    } else if (address.ss_family == AF_INET6) {
        *port = ntohs(((struct sockaddr_in6 *)&address)->sin6_port);
    } else {
        *port = 0;
        return self.boundHost;
    }
    int result = getnameinfo((struct sockaddr *)&address, addressLength, hostBuffer, sizeof(hostBuffer), NULL, 0, NI_NUMERICHOST);
    if (result != 0) {
        return self.boundHost;
    }
    return [NSString stringWithUTF8String:hostBuffer];
}

- (void)setActiveSocket:(int)activeSocket {
    [self.lock lock];
    _activeSocket = activeSocket;
    [self.lock unlock];
}

- (BOOL)isClosed {
    [self.lock lock];
    BOOL closed = self.closed;
    [self.lock unlock];
    return closed;
}

- (void)closeWithCompletion:(SSHKitCompletion)completion {
    [self.lock lock];
    if (self.didCallCloseHandler) {
        [self.lock unlock];
        completion(nil);
        return;
    }
    self.closed = YES;
    int activeSocket = self.activeSocket;
    [self.closeCompletions addObject:[completion copy]];
    [self.lock unlock];

    [self.client emitLogLevel:SSHKitLogLevelInfo
                        phase:@"tunnel"
                      message:@"SSH local forward close requested."
                     metadata:[self diagnosticMetadataWithAdditional:@{@"activeSocket": [NSString stringWithFormat:@"%d", activeSocket]}]];
    SSHCoreShutdownDescriptor(activeSocket);
    [self.client emitLogLevel:SSHKitLogLevelDebug
                        phase:@"tunnel"
                      message:@"SSH local forward active socket shutdown requested."
                     metadata:[self diagnosticMetadataWithAdditional:@{@"activeSocket": [NSString stringWithFormat:@"%d", activeSocket]}]];
}

- (void)invalidateOnWorkerQueue {
    [self.lock lock];
    self.closed = YES;
    int listenerSocket = self.listenerSocket;
    _listenerSocket = -1;
    int activeSocket = self.activeSocket;
    _activeSocket = -1;
    [self.lock unlock];

    [self.client emitLogLevel:SSHKitLogLevelDebug
                        phase:@"tunnel"
                      message:@"SSH local forward invalidate started."
                     metadata:[self diagnosticMetadataWithAdditional:@{@"listenerSocket": [NSString stringWithFormat:@"%d", listenerSocket],
                                                                       @"activeSocket": [NSString stringWithFormat:@"%d", activeSocket]}]];
    SSHCoreCloseDescriptor(&listenerSocket);
    SSHCoreCloseDescriptor(&activeSocket);
    [self.client emitLogLevel:SSHKitLogLevelDebug
                        phase:@"tunnel"
                      message:@"SSH local forward invalidate finished."
                     metadata:[self diagnosticMetadata]];
}

- (void)callCloseHandlerIfNeeded {
    [self.lock lock];
    if (self.didCallCloseHandler) {
        [self.lock unlock];
        return;
    }
    self.didCallCloseHandler = YES;
    [self.lock unlock];
    self.closeHandler();
}

- (void)completePendingCloseCompletions {
    [self.lock lock];
    NSArray<SSHKitCompletion> *completions = [self.closeCompletions copy];
    [self.closeCompletions removeAllObjects];
    [self.lock unlock];

    [self.client emitLogLevel:SSHKitLogLevelDebug
                        phase:@"tunnel"
                      message:@"SSH local forward close completions started."
                     metadata:[self diagnosticMetadataWithAdditional:@{@"completionCount": [NSString stringWithFormat:@"%lu", (unsigned long)completions.count]}]];
    for (SSHKitCompletion completion in completions) {
        completion(nil);
    }
}

- (NSDictionary<NSString *, NSString *> *)diagnosticMetadata {
    return [self diagnosticMetadataWithAdditional:@{}];
}

- (NSDictionary<NSString *, NSString *> *)diagnosticMetadataWithAdditional:(NSDictionary<NSString *, NSString *> *)additional {
    NSMutableDictionary<NSString *, NSString *> *metadata = [@{
        @"forwardType": self.targetHost == nil ? @"dynamic" : @"local",
        @"boundHost": self.boundHost,
        @"boundPort": [NSString stringWithFormat:@"%hu", self.boundPort],
        @"configuredTargetHost": self.targetHost ?: @"",
        @"configuredTargetPort": [NSString stringWithFormat:@"%hu", self.targetPort],
    } mutableCopy];
    [metadata addEntriesFromDictionary:additional];
    return metadata;
}

- (void)dealloc {
    [self invalidateOnWorkerQueue];
}

@end

#pragma clang diagnostic pop
