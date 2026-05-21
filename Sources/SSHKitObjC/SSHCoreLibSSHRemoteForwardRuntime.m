#import "SSHCoreLibSSHRemoteForwardRuntime.h"

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
#pragma clang diagnostic ignored "-Wdeprecated-declarations"

@interface SSHCoreLibSSHRemoteForwardRuntime ()

@property (nonatomic) ssh_session session;
@property (nonatomic, copy) NSString *remoteHost;
@property (nonatomic) uint16_t remotePort;
@property (nonatomic) uint16_t boundPort;
@property (nonatomic, copy) NSString *targetHost;
@property (nonatomic) uint16_t targetPort;
@property (nonatomic) dispatch_queue_t workerQueue;
@property (nonatomic, copy) SSHCoreTunnelCloseHandler closeHandler;
@property (nonatomic, weak) SSHCoreOpenSSHClient *client;
@property (nonatomic) NSLock *lock;
@property (nonatomic) int activeSocket;
@property (nonatomic) BOOL closed;
@property (nonatomic) BOOL didCancelRemoteForward;
@property (nonatomic) BOOL didCallCloseHandler;
@property (nonatomic) NSMutableArray<SSHKitCompletion> *closeCompletions;

@end

@implementation SSHCoreLibSSHRemoteForwardRuntime

- (instancetype)initWithSession:(ssh_session)session
                     remoteHost:(NSString *)remoteHost
                     remotePort:(uint16_t)remotePort
                      boundPort:(uint16_t)boundPort
                     targetHost:(NSString *)targetHost
                     targetPort:(uint16_t)targetPort
                    workerQueue:(dispatch_queue_t)workerQueue
                   closeHandler:(SSHCoreTunnelCloseHandler)closeHandler
                         client:(SSHCoreOpenSSHClient *)client {
    self = [super init];
    if (self) {
        _session = session;
        _remoteHost = [remoteHost copy];
        _remotePort = remotePort;
        _boundPort = boundPort;
        _targetHost = [targetHost copy];
        _targetPort = targetPort;
        _workerQueue = workerQueue;
        _closeHandler = [closeHandler copy];
        _client = client;
        _lock = [[NSLock alloc] init];
        _activeSocket = -1;
        _closeCompletions = [[NSMutableArray alloc] init];
    }
    return self;
}

- (void)start {
    [self.client emitLogLevel:SSHKitLogLevelDebug
                        phase:@"tunnel"
                      message:@"SSH remote forward worker loop started."
                     metadata:[self diagnosticMetadata]];
    while (![self isClosed]) {
        int destinationPort = 0;
        ssh_channel channel = ssh_channel_accept_forward(self.session, 100, &destinationPort);
        if (channel == NULL) {
            continue;
        }

        [self.client emitLogLevel:SSHKitLogLevelDebug
                            phase:@"tunnel"
                          message:@"SSH remote forward accepted channel."
                         metadata:[self diagnosticMetadataWithAdditional:@{@"destinationPort": [NSString stringWithFormat:@"%d", destinationPort]}]];
        int localSocket = [self openTargetSocket];
        if (localSocket >= 0) {
            [self setActiveSocket:localSocket];
            [self.client emitLogLevel:SSHKitLogLevelDebug
                                phase:@"tunnel"
                              message:@"SSH remote forward bridge started."
                             metadata:[self diagnosticMetadataWithAdditional:@{@"localSocket": [NSString stringWithFormat:@"%d", localSocket]}]];
            [self bridgeLocalSocket:localSocket channel:channel];
            [self.client emitLogLevel:SSHKitLogLevelDebug
                                phase:@"tunnel"
                              message:@"SSH remote forward bridge finished."
                             metadata:[self diagnosticMetadataWithAdditional:@{@"localSocket": [NSString stringWithFormat:@"%d", localSocket]}]];
            SSHCoreCloseDescriptor(&localSocket);
            [self setActiveSocket:-1];
        } else {
            [self.client emitLogLevel:SSHKitLogLevelWarning
                                phase:@"tunnel"
                              message:@"SSH remote forward local target connect failed."
                             metadata:@{@"targetHost": self.targetHost,
                                        @"targetPort": [NSString stringWithFormat:@"%hu", self.targetPort]}];
        }
        [self.client emitLogLevel:SSHKitLogLevelDebug
                            phase:@"tunnel"
                          message:@"SSH remote forward channel free started."
                         metadata:[self diagnosticMetadata]];
        SSHCoreFreeForwardChannel(channel);
        [self.client emitLogLevel:SSHKitLogLevelDebug
                            phase:@"tunnel"
                          message:@"SSH remote forward channel free finished."
                         metadata:[self diagnosticMetadata]];
    }

    [self.client emitLogLevel:SSHKitLogLevelDebug
                        phase:@"tunnel"
                      message:@"SSH remote forward worker loop exiting."
                     metadata:[self diagnosticMetadata]];
    [self invalidateOnWorkerQueue];
    [self callCloseHandlerIfNeeded];
    [self completePendingCloseCompletions];
}

- (int)openTargetSocket {
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    NSString *port = [NSString stringWithFormat:@"%hu", self.targetPort];
    struct addrinfo *addresses = NULL;
    if (getaddrinfo(self.targetHost.UTF8String, port.UTF8String, &hints, &addresses) != 0) {
        return -1;
    }
    for (struct addrinfo *address = addresses; address != NULL; address = address->ai_next) {
        int fileDescriptor = socket(address->ai_family, address->ai_socktype, address->ai_protocol);
        if (fileDescriptor < 0) {
            continue;
        }
        if (connect(fileDescriptor, address->ai_addr, address->ai_addrlen) == 0) {
            freeaddrinfo(addresses);
            return fileDescriptor;
        }
        close(fileDescriptor);
    }
    freeaddrinfo(addresses);
    return -1;
}

- (void)bridgeLocalSocket:(int)localSocket channel:(ssh_channel)channel {
    char buffer[32768];
    while (![self isClosed] && ssh_channel_is_open(channel)) {
        fd_set readSet;
        FD_ZERO(&readSet);
        FD_SET(localSocket, &readSet);
        struct timeval timeout;
        timeout.tv_sec = 0;
        timeout.tv_usec = 10000;
        int selectResult = select(localSocket + 1, &readSet, NULL, NULL, &timeout);
        if (selectResult > 0 && FD_ISSET(localSocket, &readSet)) {
            ssize_t bytesRead = read(localSocket, buffer, sizeof(buffer));
            if (bytesRead <= 0 || ![self writeBytes:buffer length:(size_t)bytesRead toChannel:channel]) {
                break;
            }
        } else if (selectResult < 0 && errno != EINTR) {
            break;
        }

        while (YES) {
            int bytesRead = ssh_channel_read_nonblocking(channel, buffer, sizeof(buffer), 0);
            if (bytesRead == SSH_ERROR) {
                return;
            }
            if (bytesRead <= 0) {
                break;
            }
            if (![self writeBytes:buffer length:(size_t)bytesRead toSocket:localSocket]) {
                return;
            }
        }
        if (ssh_channel_is_eof(channel)) {
            break;
        }
    }
}

- (BOOL)writeBytes:(const char *)bytes length:(size_t)length toChannel:(ssh_channel)channel {
    size_t offset = 0;
    while (offset < length) {
        int written = ssh_channel_write(channel, bytes + offset, (uint32_t)MIN(length - offset, (size_t)UINT32_MAX));
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
                      message:@"SSH remote forward close requested."
                     metadata:[self diagnosticMetadataWithAdditional:@{@"activeSocket": [NSString stringWithFormat:@"%d", activeSocket]}]];
    SSHCoreShutdownDescriptor(activeSocket);
    [self.client emitLogLevel:SSHKitLogLevelDebug
                        phase:@"tunnel"
                      message:@"SSH remote forward active socket shutdown requested."
                     metadata:[self diagnosticMetadataWithAdditional:@{@"activeSocket": [NSString stringWithFormat:@"%d", activeSocket]}]];
}

- (void)invalidateOnWorkerQueue {
    [self.lock lock];
    self.closed = YES;
    int activeSocket = self.activeSocket;
    _activeSocket = -1;
    BOOL shouldCancelRemoteForward = !self.didCancelRemoteForward;
    self.didCancelRemoteForward = YES;
    [self.lock unlock];

    [self.client emitLogLevel:SSHKitLogLevelDebug
                        phase:@"tunnel"
                      message:@"SSH remote forward invalidate started."
                     metadata:[self diagnosticMetadataWithAdditional:@{@"activeSocket": [NSString stringWithFormat:@"%d", activeSocket],
                                                                       @"cancelRemoteForward": shouldCancelRemoteForward ? @"true" : @"false"}]];
    SSHCoreCloseDescriptor(&activeSocket);
    if (shouldCancelRemoteForward) {
        ssh_forward_cancel(self.session, self.remoteHost.UTF8String, self.boundPort);
    }
    [self.client emitLogLevel:SSHKitLogLevelDebug
                        phase:@"tunnel"
                      message:@"SSH remote forward invalidate finished."
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
                      message:@"SSH remote forward close completions started."
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
        @"forwardType": @"remote",
        @"remoteHost": self.remoteHost,
        @"remotePort": [NSString stringWithFormat:@"%hu", self.remotePort],
        @"boundPort": [NSString stringWithFormat:@"%hu", self.boundPort],
        @"targetHost": self.targetHost ?: @"",
        @"targetPort": [NSString stringWithFormat:@"%hu", self.targetPort],
    } mutableCopy];
    [metadata addEntriesFromDictionary:additional];
    return metadata;
}

@end

#pragma clang diagnostic pop
