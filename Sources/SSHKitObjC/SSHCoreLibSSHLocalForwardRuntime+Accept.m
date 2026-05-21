#import "SSHCoreLibSSHLocalForwardRuntime+Accept.h"

#import "SSHCoreLibSSHLocalForwardRuntime+Internal.h"
#import "SSHCoreLibSSHHelpers.h"
#import "SSHCoreOpenSSHClient+Internal.h"
#import "SSHKitPortForward+Private.h"

#import <SSHKitObjC/SSHKitError.h>

#include <errno.h>
#include <fcntl.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wobjc-protocol-method-implementation"

@implementation SSHCoreLibSSHLocalForwardRuntime (Accept)

- (void)start {
    [self acceptLoopOnWorkerQueue];
}

- (void)acceptLoopOnWorkerQueue {
    [self.client emitLogLevel:SSHKitLogLevelDebug
                        phase:@"tunnel"
                      message:@"SSH local forward worker loop started."
                     metadata:[self diagnosticMetadata]];
    while (![self isClosed]) {
        fd_set readSet;
        FD_ZERO(&readSet);
        FD_SET(self.listenerSocket, &readSet);
        struct timeval timeout;
        timeout.tv_sec = 0;
        timeout.tv_usec = 10000;
        int selectResult = select(self.listenerSocket + 1, &readSet, NULL, NULL, &timeout);
        if (selectResult == 0 || (selectResult < 0 && errno == EINTR)) {
            continue;
        }
        if (selectResult < 0) {
            [self.client emitLogLevel:SSHKitLogLevelWarning
                                phase:@"tunnel"
                              message:@"SSH local forward listener failed."
                             metadata:@{@"error": [NSString stringWithUTF8String:strerror(errno)]}];
            break;
        }

        struct sockaddr_storage clientAddress;
        socklen_t clientAddressLength = sizeof(clientAddress);
        int clientSocket = accept(self.listenerSocket, (struct sockaddr *)&clientAddress, &clientAddressLength);
        if (clientSocket < 0) {
            if ([self isClosed] || errno == EBADF || errno == EINVAL) {
                break;
            }
            if (errno == EINTR) {
                continue;
            }
            if (errno == ECONNABORTED || errno == EMFILE || errno == ENFILE) {
                [self.client emitLogLevel:SSHKitLogLevelWarning
                                    phase:@"tunnel"
                                  message:@"SSH local forward accept failed."
                                 metadata:@{@"error": [NSString stringWithUTF8String:strerror(errno)]}];
                continue;
            }
            [self.client emitLogLevel:SSHKitLogLevelWarning
                                phase:@"tunnel"
                              message:@"SSH local forward stopped after accept failure."
                             metadata:@{@"error": [NSString stringWithUTF8String:strerror(errno)]}];
            break;
        }

        [self setActiveSocket:clientSocket];
        [self.client emitLogLevel:SSHKitLogLevelDebug
                            phase:@"tunnel"
                          message:@"SSH local forward accepted client socket."
                         metadata:[self diagnosticMetadataWithAdditional:@{@"clientSocket": [NSString stringWithFormat:@"%d", clientSocket]}]];
        NSString *targetHost = self.targetHost;
        uint16_t targetPort = self.targetPort;
        BOOL isDynamicRequest = targetHost == nil;
        if (targetHost == nil) {
            if (![self readSOCKSTargetHost:&targetHost port:&targetPort fromClientSocket:clientSocket]) {
                SSHCoreCloseDescriptor(&clientSocket);
                [self setActiveSocket:-1];
                continue;
            }
        }
        ssh_channel channel = [self openForwardChannelForClientSocket:clientSocket targetHost:targetHost targetPort:targetPort];
        if (channel != NULL) {
            if (isDynamicRequest) {
                [self sendSOCKSReply:0x00 toSocket:clientSocket];
            }
            [self.client emitLogLevel:SSHKitLogLevelDebug
                                phase:@"tunnel"
                              message:@"SSH local forward bridge started."
                             metadata:[self diagnosticMetadataWithAdditional:@{@"targetHost": targetHost,
                                                                               @"targetPort": [NSString stringWithFormat:@"%hu", targetPort]}]];
            [self bridgeClientSocket:clientSocket channel:channel];
            [self.client emitLogLevel:SSHKitLogLevelDebug
                                phase:@"tunnel"
                              message:@"SSH local forward bridge finished."
                             metadata:[self diagnosticMetadataWithAdditional:@{@"targetHost": targetHost,
                                                                               @"targetPort": [NSString stringWithFormat:@"%hu", targetPort]}]];
            [self.client emitLogLevel:SSHKitLogLevelDebug
                                phase:@"tunnel"
                              message:@"SSH local forward channel free started."
                             metadata:[self diagnosticMetadata]];
            SSHCoreFreeForwardChannel(channel);
            [self.client emitLogLevel:SSHKitLogLevelDebug
                                phase:@"tunnel"
                              message:@"SSH local forward channel free finished."
                             metadata:[self diagnosticMetadata]];
        } else if (isDynamicRequest) {
            [self sendSOCKSReply:0x05 toSocket:clientSocket];
        }
        SSHCoreCloseDescriptor(&clientSocket);
        [self setActiveSocket:-1];
    }

    [self.client emitLogLevel:SSHKitLogLevelDebug
                        phase:@"tunnel"
                      message:@"SSH local forward worker loop exiting."
                     metadata:[self diagnosticMetadata]];
    [self invalidateOnWorkerQueue];
    [self callCloseHandlerIfNeeded];
    [self completePendingCloseCompletions];
}

- (nullable ssh_channel)openForwardChannelForClientSocket:(int)clientSocket targetHost:(NSString *)targetHost targetPort:(uint16_t)targetPort {
    ssh_channel channel = ssh_channel_new(self.session);
    if (channel == NULL) {
        [self.client emitLogLevel:SSHKitLogLevelWarning phase:@"tunnel" message:@"SSH local forward could not allocate channel." metadata:@{}];
        return NULL;
    }

    int sourcePort = 0;
    NSString *sourceHost = [self peerHostForSocket:clientSocket port:&sourcePort];
    if (ssh_channel_open_forward(channel, targetHost.UTF8String, targetPort, sourceHost.UTF8String, sourcePort) != SSH_OK) {
        [self.client emitLogLevel:SSHKitLogLevelWarning
                            phase:@"tunnel"
                          message:@"SSH local forward channel open failed."
                         metadata:@{@"targetHost": targetHost,
                                    @"targetPort": [NSString stringWithFormat:@"%hu", targetPort],
                                    @"sourceHost": sourceHost,
                                    @"sourcePort": [NSString stringWithFormat:@"%d", sourcePort]}];
        ssh_channel_free(channel);
        return NULL;
    }
    return channel;
}

- (void)bridgeClientSocket:(int)clientSocket channel:(ssh_channel)channel {
    char buffer[32768];
    while (![self isClosed] && ssh_channel_is_open(channel)) {
        fd_set readSet;
        FD_ZERO(&readSet);
        FD_SET(clientSocket, &readSet);
        struct timeval timeout;
        timeout.tv_sec = 0;
        timeout.tv_usec = 10000;

        int selectResult = select(clientSocket + 1, &readSet, NULL, NULL, &timeout);
        if (selectResult > 0 && FD_ISSET(clientSocket, &readSet)) {
            ssize_t bytesRead = read(clientSocket, buffer, sizeof(buffer));
            if (bytesRead <= 0) {
                break;
            }
            if (![self writeBytes:buffer length:(size_t)bytesRead toChannel:channel]) {
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
            if (![self writeBytes:buffer length:(size_t)bytesRead toSocket:clientSocket]) {
                return;
            }
        }

        if (ssh_channel_is_eof(channel)) {
            break;
        }
    }
}

@end

#pragma clang diagnostic pop
