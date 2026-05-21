#import "SSHCoreOpenSSHClient+Sockets.h"

#import "SSHCoreOpenSSHClient+Internal.h"

#import <SSHKitObjC/SSHKitConfiguration.h>
#import <SSHKitObjC/SSHKitError.h>

#import "SSHCoreSessionWorker.h"
#import "SSHCoreSocketHandle.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wobjc-protocol-method-implementation"

@implementation SSHCoreOpenSSHClient (Sockets)

- (int)openSocketWithError:(NSError **)error {
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    NSString *socketHost = self.configuration.host;
    uint16_t socketPort = self.configuration.port;
    if (self.configuration.proxyRouteKind == SSHKitProxyRouteKindSOCKS5 ||
        self.configuration.proxyRouteKind == SSHKitProxyRouteKindHTTPConnect) {
        if (self.configuration.proxyHost.length == 0 || self.configuration.proxyPort == 0) {
            if (error) {
                *error = SSHKitMakeError(SSHKitErrorCodeConnectionFailed, @"Proxy route requires a proxy host and port.");
            }
            return -1;
        }
        socketHost = self.configuration.proxyHost;
        socketPort = self.configuration.proxyPort;
    }

    NSString *port = [NSString stringWithFormat:@"%hu", socketPort];
    struct addrinfo *addresses = NULL;
    int result = getaddrinfo(socketHost.UTF8String, port.UTF8String, &hints, &addresses);
    if (result != 0) {
        if (error) {
            *error = SSHKitMakeError(SSHKitErrorCodeConnectionFailed, [NSString stringWithFormat:@"Unable to resolve SSH route host: %s", gai_strerror(result)]);
        }
        return -1;
    }

    NSError *lastError = nil;
    for (struct addrinfo *address = addresses; address != NULL; address = address->ai_next) {
        int fileDescriptor = socket(address->ai_family, address->ai_socktype, address->ai_protocol);
        if (fileDescriptor < 0) {
            lastError = SSHKitMakeError(SSHKitErrorCodeConnectionFailed, [NSString stringWithFormat:@"Unable to create SSH socket: %s", strerror(errno)]);
            continue;
        }

        self.worker.socketHandle = [[SSHCoreSocketHandle alloc] initWithFileDescriptor:fileDescriptor];
        if ([self connectSocket:fileDescriptor address:address error:&lastError] &&
            [self completeProxyRouteOnSocket:fileDescriptor error:&lastError]) {
            freeaddrinfo(addresses);
            return fileDescriptor;
        }

        [self closeWorkerSocketHandle];
    }

    freeaddrinfo(addresses);
    if (error) {
        *error = lastError ?: SSHKitMakeError(SSHKitErrorCodeConnectionFailed, @"Unable to connect SSH socket.");
    }
    return -1;
}

- (BOOL)completeProxyRouteOnSocket:(int)fileDescriptor error:(NSError **)error {
    switch (self.configuration.proxyRouteKind) {
        case SSHKitProxyRouteKindNone:
        case SSHKitProxyRouteKindProxyJump:
            return YES;
        case SSHKitProxyRouteKindSOCKS5:
            return [self completeSOCKS5ProxyRouteOnSocket:fileDescriptor error:error];
        case SSHKitProxyRouteKindHTTPConnect:
            return [self completeHTTPConnectProxyRouteOnSocket:fileDescriptor error:error];
    }
}

- (BOOL)connectSocket:(int)fileDescriptor address:(struct addrinfo *)address error:(NSError **)error {
    int originalFlags = fcntl(fileDescriptor, F_GETFL, 0);
    if (originalFlags < 0 || fcntl(fileDescriptor, F_SETFL, originalFlags | O_NONBLOCK) != 0) {
        if (error) {
            *error = SSHKitMakeError(SSHKitErrorCodeConnectionFailed, [NSString stringWithFormat:@"Unable to configure SSH socket: %s", strerror(errno)]);
        }
        return NO;
    }

    int connectResult = connect(fileDescriptor, address->ai_addr, address->ai_addrlen);
    if (connectResult == 0) {
        fcntl(fileDescriptor, F_SETFL, originalFlags);
        return YES;
    }

    if (errno != EINPROGRESS) {
        if (error) {
            *error = SSHKitMakeError(SSHKitErrorCodeConnectionFailed, [NSString stringWithFormat:@"SSH socket connect failed: %s", strerror(errno)]);
        }
        return NO;
    }

    fd_set writeSet;
    FD_ZERO(&writeSet);
    FD_SET(fileDescriptor, &writeSet);

    NSTimeInterval timeoutInterval = self.configuration.timeout;
    struct timeval timeout;
    timeout.tv_sec = (long)timeoutInterval;
    timeout.tv_usec = (int)((timeoutInterval - floor(timeoutInterval)) * 1000000);

    int selectResult = select(fileDescriptor + 1, NULL, &writeSet, NULL, &timeout);
    if (selectResult <= 0) {
        if (error) {
            *error = [self isTaskCancelled]
                ? SSHKitMakeError(SSHKitErrorCodeCancelled, @"SSH socket connect was cancelled.")
                : SSHKitMakeError(SSHKitErrorCodeConnectionFailed, @"SSH socket connect timed out.");
        }
        return NO;
    }

    int socketError = 0;
    socklen_t socketErrorLength = sizeof(socketError);
    if (getsockopt(fileDescriptor, SOL_SOCKET, SO_ERROR, &socketError, &socketErrorLength) != 0 || socketError != 0) {
        if (error) {
            int reportedError = socketError != 0 ? socketError : errno;
            *error = SSHKitMakeError(SSHKitErrorCodeConnectionFailed, [NSString stringWithFormat:@"SSH socket connect failed: %s", strerror(reportedError)]);
        }
        return NO;
    }

    fcntl(fileDescriptor, F_SETFL, originalFlags);
    return YES;
}

- (BOOL)completeSOCKS5ProxyRouteOnSocket:(int)fileDescriptor error:(NSError **)error {
    BOOL wantsPassword = self.configuration.proxyUsername.length > 0 || self.configuration.proxyPassword.length > 0;
    uint8_t greeting[4] = {0x05, wantsPassword ? 0x02 : 0x01, 0x00, 0x02};
    if (![self writeBytes:(const char *)greeting length:(wantsPassword ? 4 : 3) toProxySocket:fileDescriptor error:error]) {
        return NO;
    }

    uint8_t selection[2];
    if (![self readBytes:selection length:sizeof(selection) fromProxySocket:fileDescriptor error:error] || selection[0] != 0x05) {
        if (error) {
            *error = SSHKitMakeError(SSHKitErrorCodeConnectionFailed, @"SOCKS5 proxy route failed during method negotiation.");
        }
        return NO;
    }
    if (wantsPassword && selection[1] == 0x02) {
        if (![self authenticateSOCKS5ProxyRouteOnSocket:fileDescriptor error:error]) {
            return NO;
        }
    } else if ((!wantsPassword && selection[1] != 0x00) || (wantsPassword && selection[1] != 0x02)) {
        if (error) {
            *error = SSHKitMakeError(SSHKitErrorCodeConnectionFailed, [NSString stringWithFormat:@"SOCKS5 proxy route rejected authentication method at %@:%hu.", self.configuration.proxyHost, self.configuration.proxyPort]);
        }
        return NO;
    }

    NSData *hostData = [self.configuration.host dataUsingEncoding:NSUTF8StringEncoding];
    if (hostData.length == 0 || hostData.length > UINT8_MAX) {
        if (error) {
            *error = SSHKitMakeError(SSHKitErrorCodeConnectionFailed, @"SOCKS5 proxy route target host must be 1...255 UTF-8 bytes.");
        }
        return NO;
    }

    NSMutableData *request = [[NSMutableData alloc] initWithCapacity:7 + hostData.length];
    uint8_t prefix[5] = {0x05, 0x01, 0x00, 0x03, (uint8_t)hostData.length};
    [request appendBytes:prefix length:sizeof(prefix)];
    [request appendData:hostData];
    uint8_t port[2] = {(uint8_t)(self.configuration.port >> 8), (uint8_t)(self.configuration.port & 0x00FF)};
    [request appendBytes:port length:sizeof(port)];
    if (![self writeBytes:request.bytes length:request.length toProxySocket:fileDescriptor error:error]) {
        return NO;
    }

    uint8_t replyHeader[4];
    if (![self readBytes:replyHeader length:sizeof(replyHeader) fromProxySocket:fileDescriptor error:error] || replyHeader[0] != 0x05) {
        if (error) {
            *error = SSHKitMakeError(SSHKitErrorCodeConnectionFailed, @"SOCKS5 proxy route failed while reading CONNECT reply.");
        }
        return NO;
    }
    if (replyHeader[1] != 0x00) {
        if (error) {
            *error = SSHKitMakeError(SSHKitErrorCodeConnectionFailed, [NSString stringWithFormat:@"SOCKS5 proxy route failed at %@:%hu with reply %hhu.", self.configuration.proxyHost, self.configuration.proxyPort, replyHeader[1]]);
        }
        return NO;
    }

    NSUInteger addressLength = 0;
    if (replyHeader[3] == 0x01) {
        addressLength = 4;
    } else if (replyHeader[3] == 0x04) {
        addressLength = 16;
    } else if (replyHeader[3] == 0x03) {
        uint8_t domainLength = 0;
        if (![self readBytes:&domainLength length:1 fromProxySocket:fileDescriptor error:error]) {
            return NO;
        }
        addressLength = domainLength;
    } else {
        if (error) {
            *error = SSHKitMakeError(SSHKitErrorCodeConnectionFailed, @"SOCKS5 proxy route returned an unsupported address type.");
        }
        return NO;
    }

    NSMutableData *ignored = [NSMutableData dataWithLength:addressLength + 2];
    return [self readBytes:ignored.mutableBytes length:ignored.length fromProxySocket:fileDescriptor error:error];
}

- (BOOL)authenticateSOCKS5ProxyRouteOnSocket:(int)fileDescriptor error:(NSError **)error {
    NSData *username = [(self.configuration.proxyUsername ?: @"") dataUsingEncoding:NSUTF8StringEncoding];
    NSData *password = [(self.configuration.proxyPassword ?: @"") dataUsingEncoding:NSUTF8StringEncoding];
    if (username.length > UINT8_MAX || password.length > UINT8_MAX) {
        if (error) {
            *error = SSHKitMakeError(SSHKitErrorCodeConnectionFailed, @"SOCKS5 proxy route credentials must be at most 255 UTF-8 bytes.");
        }
        return NO;
    }

    NSMutableData *request = [[NSMutableData alloc] initWithCapacity:3 + username.length + password.length];
    uint8_t version = 0x01;
    uint8_t usernameLength = (uint8_t)username.length;
    uint8_t passwordLength = (uint8_t)password.length;
    [request appendBytes:&version length:1];
    [request appendBytes:&usernameLength length:1];
    [request appendData:username];
    [request appendBytes:&passwordLength length:1];
    [request appendData:password];
    if (![self writeBytes:request.bytes length:request.length toProxySocket:fileDescriptor error:error]) {
        return NO;
    }

    uint8_t response[2];
    if (![self readBytes:response length:sizeof(response) fromProxySocket:fileDescriptor error:error] || response[0] != 0x01 || response[1] != 0x00) {
        if (error) {
            *error = SSHKitMakeError(SSHKitErrorCodeAuthenticationFailed, [NSString stringWithFormat:@"SOCKS5 proxy route authentication failed at %@:%hu.", self.configuration.proxyHost, self.configuration.proxyPort]);
        }
        return NO;
    }
    return YES;
}

- (BOOL)completeHTTPConnectProxyRouteOnSocket:(int)fileDescriptor error:(NSError **)error {
    NSString *authority = [NSString stringWithFormat:@"%@:%hu", self.configuration.host, self.configuration.port];
    NSMutableString *request = [NSMutableString stringWithFormat:@"CONNECT %@ HTTP/1.1\r\nHost: %@\r\nProxy-Connection: Keep-Alive\r\n", authority, authority];
    if (self.configuration.proxyUsername.length > 0 || self.configuration.proxyPassword.length > 0) {
        NSString *credentials = [NSString stringWithFormat:@"%@:%@", self.configuration.proxyUsername ?: @"", self.configuration.proxyPassword ?: @""];
        NSString *encodedCredentials = [[credentials dataUsingEncoding:NSUTF8StringEncoding] base64EncodedStringWithOptions:0];
        [request appendFormat:@"Proxy-Authorization: Basic %@\r\n", encodedCredentials];
    }
    [request appendString:@"\r\n"];

    NSData *requestData = [request dataUsingEncoding:NSUTF8StringEncoding];
    if (![self writeBytes:requestData.bytes length:requestData.length toProxySocket:fileDescriptor error:error]) {
        return NO;
    }

    NSMutableData *response = [[NSMutableData alloc] init];
    uint8_t byte = 0;
    while (response.length < 16 * 1024) {
        if (![self readBytes:&byte length:1 fromProxySocket:fileDescriptor error:error]) {
            return NO;
        }
        [response appendBytes:&byte length:1];
        if (response.length >= 4) {
            const uint8_t *bytes = response.bytes;
            NSUInteger length = response.length;
            if (bytes[length - 4] == '\r' && bytes[length - 3] == '\n' && bytes[length - 2] == '\r' && bytes[length - 1] == '\n') {
                NSString *header = [[NSString alloc] initWithData:response encoding:NSUTF8StringEncoding] ?: @"";
                NSArray<NSString *> *lines = [header componentsSeparatedByString:@"\r\n"];
                NSString *statusLine = lines.firstObject ?: @"";
                if ([statusLine containsString:@" 200 "]) {
                    return YES;
                }
                if (error) {
                    *error = SSHKitMakeError(SSHKitErrorCodeConnectionFailed, [NSString stringWithFormat:@"HTTP CONNECT proxy route failed at %@:%hu with status '%@'.", self.configuration.proxyHost, self.configuration.proxyPort, statusLine]);
                }
                return NO;
            }
        }
    }

    if (error) {
        *error = SSHKitMakeError(SSHKitErrorCodeConnectionFailed, @"HTTP CONNECT proxy route response header exceeded 16 KiB.");
    }
    return NO;
}

- (BOOL)readBytes:(void *)buffer length:(NSUInteger)length fromProxySocket:(int)socket error:(NSError **)error {
    uint8_t *cursor = buffer;
    NSUInteger remaining = length;
    while (remaining > 0) {
        if ([self isTaskCancelled]) {
            if (error) {
                *error = SSHKitMakeError(SSHKitErrorCodeCancelled, @"Proxy route socket read was cancelled.");
            }
            return NO;
        }

        ssize_t bytesRead = read(socket, cursor, remaining);
        if (bytesRead < 0 && errno == EINTR) {
            continue;
        }
        if (bytesRead <= 0) {
            if (error) {
                *error = [self isTaskCancelled]
                    ? SSHKitMakeError(SSHKitErrorCodeCancelled, @"Proxy route socket read was cancelled.")
                    : SSHKitMakeError(SSHKitErrorCodeConnectionFailed, [NSString stringWithFormat:@"Proxy route socket read failed: %s", strerror(errno)]);
            }
            return NO;
        }
        cursor += bytesRead;
        remaining -= (NSUInteger)bytesRead;
    }
    return YES;
}

- (BOOL)writeBytes:(const char *)bytes length:(size_t)length toProxySocket:(int)socket error:(NSError **)error {
    size_t offset = 0;
    while (offset < length) {
        if ([self isTaskCancelled]) {
            if (error) {
                *error = SSHKitMakeError(SSHKitErrorCodeCancelled, @"Proxy route socket write was cancelled.");
            }
            return NO;
        }

        ssize_t written = write(socket, bytes + offset, length - offset);
        if (written < 0 && errno == EINTR) {
            continue;
        }
        if (written <= 0) {
            if (error) {
                *error = [self isTaskCancelled]
                    ? SSHKitMakeError(SSHKitErrorCodeCancelled, @"Proxy route socket write was cancelled.")
                    : SSHKitMakeError(SSHKitErrorCodeConnectionFailed, [NSString stringWithFormat:@"Proxy route socket write failed: %s", strerror(errno)]);
            }
            return NO;
        }
        offset += (size_t)written;
    }
    return YES;
}

@end

#pragma clang diagnostic pop
