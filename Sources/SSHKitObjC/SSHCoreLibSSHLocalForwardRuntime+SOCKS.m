#import "SSHCoreLibSSHLocalForwardRuntime+SOCKS.h"

#import "SSHCoreLibSSHLocalForwardRuntime+Internal.h"
#import "SSHCoreOpenSSHClient+Internal.h"

#import <SSHKitObjC/SSHKitError.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wobjc-protocol-method-implementation"

@implementation SSHCoreLibSSHLocalForwardRuntime (SOCKS)

- (BOOL)readSOCKSTargetHost:(NSString **)targetHost port:(uint16_t *)targetPort fromClientSocket:(int)clientSocket {
    uint8_t header[2];
    if (![self readExactly:header length:sizeof(header) fromSocket:clientSocket] || header[0] != 0x05 || header[1] == 0) {
        return NO;
    }

    NSMutableData *methods = [NSMutableData dataWithLength:header[1]];
    if (![self readExactly:methods.mutableBytes length:methods.length fromSocket:clientSocket]) {
        return NO;
    }

    uint8_t selectedMethod = 0xFF;
    const uint8_t *methodBytes = methods.bytes;
    BOOL wantsPassword = self.socksUsername != nil || self.socksPassword != nil;
    for (NSUInteger index = 0; index < methods.length; index++) {
        if (!wantsPassword && methodBytes[index] == 0x00) {
            selectedMethod = 0x00;
            break;
        }
        if (wantsPassword && methodBytes[index] == 0x02) {
            selectedMethod = 0x02;
            break;
        }
    }

    uint8_t selection[2] = {0x05, selectedMethod};
    if (![self writeBytes:(const char *)selection length:sizeof(selection) toSocket:clientSocket] || selectedMethod == 0xFF) {
        return NO;
    }
    if (selectedMethod == 0x02 && ![self authenticateSOCKSUserPasswordOnSocket:clientSocket]) {
        return NO;
    }

    uint8_t requestHeader[4];
    if (![self readExactly:requestHeader length:sizeof(requestHeader) fromSocket:clientSocket] ||
        requestHeader[0] != 0x05 ||
        requestHeader[1] != 0x01 ||
        requestHeader[2] != 0x00) {
        [self sendSOCKSReply:0x07 toSocket:clientSocket];
        return NO;
    }

    NSString *host = nil;
    switch (requestHeader[3]) {
        case 0x01: {
            uint8_t address[4];
            if (![self readExactly:address length:sizeof(address) fromSocket:clientSocket]) {
                return NO;
            }
            char buffer[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, address, buffer, sizeof(buffer));
            host = [NSString stringWithUTF8String:buffer];
            break;
        }
        case 0x03: {
            uint8_t length = 0;
            if (![self readExactly:&length length:1 fromSocket:clientSocket] || length == 0) {
                return NO;
            }
            NSMutableData *domain = [NSMutableData dataWithLength:length];
            if (![self readExactly:domain.mutableBytes length:domain.length fromSocket:clientSocket]) {
                return NO;
            }
            host = [[NSString alloc] initWithData:domain encoding:NSUTF8StringEncoding];
            break;
        }
        case 0x04: {
            uint8_t address[16];
            if (![self readExactly:address length:sizeof(address) fromSocket:clientSocket]) {
                return NO;
            }
            char buffer[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, address, buffer, sizeof(buffer));
            host = [NSString stringWithUTF8String:buffer];
            break;
        }
        default:
            [self sendSOCKSReply:0x08 toSocket:clientSocket];
            return NO;
    }

    uint8_t portBytes[2];
    if (host.length == 0) {
        [self sendSOCKSReply:0x01 toSocket:clientSocket];
        return NO;
    }
    if (![self readExactly:portBytes length:sizeof(portBytes) fromSocket:clientSocket]) {
        return NO;
    }

    *targetHost = host;
    *targetPort = (uint16_t)((portBytes[0] << 8) | portBytes[1]);
    return YES;
}

- (BOOL)authenticateSOCKSUserPasswordOnSocket:(int)clientSocket {
    uint8_t header[2];
    if (![self readExactly:header length:sizeof(header) fromSocket:clientSocket] || header[0] != 0x01) {
        return NO;
    }
    NSMutableData *username = [NSMutableData dataWithLength:header[1]];
    if (![self readExactly:username.mutableBytes length:username.length fromSocket:clientSocket]) {
        return NO;
    }
    uint8_t passwordLength = 0;
    if (![self readExactly:&passwordLength length:1 fromSocket:clientSocket]) {
        return NO;
    }
    NSMutableData *password = [NSMutableData dataWithLength:passwordLength];
    if (![self readExactly:password.mutableBytes length:password.length fromSocket:clientSocket]) {
        return NO;
    }

    NSString *requestUsername = [[NSString alloc] initWithData:username encoding:NSUTF8StringEncoding] ?: @"";
    NSString *requestPassword = [[NSString alloc] initWithData:password encoding:NSUTF8StringEncoding] ?: @"";
    BOOL accepted = [requestUsername isEqualToString:self.socksUsername ?: @""] &&
        [requestPassword isEqualToString:self.socksPassword ?: @""];
    uint8_t response[2] = {0x01, accepted ? 0x00 : 0x01};
    [self writeBytes:(const char *)response length:sizeof(response) toSocket:clientSocket];
    return accepted;
}

- (void)sendSOCKSReply:(uint8_t)reply toSocket:(int)clientSocket {
    uint8_t response[10] = {0x05, reply, 0x00, 0x01, 0, 0, 0, 0, 0, 0};
    [self writeBytes:(const char *)response length:sizeof(response) toSocket:clientSocket];
}

@end

#pragma clang diagnostic pop
