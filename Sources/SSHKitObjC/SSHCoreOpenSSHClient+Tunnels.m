#import "SSHCoreOpenSSHClient+Tunnels.h"

#import "SSHCoreOpenSSHClient+Internal.h"

#import <SSHKitObjC/SSHKitConfiguration.h>
#import <SSHKitObjC/SSHKitError.h>

#import "SSHCoreLibSSHLocalForwardRuntime.h"
#import "SSHCoreLibSSHRemoteForwardRuntime.h"
#import "SSHCoreLibSSHTunnelRuntime.h"
#import "SSHKitPortForward+Private.h"
#import "SSHKitTunnelChannel+Private.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wobjc-protocol-method-implementation"

@implementation SSHCoreOpenSSHClient (Tunnels)

- (nullable SSHKitTunnelChannel *)openDirectTCPChannelToHost:(NSString *)host
                                                        port:(uint16_t)port
                                                closeHandler:(SSHCoreTunnelCloseHandler)closeHandler
                                                       error:(NSError **)error {
    [self emitLogLevel:SSHKitLogLevelInfo
                 phase:@"tunnel"
               message:@"SSH direct TCP channel open started."
              metadata:@{@"targetHost": host,
                         @"targetPort": [NSString stringWithFormat:@"%hu", port]}];
    if (self.session == NULL) {
        if (error) {
            *error = SSHKitMakeError(SSHKitErrorCodeInvalidState, @"SSH session is not connected.");
        }
        return nil;
    }

    ssh_channel channel = ssh_channel_new(self.session);
    if (channel == NULL) {
        if (error) {
            *error = [self libSSHErrorWithCode:SSHKitErrorCodeConnectionFailed fallback:@"Unable to allocate SSH tunnel channel."];
        }
        return nil;
    }

    if (ssh_channel_open_forward(channel, host.UTF8String, port, self.configuration.host.UTF8String, 0) != SSH_OK) {
        if (error) {
            *error = [self libSSHErrorWithCode:SSHKitErrorCodeConnectionFailed fallback:@"Unable to open SSH direct TCP channel."];
        }
        ssh_channel_free(channel);
        return nil;
    }

    __weak SSHCoreOpenSSHClient *weakSelf = self;
    SSHCoreLibSSHTunnelRuntime *runtime = [[SSHCoreLibSSHTunnelRuntime alloc] initWithChannel:channel
                                                                                  workerQueue:self.worker.queue
                                                                                  isCancelled:^BOOL{
        SSHCoreOpenSSHClient *strongSelf = weakSelf;
        return strongSelf ? [strongSelf isTaskCancelled] : NO;
    }
                                                                                 closeHandler:^{
        [weakSelf clearCurrentTask];
        closeHandler();
    }];
    [self.taskLock lock];
    self.currentTask = runtime;
    [self.taskLock unlock];

    [self emitLogLevel:SSHKitLogLevelInfo
                 phase:@"tunnel"
               message:@"SSH direct TCP channel opened."
              metadata:@{@"targetHost": host,
                         @"targetPort": [NSString stringWithFormat:@"%hu", port]}];
    return [[SSHKitTunnelChannel alloc] initWithReadBlock:^(NSUInteger maximumLength, SSHKitTunnelReadCompletion completion) {
        [runtime readDataWithMaximumLength:maximumLength completion:completion];
    } writeBlock:^(NSData *data, SSHKitCompletion completion) {
        [runtime writeData:data completion:completion];
    } closeBlock:^(SSHKitCompletion completion) {
        [runtime closeWithCompletion:completion];
    }];
}

- (nullable SSHKitPortForward *)startLocalForwardFromHost:(NSString *)localHost
                                                     port:(uint16_t)localPort
                                                   toHost:(NSString *)remoteHost
                                               targetPort:(uint16_t)remotePort
                                             closeHandler:(SSHCoreTunnelCloseHandler)closeHandler
                                                    error:(NSError **)error {
    [self emitLogLevel:SSHKitLogLevelInfo
                 phase:@"tunnel"
               message:@"SSH local forward start requested."
              metadata:@{@"localHost": localHost,
                         @"localPort": [NSString stringWithFormat:@"%hu", localPort],
                         @"targetHost": remoteHost,
                         @"targetPort": [NSString stringWithFormat:@"%hu", remotePort]}];
    if (self.session == NULL) {
        if (error) {
            *error = SSHKitMakeError(SSHKitErrorCodeInvalidState, @"SSH session is not connected.");
        }
        return nil;
    }

    uint16_t boundPort = 0;
    int listenerSocket = [self openLocalForwardListenerAtHost:localHost port:localPort boundPort:&boundPort error:error];
    if (listenerSocket < 0) {
        return nil;
    }

    __weak SSHCoreOpenSSHClient *weakSelf = self;
    SSHCoreLibSSHLocalForwardRuntime *runtime = [[SSHCoreLibSSHLocalForwardRuntime alloc] initWithSession:self.session
                                                                                           listenerSocket:listenerSocket
                                                                                                boundHost:localHost
                                                                                                boundPort:boundPort
                                                                                               targetHost:remoteHost
                                                                                               targetPort:remotePort
                                                                                            socksUsername:nil
                                                                                            socksPassword:nil
                                                                                              workerQueue:self.worker.queue
                                                                                             closeHandler:^{
        [weakSelf clearCurrentTask];
        closeHandler();
    }
                                                                                                   client:self];
    [self.taskLock lock];
    self.currentTask = runtime;
    [self.taskLock unlock];

    dispatch_async(self.worker.queue, ^{
        [runtime start];
    });

    [self emitLogLevel:SSHKitLogLevelInfo
                 phase:@"tunnel"
               message:@"SSH local forward started."
              metadata:@{@"localHost": localHost,
                         @"boundPort": [NSString stringWithFormat:@"%hu", boundPort],
                         @"targetHost": remoteHost,
                         @"targetPort": [NSString stringWithFormat:@"%hu", remotePort]}];
    return [[SSHKitPortForward alloc] initWithBoundHost:localHost boundPort:boundPort closeBlock:^(SSHKitCompletion completion) {
        [runtime closeWithCompletion:completion];
    }];
}

- (nullable SSHKitPortForward *)startDynamicForwardFromHost:(NSString *)localHost
                                                       port:(uint16_t)localPort
                                                   username:(NSString *)username
                                                   password:(NSString *)password
                                               closeHandler:(SSHCoreTunnelCloseHandler)closeHandler
                                                      error:(NSError **)error {
    [self emitLogLevel:SSHKitLogLevelInfo
                 phase:@"tunnel"
               message:@"SSH dynamic SOCKS forward start requested."
              metadata:@{@"localHost": localHost,
                         @"localPort": [NSString stringWithFormat:@"%hu", localPort]}];
    if (self.session == NULL) {
        if (error) {
            *error = SSHKitMakeError(SSHKitErrorCodeInvalidState, @"SSH session is not connected.");
        }
        return nil;
    }

    uint16_t boundPort = 0;
    int listenerSocket = [self openLocalForwardListenerAtHost:localHost port:localPort boundPort:&boundPort error:error];
    if (listenerSocket < 0) {
        return nil;
    }

    __weak SSHCoreOpenSSHClient *weakSelf = self;
    SSHCoreLibSSHLocalForwardRuntime *runtime = [[SSHCoreLibSSHLocalForwardRuntime alloc] initWithSession:self.session
                                                                                           listenerSocket:listenerSocket
                                                                                                boundHost:localHost
                                                                                                boundPort:boundPort
                                                                                               targetHost:nil
                                                                                               targetPort:0
                                                                                            socksUsername:username
                                                                                            socksPassword:password
                                                                                              workerQueue:self.worker.queue
                                                                                             closeHandler:^{
        [weakSelf clearCurrentTask];
        closeHandler();
    }
                                                                                                   client:self];
    [self.taskLock lock];
    self.currentTask = runtime;
    [self.taskLock unlock];

    dispatch_async(self.worker.queue, ^{
        [runtime start];
    });

    [self emitLogLevel:SSHKitLogLevelInfo
                 phase:@"tunnel"
               message:@"SSH dynamic SOCKS forward started."
              metadata:@{@"localHost": localHost,
                         @"boundPort": [NSString stringWithFormat:@"%hu", boundPort]}];
    return [[SSHKitPortForward alloc] initWithBoundHost:localHost boundPort:boundPort closeBlock:^(SSHKitCompletion completion) {
        [runtime closeWithCompletion:completion];
    }];
}

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"

- (nullable SSHKitPortForward *)startRemoteForwardFromHost:(NSString *)remoteHost
                                                      port:(uint16_t)remotePort
                                                    toHost:(NSString *)localHost
                                                targetPort:(uint16_t)localPort
                                              closeHandler:(SSHCoreTunnelCloseHandler)closeHandler
                                                     error:(NSError **)error {
    [self emitLogLevel:SSHKitLogLevelInfo
                 phase:@"tunnel"
               message:@"SSH remote forward start requested."
              metadata:@{@"remoteHost": remoteHost,
                         @"remotePort": [NSString stringWithFormat:@"%hu", remotePort],
                         @"targetHost": localHost,
                         @"targetPort": [NSString stringWithFormat:@"%hu", localPort]}];
    if (self.session == NULL) {
        if (error) {
            *error = SSHKitMakeError(SSHKitErrorCodeInvalidState, @"SSH session is not connected.");
        }
        return nil;
    }

    int boundPort = 0;
    if (ssh_forward_listen(self.session, remoteHost.UTF8String, remotePort, &boundPort) != SSH_OK) {
        if (error) {
            *error = SSHKitMakeError(SSHKitErrorCodeConnectionFailed, @"SSH remote forward listen failed.");
        }
        return nil;
    }

    __weak SSHCoreOpenSSHClient *weakSelf = self;
    SSHCoreLibSSHRemoteForwardRuntime *runtime = [[SSHCoreLibSSHRemoteForwardRuntime alloc] initWithSession:self.session
                                                                                                remoteHost:remoteHost
                                                                                                remotePort:remotePort
                                                                                                 boundPort:(uint16_t)boundPort
                                                                                                targetHost:localHost
                                                                                                targetPort:localPort
                                                                                               workerQueue:self.worker.queue
                                                                                              closeHandler:^{
        [weakSelf clearCurrentTask];
        closeHandler();
    }
                                                                                                    client:self];
    [self.taskLock lock];
    self.currentTask = runtime;
    [self.taskLock unlock];

    dispatch_async(self.worker.queue, ^{
        [runtime start];
    });

    [self emitLogLevel:SSHKitLogLevelInfo
                 phase:@"tunnel"
               message:@"SSH remote forward started."
              metadata:@{@"remoteHost": remoteHost,
                         @"boundPort": [NSString stringWithFormat:@"%d", boundPort]}];
    return [[SSHKitPortForward alloc] initWithBoundHost:remoteHost boundPort:(uint16_t)boundPort closeBlock:^(SSHKitCompletion completion) {
        [runtime closeWithCompletion:completion];
    }];
}

#pragma clang diagnostic pop

- (int)openLocalForwardListenerAtHost:(NSString *)host port:(uint16_t)port boundPort:(uint16_t *)boundPort error:(NSError **)error {
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_flags = AI_PASSIVE;

    NSString *portString = [NSString stringWithFormat:@"%hu", port];
    struct addrinfo *addresses = NULL;
    int result = getaddrinfo(host.UTF8String, portString.UTF8String, &hints, &addresses);
    if (result != 0) {
        if (error) {
            *error = SSHKitMakeError(SSHKitErrorCodeConnectionFailed, [NSString stringWithFormat:@"Unable to resolve local forward bind host: %s", gai_strerror(result)]);
        }
        return -1;
    }

    NSError *lastError = nil;
    for (struct addrinfo *address = addresses; address != NULL; address = address->ai_next) {
        int fileDescriptor = socket(address->ai_family, address->ai_socktype, address->ai_protocol);
        if (fileDescriptor < 0) {
            lastError = SSHKitMakeError(SSHKitErrorCodeConnectionFailed, [NSString stringWithFormat:@"Unable to create local forward listener: %s", strerror(errno)]);
            continue;
        }

        int reuse = 1;
        setsockopt(fileDescriptor, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
        if (bind(fileDescriptor, address->ai_addr, address->ai_addrlen) != 0) {
            lastError = SSHKitMakeError(SSHKitErrorCodeConnectionFailed, [NSString stringWithFormat:@"Unable to bind local forward listener: %s", strerror(errno)]);
            close(fileDescriptor);
            continue;
        }
        if (listen(fileDescriptor, 16) != 0) {
            lastError = SSHKitMakeError(SSHKitErrorCodeConnectionFailed, [NSString stringWithFormat:@"Unable to listen for local forward: %s", strerror(errno)]);
            close(fileDescriptor);
            continue;
        }

        *boundPort = [self boundPortForSocket:fileDescriptor fallback:port];
        freeaddrinfo(addresses);
        return fileDescriptor;
    }

    freeaddrinfo(addresses);
    if (error) {
        *error = lastError ?: SSHKitMakeError(SSHKitErrorCodeConnectionFailed, @"Unable to start local forward listener.");
    }
    return -1;
}

- (uint16_t)boundPortForSocket:(int)socket fallback:(uint16_t)fallback {
    struct sockaddr_storage address;
    socklen_t addressLength = sizeof(address);
    if (getsockname(socket, (struct sockaddr *)&address, &addressLength) != 0) {
        return fallback;
    }
    if (address.ss_family == AF_INET) {
        return ntohs(((struct sockaddr_in *)&address)->sin_port);
    }
    if (address.ss_family == AF_INET6) {
        return ntohs(((struct sockaddr_in6 *)&address)->sin6_port);
    }
    return fallback;
}

@end

#pragma clang diagnostic pop
