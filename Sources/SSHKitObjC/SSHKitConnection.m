#import <SSHKitObjC/SSHKitError.h>
#import <SSHKitObjC/SSHKitConnection.h>
#import "SSHCoreOpenSSHClient.h"
#import "SSHCoreSessionWorker.h"
#import "SSHKitCommand+Private.h"
#import "SSHKitPortForward+Private.h"
#import "SSHKitSFTPClient+Private.h"
#import "SSHKitShell+Private.h"
#import "SSHKitTunnelChannel+Private.h"

@interface SSHKitConfiguration (SSHKitResolution)
- (SSHKitConfiguration *)sshkit_resolvedConfiguration;
@end

@interface SSHKitConnection ()

@property (nonatomic, copy, readwrite) SSHKitConfiguration *configuration;
@property (nonatomic) SSHCoreSessionWorker *worker;
@property (nonatomic) SSHCoreOpenSSHClient *client;

@end

@implementation SSHKitConnection

- (NSString *)hostKeySHA256Fingerprint {
    return self.client.hostKeySHA256Fingerprint;
}

- (instancetype)initWithConfiguration:(SSHKitConfiguration *)configuration {
    self = [super init];
    if (self) {
        _configuration = [configuration sshkit_resolvedConfiguration];
        _worker = [[SSHCoreSessionWorker alloc] init];
        _client = [[SSHCoreOpenSSHClient alloc] initWithConfiguration:_configuration worker:_worker];
    }
    return self;
}

- (void)connectWithCompletion:(SSHKitCompletion)completion {
    [self.worker async:^{
        if (self.worker.state != SSHCoreSessionStateIdle) {
            NSError *error = SSHKitMakeError(SSHKitErrorCodeCancelled, @"SSH connection was cancelled before connect began.");
            [self completeOnDefaultQueue:completion error:error];
            return;
        }

        [self.worker transitionToState:SSHCoreSessionStateConnecting];
        NSError *error = nil;
        if ([self.client verifyConnectionWithError:&error]) {
            [self.worker transitionToState:SSHCoreSessionStateReady];
            [self completeOnDefaultQueue:completion error:nil];
            return;
        }

        [self.worker transitionToState:SSHCoreSessionStateClosed];
        [self completeOnDefaultQueue:completion error:error];
    }];
}

- (void)discoverAuthenticationMethodsWithCompletion:(SSHKitAuthenticationDiscoveryCompletion)completion {
    [self.worker async:^{
        if (self.worker.state != SSHCoreSessionStateIdle) {
            NSError *error = SSHKitMakeError(SSHKitErrorCodeInvalidState, @"SSH authentication discovery can only start from an idle session.");
            [self completeAuthenticationDiscoveryOnDefaultQueue:completion result:nil error:error];
            return;
        }

        NSError *error = nil;
        [self.worker transitionToState:SSHCoreSessionStateConnecting];
        SSHKitAuthenticationDiscoveryResult *result = [self.client discoverAuthenticationMethodsWithError:&error];
        [self.client closeSession];
        [self.worker transitionToState:SSHCoreSessionStateClosed];
        [self completeAuthenticationDiscoveryOnDefaultQueue:completion result:result error:error];
    }];
}

- (void)discoverHostKeyWithCompletion:(SSHKitHostKeyDiscoveryCompletion)completion {
    [self.worker async:^{
        if (self.worker.state != SSHCoreSessionStateIdle) {
            NSError *error = SSHKitMakeError(SSHKitErrorCodeInvalidState, @"SSH host key discovery can only start from an idle session.");
            [self completeHostKeyDiscoveryOnDefaultQueue:completion result:nil error:error];
            return;
        }

        NSError *error = nil;
        [self.worker transitionToState:SSHCoreSessionStateConnecting];
        SSHKitHostKeyDiscoveryResult *result = [self.client discoverHostKeyWithError:&error];
        [self.client closeSession];
        [self.worker transitionToState:SSHCoreSessionStateClosed];
        [self completeHostKeyDiscoveryOnDefaultQueue:completion result:result error:error];
    }];
}

- (void)executeCommand:(NSString *)command completion:(SSHKitCommandCompletion)completion {
    NSParameterAssert(command.length > 0);
    [self executeCommand:command requestPTY:NO completion:completion];
}

- (void)executePTYCommand:(NSString *)command completion:(SSHKitCommandCompletion)completion {
    NSParameterAssert(command.length > 0);
    [self executeCommand:command requestPTY:YES completion:completion];
}

- (void)executeCommand:(NSString *)command requestPTY:(BOOL)requestPTY completion:(SSHKitCommandCompletion)completion {

    [self.worker async:^{
        if (self.worker.state != SSHCoreSessionStateReady) {
            NSError *error = SSHKitMakeError(SSHKitErrorCodeInvalidState, @"SSH session is not connected.");
            [self completeCommandOnDefaultQueue:completion result:nil error:error];
            return;
        }

        [self.worker transitionToState:SSHCoreSessionStateRunningCommand];
        NSError *error = nil;
        SSHKitCommandResult *result = requestPTY
            ? [self.client executePTYCommand:command error:&error]
            : [self.client executeCommand:command error:&error];
        [self.worker transitionToState:SSHCoreSessionStateReady];
        [self completeCommandOnDefaultQueue:completion result:result error:error];
    }];
}

- (void)openCommand:(NSString *)command
       eventHandler:(SSHKitCommandEventHandler)eventHandler
         completion:(SSHKitStreamingCommandCompletion)completion {
    NSParameterAssert(command.length > 0);

    [self.worker async:^{
        if (self.worker.state != SSHCoreSessionStateReady) {
            NSError *error = SSHKitMakeError(SSHKitErrorCodeInvalidState, @"SSH session is not connected.");
            [self completeStreamingCommandOnDefaultQueue:completion command:nil error:error];
            return;
        }

        [self.worker transitionToState:SSHCoreSessionStateRunningCommand];
        NSError *error = nil;
        __block BOOL shouldDeliverClosedEvent = YES;
        SSHKitCommand *streamingCommand = [self.client openCommand:command
                                                     eventHandler:eventHandler
                                                         onClosed:^(int32_t exitStatus, NSString *exitSignal) {
            [self.worker async:^{
                if (!shouldDeliverClosedEvent) {
                    return;
                }
                if (self.worker.state == SSHCoreSessionStateRunningCommand) {
                    [self.worker transitionToState:SSHCoreSessionStateReady];
                }
                SSHKitCommandEvent *event = [[SSHKitCommandEvent alloc] initWithKind:SSHKitCommandEventKindClosed
                                                                                data:[NSData data]
                                                                          exitStatus:exitStatus
                                                                          exitSignal:exitSignal];
                eventHandler(event);
            }];
        } error:&error];

        if (!streamingCommand) {
            shouldDeliverClosedEvent = NO;
            [self.worker transitionToState:SSHCoreSessionStateReady];
            [self completeStreamingCommandOnDefaultQueue:completion command:nil error:error];
            return;
        }

        [self completeStreamingCommandOnDefaultQueue:completion command:streamingCommand error:nil];
    }];
}

- (void)openShellWithTerminalType:(NSString *)terminalType
                           columns:(uint16_t)columns
                              rows:(uint16_t)rows
                      eventHandler:(SSHKitShellEventHandler)eventHandler
                        completion:(SSHKitShellCompletion)completion {
    NSParameterAssert(terminalType.length > 0);
    NSParameterAssert(columns > 0);
    NSParameterAssert(rows > 0);

    [self.worker async:^{
        if (self.worker.state != SSHCoreSessionStateReady) {
            NSError *error = SSHKitMakeError(SSHKitErrorCodeInvalidState, @"SSH session is not connected.");
            [self completeShellOnDefaultQueue:completion shell:nil error:error];
            return;
        }

        [self.worker transitionToState:SSHCoreSessionStateRunningShell];
        NSError *error = nil;
        __block BOOL shouldDeliverClosedEvent = YES;
        SSHKitShell *shell = [self.client openShellWithTerminalType:terminalType
                                                            columns:columns
                                                               rows:rows
                                                       eventHandler:eventHandler
                                                           onClosed:^(int32_t exitStatus) {
            [self.worker async:^{
                if (!shouldDeliverClosedEvent) {
                    return;
                }
                if (self.worker.state == SSHCoreSessionStateRunningShell) {
                    [self.worker transitionToState:SSHCoreSessionStateReady];
                }
                SSHKitShellEvent *event = [[SSHKitShellEvent alloc] initWithKind:SSHKitShellEventKindClosed
                                                                            data:[NSData data]
                                                                      exitStatus:exitStatus];
                eventHandler(event);
            }];
        } error:&error];

        if (!shell) {
            shouldDeliverClosedEvent = NO;
            [self.worker transitionToState:SSHCoreSessionStateReady];
            [self completeShellOnDefaultQueue:completion shell:nil error:error];
            return;
        }

        [self completeShellOnDefaultQueue:completion shell:shell error:nil];
    }];
}

- (void)openSFTPWithCompletion:(SSHKitSFTPCompletion)completion {
    [self.worker async:^{
        if (self.worker.state != SSHCoreSessionStateReady) {
            NSError *error = SSHKitMakeError(SSHKitErrorCodeInvalidState, @"SSH session is not connected.");
            [self completeSFTPOnDefaultQueue:completion client:nil error:error];
            return;
        }

        NSError *error = nil;
        [self.worker transitionToState:SSHCoreSessionStateRunningSFTP];
        SSHKitSFTPClient *client = [self.client openSFTPWithCloseHandler:^{
            [self.worker async:^{
                if (self.worker.state == SSHCoreSessionStateRunningSFTP) {
                    [self.worker transitionToState:SSHCoreSessionStateReady];
                }
            }];
        } error:&error];
        if (!client) {
            [self.worker transitionToState:SSHCoreSessionStateReady];
            [self completeSFTPOnDefaultQueue:completion client:nil error:error];
            return;
        }
        [self completeSFTPOnDefaultQueue:completion client:client error:nil];
    }];
}

- (void)openDirectTCPChannelToHost:(NSString *)host
                              port:(uint16_t)port
                        completion:(SSHKitTunnelChannelCompletion)completion {
    NSParameterAssert(host.length > 0);
    NSParameterAssert(port > 0);

    [self.worker async:^{
        if (self.worker.state != SSHCoreSessionStateReady) {
            NSError *error = SSHKitMakeError(SSHKitErrorCodeInvalidState, @"SSH session is not connected.");
            [self completeTunnelChannelOnDefaultQueue:completion channel:nil error:error];
            return;
        }

        NSError *error = nil;
        [self.worker transitionToState:SSHCoreSessionStateRunningTunnel];
        SSHKitTunnelChannel *channel = [self.client openDirectTCPChannelToHost:host port:port closeHandler:^{
            [self.worker async:^{
                if (self.worker.state == SSHCoreSessionStateRunningTunnel) {
                    [self.worker transitionToState:SSHCoreSessionStateReady];
                }
            }];
        } error:&error];
        if (!channel) {
            [self.worker transitionToState:SSHCoreSessionStateReady];
            [self completeTunnelChannelOnDefaultQueue:completion channel:nil error:error];
            return;
        }

        [self completeTunnelChannelOnDefaultQueue:completion channel:channel error:nil];
    }];
}

- (void)startLocalForwardFromHost:(NSString *)localHost
                              port:(uint16_t)localPort
                            toHost:(NSString *)remoteHost
                        targetPort:(uint16_t)remotePort
                        completion:(SSHKitPortForwardCompletion)completion {
    NSParameterAssert(localHost.length > 0);
    NSParameterAssert(remoteHost.length > 0);
    NSParameterAssert(remotePort > 0);

    [self.worker async:^{
        if (self.worker.state != SSHCoreSessionStateReady) {
            NSError *error = SSHKitMakeError(SSHKitErrorCodeInvalidState, @"SSH session is not connected.");
            [self completePortForwardOnDefaultQueue:completion forward:nil error:error];
            return;
        }

        NSError *error = nil;
        [self.worker transitionToState:SSHCoreSessionStateRunningTunnel];
        SSHKitPortForward *forward = [self.client startLocalForwardFromHost:localHost port:localPort toHost:remoteHost targetPort:remotePort closeHandler:^{
            if (self.worker.state == SSHCoreSessionStateRunningTunnel) {
                [self.worker transitionToState:SSHCoreSessionStateReady];
            }
        } error:&error];
        if (!forward) {
            [self.worker transitionToState:SSHCoreSessionStateReady];
            [self completePortForwardOnDefaultQueue:completion forward:nil error:error];
            return;
        }

        [self completePortForwardOnDefaultQueue:completion forward:forward error:nil];
    }];
}

- (void)startRemoteForwardFromHost:(NSString *)remoteHost
                               port:(uint16_t)remotePort
                             toHost:(NSString *)localHost
                         targetPort:(uint16_t)localPort
                         completion:(SSHKitPortForwardCompletion)completion {
    NSParameterAssert(remoteHost.length > 0);
    NSParameterAssert(localHost.length > 0);
    NSParameterAssert(localPort > 0);

    [self.worker async:^{
        if (self.worker.state != SSHCoreSessionStateReady) {
            NSError *error = SSHKitMakeError(SSHKitErrorCodeInvalidState, @"SSH session is not connected.");
            [self completePortForwardOnDefaultQueue:completion forward:nil error:error];
            return;
        }

        NSError *error = nil;
        [self.worker transitionToState:SSHCoreSessionStateRunningTunnel];
        SSHKitPortForward *forward = [self.client startRemoteForwardFromHost:remoteHost port:remotePort toHost:localHost targetPort:localPort closeHandler:^{
            if (self.worker.state == SSHCoreSessionStateRunningTunnel) {
                [self.worker transitionToState:SSHCoreSessionStateReady];
            }
        } error:&error];
        if (!forward) {
            [self.worker transitionToState:SSHCoreSessionStateReady];
            [self completePortForwardOnDefaultQueue:completion forward:nil error:error];
            return;
        }

        [self completePortForwardOnDefaultQueue:completion forward:forward error:nil];
    }];
}

- (void)startDynamicForwardFromHost:(NSString *)localHost
                                port:(uint16_t)localPort
                            username:(NSString *)username
                            password:(NSString *)password
                          completion:(SSHKitPortForwardCompletion)completion {
    NSParameterAssert(localHost.length > 0);

    [self.worker async:^{
        if (self.worker.state != SSHCoreSessionStateReady) {
            NSError *error = SSHKitMakeError(SSHKitErrorCodeInvalidState, @"SSH session is not connected.");
            [self completePortForwardOnDefaultQueue:completion forward:nil error:error];
            return;
        }

        NSError *error = nil;
        [self.worker transitionToState:SSHCoreSessionStateRunningTunnel];
        SSHKitPortForward *forward = [self.client startDynamicForwardFromHost:localHost port:localPort username:username password:password closeHandler:^{
            if (self.worker.state == SSHCoreSessionStateRunningTunnel) {
                [self.worker transitionToState:SSHCoreSessionStateReady];
            }
        } error:&error];
        if (!forward) {
            [self.worker transitionToState:SSHCoreSessionStateReady];
            [self completePortForwardOnDefaultQueue:completion forward:nil error:error];
            return;
        }

        [self completePortForwardOnDefaultQueue:completion forward:forward error:nil];
    }];
}

- (void)disconnectWithCompletion:(SSHKitCompletion)completion {
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_DEFAULT, 0), ^{
        [self.client cancelCurrentTask];
        NSError *closeError = nil;
        if (![self waitForActiveJobClosedEventDelivery]) {
            closeError = SSHKitMakeError(SSHKitErrorCodeConnectionFailed, @"Timed out waiting for SSH operation to close.");
        }
        [self.worker async:^{
            if (self.worker.state != SSHCoreSessionStateClosed &&
                self.worker.state != SSHCoreSessionStateClosing) {
                [self.worker transitionToState:SSHCoreSessionStateClosing];
            }
            [self.client closeSession];
            if (self.worker.state != SSHCoreSessionStateClosed) {
                [self.worker transitionToState:SSHCoreSessionStateClosed];
            }
            [self completeOnDefaultQueue:completion error:closeError];
        }];
    });
}

- (BOOL)waitForActiveJobClosedEventDelivery {
    NSDate *deadline = [NSDate dateWithTimeIntervalSinceNow:5];
    while ([deadline timeIntervalSinceNow] > 0) {
        if (![self.worker isActiveJobState:self.worker.state]) {
            return YES;
        }
        [NSThread sleepForTimeInterval:0.01];
    }
    return ![self.worker isActiveJobState:self.worker.state];
}

- (void)completeOnDefaultQueue:(SSHKitCompletion)completion error:(NSError *)error {
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_DEFAULT, 0), ^{
        completion(error);
    });
}

- (void)completeCommandOnDefaultQueue:(SSHKitCommandCompletion)completion
                               result:(SSHKitCommandResult *)result
                                error:(NSError *)error {
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_DEFAULT, 0), ^{
        completion(result, error);
    });
}

- (void)completeAuthenticationDiscoveryOnDefaultQueue:(SSHKitAuthenticationDiscoveryCompletion)completion
                                               result:(SSHKitAuthenticationDiscoveryResult *)result
                                                error:(NSError *)error {
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_DEFAULT, 0), ^{
        completion(result, error);
    });
}

- (void)completeHostKeyDiscoveryOnDefaultQueue:(SSHKitHostKeyDiscoveryCompletion)completion
                                        result:(SSHKitHostKeyDiscoveryResult *)result
                                         error:(NSError *)error {
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_DEFAULT, 0), ^{
        completion(result, error);
    });
}

- (void)completeStreamingCommandOnDefaultQueue:(SSHKitStreamingCommandCompletion)completion
                                       command:(SSHKitCommand *)command
                                         error:(NSError *)error {
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_DEFAULT, 0), ^{
        completion(command, error);
        [command startEventDelivery];
    });
}

- (void)completeShellOnDefaultQueue:(SSHKitShellCompletion)completion
                              shell:(SSHKitShell *)shell
                              error:(NSError *)error {
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_DEFAULT, 0), ^{
        completion(shell, error);
        [shell startEventDelivery];
    });
}

- (void)completeSFTPOnDefaultQueue:(SSHKitSFTPCompletion)completion
                            client:(SSHKitSFTPClient *)client
                             error:(NSError *)error {
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_DEFAULT, 0), ^{
        completion(client, error);
    });
}

- (void)completeTunnelChannelOnDefaultQueue:(SSHKitTunnelChannelCompletion)completion
                                    channel:(SSHKitTunnelChannel *)channel
                                      error:(NSError *)error {
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_DEFAULT, 0), ^{
        completion(channel, error);
    });
}

- (void)completePortForwardOnDefaultQueue:(SSHKitPortForwardCompletion)completion
                                  forward:(SSHKitPortForward *)forward
                                    error:(NSError *)error {
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_DEFAULT, 0), ^{
        completion(forward, error);
    });
}

@end
