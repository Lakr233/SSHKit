#import "SSHCoreOpenSSHClient+Connect.h"

#import "SSHCoreOpenSSHClient+Internal.h"
#import "SSHCoreOpenSSHClient+Auth.h"
#import "SSHCoreOpenSSHClient+Sockets.h"
#import "SSHCoreOpenSSHClient+HostKey.h"
#import "SSHCoreOpenSSHClient+ProxyJump.h"

#import <SSHKitObjC/SSHKitConfiguration.h>
#import <SSHKitObjC/SSHKitError.h>

#import "SSHCoreLibSSHHelpers.h"
#import "SSHCoreSessionWorker.h"
#import "SSHCoreSocketHandle.h"

#include <math.h>

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wobjc-protocol-method-implementation"

@implementation SSHCoreOpenSSHClient (Connect)

- (BOOL)connectLibSSHSessionWithError:(NSError **)error {
    if (![self connectLibSSHSessionWithoutAuthenticationWithError:error]) {
        return NO;
    }

    [self.taskLock lock];
    ssh_session session = self.session;
    [self.taskLock unlock];
    [self emitLogLevel:SSHKitLogLevelInfo phase:@"auth" message:@"SSH authentication started." metadata:@{}];
    if (![self authenticateLibSSHSession:session error:error]) {
        [self emitLogLevel:SSHKitLogLevelError phase:@"auth" message:@"SSH authentication failed." metadata:@{}];
        [self clearLibSSHSession:session];
        return NO;
    }

    [self emitLogLevel:SSHKitLogLevelInfo phase:@"auth" message:@"SSH authentication succeeded." metadata:@{}];
    return YES;
}

- (BOOL)connectLibSSHSessionWithoutAuthenticationWithError:(NSError **)error {
    return [self connectLibSSHSessionWithoutAuthenticationVerifyingHostKey:YES error:error];
}

- (BOOL)connectLibSSHSessionForHostKeyDiscoveryWithError:(NSError **)error {
    return [self connectLibSSHSessionWithoutAuthenticationVerifyingHostKey:NO error:error];
}

- (BOOL)connectLibSSHSessionWithoutAuthenticationVerifyingHostKey:(BOOL)verifyHostKey error:(NSError **)error {
    [self emitLogLevel:SSHKitLogLevelInfo phase:@"connect" message:@"SSH connect started." metadata:@{}];
    if ([self isTaskCancelled]) {
        if (error) {
            *error = SSHKitMakeError(SSHKitErrorCodeCancelled, @"SSH connection was cancelled before connect.");
        }
        [self emitLogLevel:SSHKitLogLevelWarning phase:@"connect" message:@"SSH connect cancelled before socket open." metadata:@{}];
        return NO;
    }

    ssh_session session = ssh_new();
    if (session == NULL) {
        if (error) {
            *error = SSHKitMakeError(SSHKitErrorCodeUnavailable, @"Unable to allocate libssh session.");
        }
        return NO;
    }

    if (![self configureLibSSHSession:session error:error]) {
        ssh_free(session);
        return NO;
    }

    if (self.configuration.proxyRouteKind != SSHKitProxyRouteKindProxyJump) {
        int fileDescriptor = [self openSocketWithError:error];
        if (fileDescriptor < 0) {
            ssh_free(session);
            return NO;
        }

        socket_t sshFileDescriptor = fileDescriptor;
        if (ssh_options_set(session, SSH_OPTIONS_FD, &sshFileDescriptor) != SSH_OK) {
            if (error) {
                *error = [self libSSHErrorWithSession:session code:SSHKitErrorCodeConnectionFailed fallback:@"Unable to attach socket to libssh session."];
            }
            ssh_free(session);
            [self closeWorkerSocketHandle];
            return NO;
        }
    }

    [self.taskLock lock];
    self.session = session;
    BOOL wasCancelledBeforeConnect = self.taskCancelled;
    [self.taskLock unlock];
    if (wasCancelledBeforeConnect) {
        [self clearLibSSHSession:session];
        if (error) {
            *error = SSHKitMakeError(SSHKitErrorCodeCancelled, @"SSH connection was cancelled before connect.");
        }
        return NO;
    }

    if (ssh_connect(session) != SSH_OK) {
        if (error) {
            if ([self isTaskCancelled]) {
                *error = SSHKitMakeError(SSHKitErrorCodeCancelled, @"SSH connection was cancelled.");
            } else {
                *error = [self libSSHErrorWithSession:session code:SSHKitErrorCodeConnectionFailed fallback:[self connectFailureFallbackMessage]];
            }
        }
        [self emitLogLevel:SSHKitLogLevelError phase:@"connect" message:@"SSH transport connect failed." metadata:@{}];
        [self clearLibSSHSession:session];
        return NO;
    }

    if (verifyHostKey) {
        if (![self verifyLibSSHHostKeyForSession:session error:error]) {
            [self clearLibSSHSession:session];
            return NO;
        }
    } else {
        NSString *fingerprint = SSHCoreSHA256FingerprintForSession(session);
        self.hostKeySHA256Fingerprint = fingerprint;
        if (fingerprint.length == 0) {
            if (error) {
                *error = SSHKitMakeError(SSHKitErrorCodeHostKeyVerificationFailed, @"Unable to read server host key fingerprint.");
            }
            [self clearLibSSHSession:session];
            return NO;
        }
    }

    [self emitLogLevel:SSHKitLogLevelInfo phase:@"connect" message:@"SSH transport connect succeeded." metadata:@{}];
    return YES;
}

- (NSString *)connectFailureFallbackMessage {
    if (self.configuration.proxyRouteKind == SSHKitProxyRouteKindProxyJump) {
        SSHKitConfiguration *jump = self.configuration.proxyJumpConfiguration;
        return [NSString stringWithFormat:@"ProxyJump route failed at %@:%hu while connecting to %@:%hu.", jump.host ?: @"<missing-hop>", jump.port, self.configuration.host, self.configuration.port];
    }
    if (self.configuration.proxyRouteKind == SSHKitProxyRouteKindSOCKS5 ||
        self.configuration.proxyRouteKind == SSHKitProxyRouteKindHTTPConnect) {
        return [NSString stringWithFormat:@"Proxy route failed at %@:%hu while connecting to %@:%hu.", self.configuration.proxyHost ?: @"<missing-proxy>", self.configuration.proxyPort, self.configuration.host, self.configuration.port];
    }
    return @"SSH connect failed.";
}

- (BOOL)configureLibSSHSession:(ssh_session)session error:(NSError **)error {
    int port = self.configuration.port;
    long timeout = (long)ceil(self.configuration.timeout);
    const char *host = self.configuration.host.UTF8String;
    const char *username = self.configuration.username.UTF8String;

    if (ssh_options_set(session, SSH_OPTIONS_HOST, host) != SSH_OK ||
        ssh_options_set(session, SSH_OPTIONS_PORT, &port) != SSH_OK ||
        ssh_options_set(session, SSH_OPTIONS_USER, username) != SSH_OK ||
        ssh_options_set(session, SSH_OPTIONS_TIMEOUT, &timeout) != SSH_OK) {
        if (error) {
            *error = [self libSSHErrorWithSession:session code:SSHKitErrorCodeConnectionFailed fallback:@"Unable to configure libssh session."];
        }
        return NO;
    }

    NSString *failedAlgorithmField = nil;
    if (!SSHCoreApplyAlgorithmProfile(session, self.configuration, &failedAlgorithmField)) {
        if (error) {
            NSString *fallback = failedAlgorithmField.length > 0
                                     ? [NSString stringWithFormat:@"Unsupported SSH algorithm profile value for %@.", failedAlgorithmField]
                                     : @"Unable to configure SSH algorithm profile.";
            *error = [self libSSHErrorWithSession:session code:SSHKitErrorCodeConnectionFailed fallback:fallback];
        }
        return NO;
    }

    if (self.configuration.hostKeyPolicyKind == SSHKitHostKeyPolicyKindKnownHostsFile) {
        if (self.configuration.knownHostsPath.length == 0) {
            if (error) {
                *error = SSHKitMakeError(SSHKitErrorCodeHostKeyVerificationFailed, @"Known hosts policy requires a known hosts file path.");
            }
            return NO;
        }

        const char *knownHostsPath = self.configuration.knownHostsPath.UTF8String;
        if (ssh_options_set(session, SSH_OPTIONS_KNOWNHOSTS, knownHostsPath) != SSH_OK) {
            if (error) {
                *error = [self libSSHErrorWithSession:session code:SSHKitErrorCodeHostKeyVerificationFailed fallback:@"Unable to configure known hosts file."];
            }
            return NO;
        }
    }

    if (self.configuration.authenticationKind == SSHKitAuthenticationKindAgent && self.configuration.identityAgentPath.length > 0) {
        if (ssh_options_set(session, SSH_OPTIONS_IDENTITY_AGENT, self.configuration.identityAgentPath.UTF8String) != SSH_OK) {
            if (error) {
                *error = [self libSSHErrorWithSession:session code:SSHKitErrorCodeAuthenticationFailed fallback:@"Unable to configure SSH agent socket."];
            }
            return NO;
        }
    }

    if (self.configuration.proxyRouteKind == SSHKitProxyRouteKindProxyJump) {
        if (![self configureProxyJumpForSession:session error:error]) {
            return NO;
        }
    }

    return YES;
}

@end

#pragma clang diagnostic pop
