#import "SSHCoreOpenSSHClient+ProxyJump.h"

#import "SSHCoreOpenSSHClient+Internal.h"

#import <SSHKitObjC/SSHKitConfiguration.h>
#import <SSHKitObjC/SSHKitError.h>

#import "SSHCoreLibSSHHelpers.h"

#include <math.h>
#include <libssh/callbacks.h>

static int SSHCoreProxyJumpBeforeConnection(ssh_session session, void *userdata) {
    SSHKitConfiguration *configuration = (__bridge SSHKitConfiguration *)userdata;
    long timeout = (long)ceil(configuration.timeout);
    if (ssh_options_set(session, SSH_OPTIONS_TIMEOUT, &timeout) != SSH_OK) {
        return SSH_ERROR;
    }
    if (!SSHCoreApplyAlgorithmProfile(session, configuration, NULL)) {
        return SSH_ERROR;
    }
    if (configuration.hostKeyPolicyKind == SSHKitHostKeyPolicyKindKnownHostsFile) {
        if (configuration.knownHostsPath.length == 0) {
            return SSH_ERROR;
        }
        if (ssh_options_set(session, SSH_OPTIONS_KNOWNHOSTS, configuration.knownHostsPath.UTF8String) != SSH_OK) {
            return SSH_ERROR;
        }
    }
    if (configuration.authenticationKind == SSHKitAuthenticationKindAgent && configuration.identityAgentPath.length > 0) {
        if (ssh_options_set(session, SSH_OPTIONS_IDENTITY_AGENT, configuration.identityAgentPath.UTF8String) != SSH_OK) {
            return SSH_ERROR;
        }
    }
    return SSH_OK;
}

static int SSHCoreProxyJumpVerifyKnownHost(ssh_session session, void *userdata) {
    SSHKitConfiguration *configuration = (__bridge SSHKitConfiguration *)userdata;
    if (configuration.hostKeyPolicyKind == SSHKitHostKeyPolicyKindInsecureAcceptAnyHostKey) {
        return SSH_OK;
    }
    NSString *fingerprint = SSHCoreSHA256FingerprintForSession(session);
    if (configuration.hostKeyPolicyKind == SSHKitHostKeyPolicyKindPinnedFingerprint) {
        return SSHCoreFingerprintMatches(fingerprint, configuration.pinnedHostKeySHA256Fingerprint) ? SSH_OK : SSH_ERROR;
    }
    if (configuration.hostKeyPolicyKind == SSHKitHostKeyPolicyKindTrustedFingerprint) {
        return configuration.hostKeyTrustStoreError.length == 0 &&
               SSHCoreFingerprintMatches(fingerprint, configuration.trustedHostKeySHA256Fingerprint)
                   ? SSH_OK
                   : SSH_ERROR;
    }
    return ssh_session_is_known_server(session) == SSH_KNOWN_HOSTS_OK ? SSH_OK : SSH_ERROR;
}

static int SSHCoreProxyJumpAuthenticate(ssh_session session, void *userdata) {
    SSHKitConfiguration *configuration = (__bridge SSHKitConfiguration *)userdata;
    int rc = SSH_AUTH_DENIED;
    switch (configuration.authenticationKind) {
        case SSHKitAuthenticationKindPassword:
            if (configuration.password.length == 0) {
                return SSH_ERROR;
            }
            rc = ssh_userauth_password(session, NULL, configuration.password.UTF8String);
            break;
        case SSHKitAuthenticationKindPrivateKeyFile: {
            if (configuration.privateKeyPath.length == 0) {
                return SSH_ERROR;
            }
            ssh_key privateKey = NULL;
            const char *passphrase = configuration.privateKeyPassphrase.length > 0 ? configuration.privateKeyPassphrase.UTF8String : NULL;
            if (ssh_pki_import_privkey_file(configuration.privateKeyPath.UTF8String, passphrase, NULL, NULL, &privateKey) != SSH_OK) {
                return SSH_ERROR;
            }
            rc = ssh_userauth_publickey(session, NULL, privateKey);
            ssh_key_free(privateKey);
            break;
        }
        case SSHKitAuthenticationKindKeyboardInteractive:
            return SSH_ERROR;
        case SSHKitAuthenticationKindAgent:
            rc = ssh_userauth_agent(session, NULL);
            break;
    }
    return rc == SSH_AUTH_SUCCESS ? SSH_OK : SSH_ERROR;
}

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wobjc-protocol-method-implementation"

@implementation SSHCoreOpenSSHClient (ProxyJump)

- (BOOL)configureProxyJumpForSession:(ssh_session)session error:(NSError **)error {
    SSHKitConfiguration *jumpConfiguration = self.configuration.proxyJumpConfiguration;
    if (jumpConfiguration == nil) {
        if (error) {
            *error = SSHKitMakeError(SSHKitErrorCodeConnectionFailed, @"ProxyJump route requires a jump host configuration.");
        }
        return NO;
    }
    if (jumpConfiguration.authenticationKind == SSHKitAuthenticationKindKeyboardInteractive) {
        if (error) {
            *error = SSHKitMakeError(SSHKitErrorCodeAuthenticationFailed, [NSString stringWithFormat:@"ProxyJump route does not support keyboard-interactive authentication for jump host %@:%hu.", jumpConfiguration.host, jumpConfiguration.port]);
        }
        return NO;
    }

    NSString *jumpRoute = [NSString stringWithFormat:@"%@@%@:%hu", jumpConfiguration.username, jumpConfiguration.host, jumpConfiguration.port];
    if (ssh_options_set(session, SSH_OPTIONS_PROXYJUMP, jumpRoute.UTF8String) != SSH_OK) {
        if (error) {
            *error = [self libSSHErrorWithSession:session code:SSHKitErrorCodeConnectionFailed fallback:@"Unable to configure ProxyJump route."];
        }
        return NO;
    }

    struct ssh_jump_callbacks_struct *callbacks = calloc(1, sizeof(struct ssh_jump_callbacks_struct));
    if (callbacks == NULL) {
        if (error) {
            *error = SSHKitMakeError(SSHKitErrorCodeUnavailable, @"Unable to allocate ProxyJump callbacks.");
        }
        return NO;
    }

    callbacks->userdata = (__bridge void *)jumpConfiguration;
    callbacks->before_connection = SSHCoreProxyJumpBeforeConnection;
    callbacks->verify_knownhost = SSHCoreProxyJumpVerifyKnownHost;
    callbacks->authenticate = SSHCoreProxyJumpAuthenticate;

    if (ssh_options_set(session, SSH_OPTIONS_PROXYJUMP_CB_LIST_APPEND, callbacks) != SSH_OK) {
        free(callbacks);
        if (error) {
            *error = [self libSSHErrorWithSession:session code:SSHKitErrorCodeConnectionFailed fallback:@"Unable to configure ProxyJump callbacks."];
        }
        return NO;
    }

    [self.proxyJumpCallbackPointers addObject:[NSValue valueWithPointer:callbacks]];
    self.proxyJumpCallbackConfigurations = @[jumpConfiguration];
    return YES;
}

@end

#pragma clang diagnostic pop
