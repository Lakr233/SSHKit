#import "SSHCoreOpenSSHClient+HostKey.h"

#import "SSHCoreOpenSSHClient+Internal.h"

#import <SSHKitObjC/SSHKitConfiguration.h>
#import <SSHKitObjC/SSHKitError.h>

#import "SSHCoreLibSSHHelpers.h"

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wobjc-protocol-method-implementation"

@implementation SSHCoreOpenSSHClient (HostKey)

- (BOOL)verifyLibSSHHostKeyForSession:(ssh_session)session error:(NSError **)error {
    NSString *fingerprint = SSHCoreSHA256FingerprintForSession(session);
    self.hostKeySHA256Fingerprint = fingerprint;
    NSDictionary<NSString *, NSString *> *fingerprintMetadata = fingerprint.length > 0 ? @{@"fingerprint": fingerprint} : @{};
    [self emitLogLevel:SSHKitLogLevelInfo phase:@"trust" message:@"SSH host key verification started." metadata:fingerprintMetadata];
    if (self.configuration.hostKeyPolicyKind == SSHKitHostKeyPolicyKindInsecureAcceptAnyHostKey) {
        [self emitLogLevel:SSHKitLogLevelWarning
                     phase:@"trust"
                   message:@"SSH host key accepted by insecure policy."
                  metadata:fingerprint.length > 0
                               ? @{@"policy": @"insecureAcceptAnyHostKey", @"fingerprint": fingerprint}
                               : @{@"policy": @"insecureAcceptAnyHostKey"}];
        return YES;
    }

    if (self.configuration.hostKeyPolicyKind == SSHKitHostKeyPolicyKindPinnedFingerprint) {
        if (fingerprint.length == 0 || !SSHCoreFingerprintMatches(fingerprint, self.configuration.pinnedHostKeySHA256Fingerprint)) {
            if (error) {
                *error = SSHKitMakeError(SSHKitErrorCodeHostKeyVerificationFailed, @"Pinned host key fingerprint did not match the server host key.");
            }
            [self emitLogLevel:SSHKitLogLevelError
                         phase:@"trust"
                       message:@"SSH pinned host key verification failed."
                      metadata:fingerprint.length > 0 ? @{@"fingerprint": fingerprint} : @{}];
            return NO;
        }
        [self emitLogLevel:SSHKitLogLevelInfo
                     phase:@"trust"
                   message:@"SSH pinned host key verification succeeded."
                  metadata:@{@"fingerprint": fingerprint}];
        return YES;
    }

    if (self.configuration.hostKeyPolicyKind == SSHKitHostKeyPolicyKindTrustedFingerprint) {
        if (self.configuration.hostKeyTrustStoreError.length > 0) {
            if (error) {
                *error = SSHKitMakeError(SSHKitErrorCodeHostKeyVerificationFailed, [NSString stringWithFormat:@"Host trust store failed to load trusted fingerprint: %@.", self.configuration.hostKeyTrustStoreError]);
            }
            return NO;
        }
        if (self.configuration.trustedHostKeySHA256Fingerprint.length == 0) {
            if (error) {
                *error = SSHKitMakeError(SSHKitErrorCodeHostKeyVerificationFailed, @"Host trust store has no trusted fingerprint for this host and port.");
            }
            return NO;
        }
        if (fingerprint.length == 0 || !SSHCoreFingerprintMatches(fingerprint, self.configuration.trustedHostKeySHA256Fingerprint)) {
            if (error) {
                *error = SSHKitMakeError(SSHKitErrorCodeHostKeyVerificationFailed, @"Trusted host key fingerprint did not match the server host key.");
            }
            [self emitLogLevel:SSHKitLogLevelError
                         phase:@"trust"
                       message:@"SSH trust-store host key verification failed."
                      metadata:fingerprint.length > 0 ? @{@"fingerprint": fingerprint} : @{}];
            return NO;
        }
        [self emitLogLevel:SSHKitLogLevelInfo
                     phase:@"trust"
                   message:@"SSH trust-store host key verification succeeded."
                  metadata:@{@"fingerprint": fingerprint}];
        return YES;
    }

    enum ssh_known_hosts_e state = ssh_session_is_known_server(session);
    if (state == SSH_KNOWN_HOSTS_OK) {
        [self emitLogLevel:SSHKitLogLevelInfo
                     phase:@"trust"
                   message:@"SSH host key verification succeeded."
                  metadata:fingerprint.length > 0
                               ? @{@"knownHostsState": [NSString stringWithFormat:@"%d", state], @"fingerprint": fingerprint}
                               : @{@"knownHostsState": [NSString stringWithFormat:@"%d", state]}];
        return YES;
    }

    if (error) {
        NSString *message = [NSString stringWithFormat:@"Host key verification failed with libssh known-hosts state %d.", state];
        *error = SSHKitMakeError(SSHKitErrorCodeHostKeyVerificationFailed, message);
    }
    [self emitLogLevel:SSHKitLogLevelError
                 phase:@"trust"
               message:@"SSH host key verification failed."
              metadata:@{@"knownHostsState": [NSString stringWithFormat:@"%d", state]}];
    return NO;
}

@end

#pragma clang diagnostic pop
