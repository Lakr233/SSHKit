#import "SSHCoreLibSSHHelpers.h"

#import <SSHKitObjC/SSHKitConfiguration.h>

#include <sys/socket.h>
#include <unistd.h>

const int32_t SSHCoreAbnormalExitStatus = -1;

static NSString *SSHCoreNormalizeSHA256Fingerprint(NSString *fingerprint) {
    NSString *trimmed = [fingerprint stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet];
    if (trimmed.length == 0) {
        return @"";
    }
    if ([trimmed rangeOfString:@"SHA256:" options:NSCaseInsensitiveSearch].location == 0) {
        return trimmed;
    }
    return [@"SHA256:" stringByAppendingString:trimmed];
}

NSString *SSHCoreSHA256FingerprintForSession(ssh_session session) {
    ssh_key key = NULL;
    unsigned char *hash = NULL;
    size_t hashLength = 0;
    char *fingerprint = NULL;
    NSString *result = nil;

    if (ssh_get_server_publickey(session, &key) != SSH_OK || key == NULL) {
        goto cleanup;
    }
    if (ssh_get_publickey_hash(key, SSH_PUBLICKEY_HASH_SHA256, &hash, &hashLength) != SSH_OK || hash == NULL) {
        goto cleanup;
    }
    fingerprint = ssh_get_fingerprint_hash(SSH_PUBLICKEY_HASH_SHA256, hash, hashLength);
    if (fingerprint == NULL) {
        goto cleanup;
    }
    result = @(fingerprint);

cleanup:
    if (fingerprint != NULL) {
        SSH_STRING_FREE_CHAR(fingerprint);
    }
    if (hash != NULL) {
        ssh_clean_pubkey_hash(&hash);
    }
    if (key != NULL) {
        ssh_key_free(key);
    }
    return result;
}

BOOL SSHCoreFingerprintMatches(NSString *actualFingerprint, NSString *expectedFingerprint) {
    NSString *actual = SSHCoreNormalizeSHA256Fingerprint(actualFingerprint);
    NSString *expected = SSHCoreNormalizeSHA256Fingerprint(expectedFingerprint);
    return actual.length > 0 && expected.length > 0 && [actual isEqualToString:expected];
}

static BOOL SSHCoreSetAlgorithmString(ssh_session session, enum ssh_options_e option, NSString *value, NSString *name, NSString **failedField) {
    if (value.length == 0) {
        return YES;
    }
    if (ssh_options_set(session, option, value.UTF8String) == SSH_OK) {
        return YES;
    }
    if (failedField) {
        *failedField = name;
    }
    return NO;
}

static BOOL SSHCoreSetAlgorithmNumber(ssh_session session, enum ssh_options_e option, NSNumber *value, NSString *name, NSString **failedField) {
    if (value == nil) {
        return YES;
    }
    int intValue = value.intValue;
    if (ssh_options_set(session, option, &intValue) == SSH_OK) {
        return YES;
    }
    if (failedField) {
        *failedField = name;
    }
    return NO;
}

BOOL SSHCoreApplyAlgorithmProfile(ssh_session session, SSHKitConfiguration *configuration, NSString **failedField) {
    return SSHCoreSetAlgorithmString(session, SSH_OPTIONS_KEY_EXCHANGE, configuration.keyExchangeAlgorithms, @"keyExchangeAlgorithms", failedField) &&
           SSHCoreSetAlgorithmString(session, SSH_OPTIONS_HOSTKEYS, configuration.hostKeyAlgorithms, @"hostKeyAlgorithms", failedField) &&
           SSHCoreSetAlgorithmString(session, SSH_OPTIONS_PUBLICKEY_ACCEPTED_TYPES, configuration.publicKeyAcceptedAlgorithms, @"publicKeyAcceptedAlgorithms", failedField) &&
           SSHCoreSetAlgorithmString(session, SSH_OPTIONS_CIPHERS_C_S, configuration.ciphersClientToServer, @"ciphersClientToServer", failedField) &&
           SSHCoreSetAlgorithmString(session, SSH_OPTIONS_CIPHERS_S_C, configuration.ciphersServerToClient, @"ciphersServerToClient", failedField) &&
           SSHCoreSetAlgorithmString(session, SSH_OPTIONS_HMAC_C_S, configuration.macsClientToServer, @"macsClientToServer", failedField) &&
           SSHCoreSetAlgorithmString(session, SSH_OPTIONS_HMAC_S_C, configuration.macsServerToClient, @"macsServerToClient", failedField) &&
           SSHCoreSetAlgorithmNumber(session, SSH_OPTIONS_RSA_MIN_SIZE, configuration.minimumRSAKeySize, @"minimumRSAKeySize", failedField);
}

void SSHCoreCloseDescriptor(int *fileDescriptor) {
    if (*fileDescriptor < 0) {
        return;
    }

    shutdown(*fileDescriptor, SHUT_RDWR);
    close(*fileDescriptor);
    *fileDescriptor = -1;
}

void SSHCoreShutdownDescriptor(int fileDescriptor) {
    if (fileDescriptor < 0) {
        return;
    }

    shutdown(fileDescriptor, SHUT_RDWR);
}

void SSHCoreFreeForwardChannel(ssh_channel channel) {
    if (channel == NULL) {
        return;
    }

    ssh_channel_send_eof(channel);
    ssh_channel_close(channel);
    ssh_channel_free(channel);
}

NSString *SSHCoreAuthenticationName(SSHKitAuthenticationKind kind) {
    switch (kind) {
        case SSHKitAuthenticationKindPassword:
            return @"password";
        case SSHKitAuthenticationKindPrivateKeyFile:
            return @"privateKeyFile";
        case SSHKitAuthenticationKindKeyboardInteractive:
            return @"keyboardInteractive";
        case SSHKitAuthenticationKindAgent:
            return @"agent";
    }
}

NSString *SSHCoreHostKeyPolicyName(SSHKitHostKeyPolicyKind kind) {
    switch (kind) {
        case SSHKitHostKeyPolicyKindInsecureAcceptAnyHostKey:
            return @"insecureAcceptAnyHostKey";
        case SSHKitHostKeyPolicyKindKnownHostsFile:
            return @"knownHostsFile";
        case SSHKitHostKeyPolicyKindPinnedFingerprint:
            return @"pinnedFingerprint";
        case SSHKitHostKeyPolicyKindTrustedFingerprint:
            return @"trustedFingerprint";
    }
}
