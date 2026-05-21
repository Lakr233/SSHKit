#import <SSHKitObjC/SSHKitAlgorithmInspector.h>

#import <CLibSSH/CLibSSH.h>
#import <SSHKitObjC/SSHKitError.h>

static BOOL SSHKitSetAlgorithmString(ssh_session session, enum ssh_options_e option, NSString *value, NSString *name, NSError **error) {
    if (value.length == 0) {
        return YES;
    }
    if (ssh_options_set(session, option, value.UTF8String) == SSH_OK) {
        return YES;
    }
    if (error) {
        *error = SSHKitMakeError(SSHKitErrorCodeInvalidState, [NSString stringWithFormat:@"Unsupported SSH algorithm profile value for %@.", name]);
    }
    return NO;
}

static BOOL SSHKitSetAlgorithmNumber(ssh_session session, enum ssh_options_e option, NSNumber *value, NSString *name, NSError **error) {
    if (value == nil) {
        return YES;
    }
    int intValue = value.intValue;
    if (ssh_options_set(session, option, &intValue) == SSH_OK) {
        return YES;
    }
    if (error) {
        *error = SSHKitMakeError(SSHKitErrorCodeInvalidState, [NSString stringWithFormat:@"Unsupported SSH algorithm profile value for %@.", name]);
    }
    return NO;
}

static BOOL SSHKitGetAlgorithmString(ssh_session session, enum ssh_options_e option, NSString *key, NSMutableDictionary<NSString *, NSString *> *values, NSError **error) {
    char *value = NULL;
    if (ssh_options_get(session, option, &value) != SSH_OK || value == NULL) {
        if (error) {
            *error = SSHKitMakeError(SSHKitErrorCodeUnavailable, [NSString stringWithFormat:@"Unable to inspect SSH algorithms for %@.", key]);
        }
        return NO;
    }
    values[key] = @(value);
    SSH_STRING_FREE_CHAR(value);
    return YES;
}

static BOOL SSHKitGetPublicKeyAcceptedAlgorithms(ssh_session session, NSString *publicKeyAcceptedAlgorithms, NSMutableDictionary<NSString *, NSString *> *values, NSError **error) {
    char *value = NULL;
    if (ssh_options_get(session, SSH_OPTIONS_PUBLICKEY_ACCEPTED_TYPES, &value) == SSH_OK && value != NULL) {
        values[@"publicKeyAcceptedAlgorithms"] = @(value);
        SSH_STRING_FREE_CHAR(value);
        return YES;
    }
    if (publicKeyAcceptedAlgorithms.length > 0) {
        if (error) {
            *error = SSHKitMakeError(SSHKitErrorCodeUnavailable, @"Unable to inspect SSH algorithms for publicKeyAcceptedAlgorithms.");
        }
        return NO;
    }

    NSString *hostKeyAlgorithms = values[@"hostKeyAlgorithms"];
    if (hostKeyAlgorithms.length == 0) {
        if (error) {
            *error = SSHKitMakeError(SSHKitErrorCodeUnavailable, @"Unable to derive SSH public-key accepted algorithms from host-key defaults.");
        }
        return NO;
    }

    // libssh falls back to the host-key algorithm defaults when PUBLICKEY_ACCEPTED_TYPES is unset.
    values[@"publicKeyAcceptedAlgorithms"] = hostKeyAlgorithms;
    return YES;
}

@implementation SSHKitAlgorithmInspector

+ (nullable NSDictionary<NSString *, NSString *> *)inspectAlgorithmsWithKeyExchangeAlgorithms:(nullable NSString *)keyExchangeAlgorithms
                                                                            hostKeyAlgorithms:(nullable NSString *)hostKeyAlgorithms
                                                                   publicKeyAcceptedAlgorithms:(nullable NSString *)publicKeyAcceptedAlgorithms
                                                                        ciphersClientToServer:(nullable NSString *)ciphersClientToServer
                                                                        ciphersServerToClient:(nullable NSString *)ciphersServerToClient
                                                                            macsClientToServer:(nullable NSString *)macsClientToServer
                                                                            macsServerToClient:(nullable NSString *)macsServerToClient
                                                                             minimumRSAKeySize:(nullable NSNumber *)minimumRSAKeySize
                                                                                        error:(NSError **)error {
    ssh_session session = ssh_new();
    if (session == NULL) {
        if (error) {
            *error = SSHKitMakeError(SSHKitErrorCodeUnavailable, @"Unable to create libssh session for algorithm inspection.");
        }
        return nil;
    }

    BOOL configured =
        SSHKitSetAlgorithmString(session, SSH_OPTIONS_KEY_EXCHANGE, keyExchangeAlgorithms, @"keyExchangeAlgorithms", error) &&
        SSHKitSetAlgorithmString(session, SSH_OPTIONS_HOSTKEYS, hostKeyAlgorithms, @"hostKeyAlgorithms", error) &&
        SSHKitSetAlgorithmString(session, SSH_OPTIONS_PUBLICKEY_ACCEPTED_TYPES, publicKeyAcceptedAlgorithms, @"publicKeyAcceptedAlgorithms", error) &&
        SSHKitSetAlgorithmString(session, SSH_OPTIONS_CIPHERS_C_S, ciphersClientToServer, @"ciphersClientToServer", error) &&
        SSHKitSetAlgorithmString(session, SSH_OPTIONS_CIPHERS_S_C, ciphersServerToClient, @"ciphersServerToClient", error) &&
        SSHKitSetAlgorithmString(session, SSH_OPTIONS_HMAC_C_S, macsClientToServer, @"macsClientToServer", error) &&
        SSHKitSetAlgorithmString(session, SSH_OPTIONS_HMAC_S_C, macsServerToClient, @"macsServerToClient", error) &&
        SSHKitSetAlgorithmNumber(session, SSH_OPTIONS_RSA_MIN_SIZE, minimumRSAKeySize, @"minimumRSAKeySize", error);
    if (!configured) {
        ssh_free(session);
        return nil;
    }

    NSMutableDictionary<NSString *, NSString *> *values = [[NSMutableDictionary alloc] init];
    BOOL inspected =
        SSHKitGetAlgorithmString(session, SSH_OPTIONS_KEY_EXCHANGE, @"keyExchangeAlgorithms", values, error) &&
        SSHKitGetAlgorithmString(session, SSH_OPTIONS_HOSTKEYS, @"hostKeyAlgorithms", values, error) &&
        SSHKitGetAlgorithmString(session, SSH_OPTIONS_CIPHERS_C_S, @"ciphersClientToServer", values, error) &&
        SSHKitGetAlgorithmString(session, SSH_OPTIONS_CIPHERS_S_C, @"ciphersServerToClient", values, error) &&
        SSHKitGetAlgorithmString(session, SSH_OPTIONS_HMAC_C_S, @"macsClientToServer", values, error) &&
        SSHKitGetAlgorithmString(session, SSH_OPTIONS_HMAC_S_C, @"macsServerToClient", values, error) &&
        SSHKitGetPublicKeyAcceptedAlgorithms(session, publicKeyAcceptedAlgorithms, values, error);
    if (minimumRSAKeySize != nil) {
        values[@"minimumRSAKeySize"] = minimumRSAKeySize.stringValue;
    }
    ssh_free(session);

    return inspected ? values : nil;
}

@end
