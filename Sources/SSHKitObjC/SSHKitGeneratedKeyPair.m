#import <SSHKitObjC/SSHKitGeneratedKeyPair.h>

#import <CLibSSH/CLibSSH.h>
#import <SSHKitObjC/SSHKitError.h>

static BOOL SSHKitResolveKeyGeneration(SSHKitKeyGenerationType type, NSInteger bits, enum ssh_keytypes_e *keyType, int *parameter, NSError **error) {
    switch (type) {
        case SSHKitKeyGenerationTypeEd25519:
            *keyType = SSH_KEYTYPE_ED25519;
            *parameter = 0;
            return YES;
        case SSHKitKeyGenerationTypeRSA:
            if (bits < 2048) {
                if (error) {
                    *error = SSHKitMakeError(SSHKitErrorCodeInvalidState, @"RSA key generation requires at least 2048 bits.");
                }
                return NO;
            }
            *keyType = SSH_KEYTYPE_RSA;
            *parameter = (int)bits;
            return YES;
        case SSHKitKeyGenerationTypeECDSAP256:
            *keyType = SSH_KEYTYPE_ECDSA_P256;
            *parameter = 256;
            return YES;
        case SSHKitKeyGenerationTypeECDSAP384:
            *keyType = SSH_KEYTYPE_ECDSA_P384;
            *parameter = 384;
            return YES;
        case SSHKitKeyGenerationTypeECDSAP521:
            *keyType = SSH_KEYTYPE_ECDSA_P521;
            *parameter = 521;
            return YES;
    }
}

@implementation SSHKitGeneratedKeyPair

- (instancetype)initWithPrivateKeyOpenSSH:(NSString *)privateKeyOpenSSH
                            authorizedKey:(NSString *)authorizedKey
                            publicKeyType:(NSString *)publicKeyType {
    NSParameterAssert(privateKeyOpenSSH.length > 0);
    NSParameterAssert(authorizedKey.length > 0);
    NSParameterAssert(publicKeyType.length > 0);

    self = [super init];
    if (self) {
        _privateKeyOpenSSH = [privateKeyOpenSSH copy];
        _authorizedKey = [authorizedKey copy];
        _publicKeyType = [publicKeyType copy];
    }
    return self;
}

+ (nullable instancetype)generateOpenSSHKeyPairWithType:(SSHKitKeyGenerationType)type
                                                   bits:(NSInteger)bits
                                                comment:(nullable NSString *)comment
                                             passphrase:(nullable NSString *)passphrase
                                                  error:(NSError **)error {
    enum ssh_keytypes_e keyType = SSH_KEYTYPE_UNKNOWN;
    int parameter = 0;
    if (!SSHKitResolveKeyGeneration(type, bits, &keyType, &parameter, error)) {
        return nil;
    }

    ssh_key privateKey = NULL;
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
    int rc = ssh_pki_generate(keyType, parameter, &privateKey);
#pragma clang diagnostic pop
    if (rc != SSH_OK || privateKey == NULL) {
        if (error) {
            *error = SSHKitMakeError(SSHKitErrorCodeUnavailable, @"Unable to generate SSH key pair.");
        }
        return nil;
    }

    char *privateKeyText = NULL;
    const char *passphraseString = passphrase.length > 0 ? passphrase.UTF8String : NULL;
    rc = ssh_pki_export_privkey_base64_format(privateKey, passphraseString, NULL, NULL, &privateKeyText, SSH_FILE_FORMAT_OPENSSH);
    if (rc != SSH_OK || privateKeyText == NULL) {
        ssh_key_free(privateKey);
        if (error) {
            *error = SSHKitMakeError(SSHKitErrorCodeUnavailable, @"Unable to export OpenSSH private key.");
        }
        return nil;
    }

    char *publicKeyBase64 = NULL;
    rc = ssh_pki_export_pubkey_base64(privateKey, &publicKeyBase64);
    if (rc != SSH_OK || publicKeyBase64 == NULL) {
        SSH_STRING_FREE_CHAR(privateKeyText);
        ssh_key_free(privateKey);
        if (error) {
            *error = SSHKitMakeError(SSHKitErrorCodeUnavailable, @"Unable to export OpenSSH public key.");
        }
        return nil;
    }

    const char *publicKeyType = ssh_key_type_to_char(ssh_key_type(privateKey));
    NSString *publicKeyTypeString = publicKeyType != NULL ? @(publicKeyType) : @"unknown";
    NSString *publicKeyString = @(publicKeyBase64);
    NSString *authorizedKey = comment.length > 0
        ? [NSString stringWithFormat:@"%@ %@ %@", publicKeyTypeString, publicKeyString, comment]
        : [NSString stringWithFormat:@"%@ %@", publicKeyTypeString, publicKeyString];

    SSHKitGeneratedKeyPair *keyPair = [[SSHKitGeneratedKeyPair alloc] initWithPrivateKeyOpenSSH:@(privateKeyText)
                                                                                  authorizedKey:authorizedKey
                                                                                  publicKeyType:publicKeyTypeString];
    SSH_STRING_FREE_CHAR(privateKeyText);
    SSH_STRING_FREE_CHAR(publicKeyBase64);
    ssh_key_free(privateKey);
    return keyPair;
}

@end
