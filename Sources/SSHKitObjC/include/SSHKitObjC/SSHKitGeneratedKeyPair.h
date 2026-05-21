#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

typedef NS_ENUM(NSInteger, SSHKitKeyGenerationType) {
    SSHKitKeyGenerationTypeEd25519 = 1,
    SSHKitKeyGenerationTypeRSA = 2,
    SSHKitKeyGenerationTypeECDSAP256 = 3,
    SSHKitKeyGenerationTypeECDSAP384 = 4,
    SSHKitKeyGenerationTypeECDSAP521 = 5,
};

@interface SSHKitGeneratedKeyPair : NSObject

@property (nonatomic, copy, readonly) NSString *privateKeyOpenSSH;
@property (nonatomic, copy, readonly) NSString *authorizedKey;
@property (nonatomic, copy, readonly) NSString *publicKeyType;

- (instancetype)init NS_UNAVAILABLE;

- (instancetype)initWithPrivateKeyOpenSSH:(NSString *)privateKeyOpenSSH
                            authorizedKey:(NSString *)authorizedKey
                            publicKeyType:(NSString *)publicKeyType NS_DESIGNATED_INITIALIZER;

+ (nullable instancetype)generateOpenSSHKeyPairWithType:(SSHKitKeyGenerationType)type
                                                   bits:(NSInteger)bits
                                                comment:(nullable NSString *)comment
                                             passphrase:(nullable NSString *)passphrase
                                                  error:(NSError **)error;

@end

NS_ASSUME_NONNULL_END
