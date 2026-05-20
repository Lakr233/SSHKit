#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

typedef NS_ENUM(NSInteger, SSHKitAuthenticationKind) {
    SSHKitAuthenticationKindPassword = 1,
    SSHKitAuthenticationKindPrivateKeyFile = 2,
};

typedef NS_ENUM(NSInteger, SSHKitHostKeyPolicyKind) {
    SSHKitHostKeyPolicyKindAcceptAnyVerifiedHostKey = 1,
    SSHKitHostKeyPolicyKindKnownHostsFile = 2,
};

@interface SSHKitConfiguration : NSObject <NSCopying>

@property (nonatomic, copy) NSString *host;
@property (nonatomic) uint16_t port;
@property (nonatomic, copy) NSString *username;
@property (nonatomic) SSHKitAuthenticationKind authenticationKind;
@property (nonatomic, copy, nullable) NSString *password;
@property (nonatomic, copy, nullable) NSString *privateKeyPath;
@property (nonatomic, copy, nullable) NSString *privateKeyPassphrase;
@property (nonatomic) SSHKitHostKeyPolicyKind hostKeyPolicyKind;
@property (nonatomic, copy, nullable) NSString *knownHostsPath;
@property (nonatomic) NSTimeInterval timeout;

- (instancetype)initWithHost:(NSString *)host username:(NSString *)username;

@end

NS_ASSUME_NONNULL_END
