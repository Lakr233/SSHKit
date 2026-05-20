#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

typedef NS_ENUM(NSInteger, GSSHAuthenticationKind) {
    GSSHAuthenticationKindPassword = 1,
    GSSHAuthenticationKindPrivateKeyFile = 2,
};

typedef NS_ENUM(NSInteger, GSSHHostKeyPolicyKind) {
    GSSHHostKeyPolicyKindAcceptAnyVerifiedHostKey = 1,
    GSSHHostKeyPolicyKindKnownHostsFile = 2,
};

@interface GSSHSessionConfiguration : NSObject <NSCopying>

@property (nonatomic, copy) NSString *host;
@property (nonatomic) uint16_t port;
@property (nonatomic, copy) NSString *username;
@property (nonatomic) GSSHAuthenticationKind authenticationKind;
@property (nonatomic, copy, nullable) NSString *password;
@property (nonatomic, copy, nullable) NSString *privateKeyPath;
@property (nonatomic, copy, nullable) NSString *privateKeyPassphrase;
@property (nonatomic) GSSHHostKeyPolicyKind hostKeyPolicyKind;
@property (nonatomic, copy, nullable) NSString *knownHostsPath;
@property (nonatomic) NSTimeInterval timeout;

- (instancetype)initWithHost:(NSString *)host username:(NSString *)username;

@end

NS_ASSUME_NONNULL_END
