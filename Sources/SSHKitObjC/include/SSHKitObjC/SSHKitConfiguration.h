#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

typedef NS_ENUM(NSInteger, SSHKitAuthenticationKind) {
    SSHKitAuthenticationKindPassword = 1,
    SSHKitAuthenticationKindPrivateKeyFile = 2,
    SSHKitAuthenticationKindKeyboardInteractive = 3,
    SSHKitAuthenticationKindAgent = 4,
};

@class SSHKitKeyboardInteractivePrompt;

typedef NSArray<NSString *> *_Nullable (^SSHKitKeyboardInteractiveResponder)(
    NSString *name,
    NSString *instruction,
    NSArray<SSHKitKeyboardInteractivePrompt *> *prompts
);

@interface SSHKitKeyboardInteractivePrompt : NSObject

@property (nonatomic, copy, readonly) NSString *prompt;
@property (nonatomic, readonly) BOOL echo;

- (instancetype)initWithPrompt:(NSString *)prompt echo:(BOOL)echo;

@end

@interface SSHKitAuthentication : NSObject <NSCopying>

@property (nonatomic, readonly) SSHKitAuthenticationKind kind;
@property (nonatomic, copy, nullable, readonly) NSString *password;
@property (nonatomic, copy, nullable, readonly) NSString *privateKeyPath;
@property (nonatomic, copy, nullable, readonly) NSString *privateKeyPassphrase;
@property (nonatomic, copy, nullable, readonly) SSHKitKeyboardInteractiveResponder keyboardInteractiveResponder;
@property (nonatomic, copy, nullable, readonly) NSString *identityAgentPath;

+ (instancetype)password:(NSString *)password;
+ (instancetype)privateKeyFileAtPath:(NSString *)path passphrase:(nullable NSString *)passphrase;
+ (instancetype)keyboardInteractiveWithResponder:(SSHKitKeyboardInteractiveResponder)responder;
+ (instancetype)agent;
+ (instancetype)agentWithSocketPath:(nullable NSString *)socketPath;

@end

typedef NS_ENUM(NSInteger, SSHKitHostKeyPolicyKind) {
    SSHKitHostKeyPolicyKindInsecureAcceptAnyHostKey = 1,
    SSHKitHostKeyPolicyKindKnownHostsFile = 2,
    SSHKitHostKeyPolicyKindPinnedFingerprint = 3,
    SSHKitHostKeyPolicyKindTrustedFingerprint = 4,
};

@interface SSHKitHostTrustStore : NSObject

- (nullable NSString *)fingerprintForHost:(NSString *)host port:(uint16_t)port error:(NSError *_Nullable *_Nullable)error;
- (BOOL)saveFingerprint:(NSString *)fingerprint host:(NSString *)host port:(uint16_t)port error:(NSError *_Nullable *_Nullable)error;
- (BOOL)removeFingerprintForHost:(NSString *)host port:(uint16_t)port error:(NSError *_Nullable *_Nullable)error;

@end

@interface SSHKitMemoryTrustStore : SSHKitHostTrustStore

- (instancetype)initWithFingerprints:(nullable NSDictionary<NSString *, NSString *> *)fingerprints;

@end

@interface SSHKitKeychainTrustStore : SSHKitHostTrustStore

@property (class, nonatomic, copy, readonly) NSString *defaultService;

- (instancetype)initWithService:(NSString *)service;

@end

@interface SSHKitHostKeyPolicy : NSObject <NSCopying>

@property (nonatomic, readonly) SSHKitHostKeyPolicyKind kind;
@property (nonatomic, copy, nullable, readonly) NSString *knownHostsPath;
@property (nonatomic, copy, nullable, readonly) NSString *pinnedFingerprint;
@property (nonatomic, readonly, nullable) SSHKitHostTrustStore *trustStore;

+ (instancetype)knownHostsFile:(NSString *)path;
+ (instancetype)pinnedFingerprint:(NSString *)fingerprint;
+ (instancetype)trustStore:(SSHKitHostTrustStore *)trustStore;
+ (instancetype)keychainTrustStoreWithService:(NSString *)service;
+ (instancetype)memoryTrustStore;
+ (instancetype)insecureAcceptAnyHostKey;

@end

typedef NS_ENUM(NSInteger, SSHKitLogLevel) {
    SSHKitLogLevelDebug = 0,
    SSHKitLogLevelInfo = 1,
    SSHKitLogLevelWarning = 2,
    SSHKitLogLevelError = 3,
};

typedef NS_ENUM(NSInteger, SSHKitProxyRouteKind) {
    SSHKitProxyRouteKindNone = 0,
    SSHKitProxyRouteKindSOCKS5 = 1,
    SSHKitProxyRouteKindHTTPConnect = 2,
    SSHKitProxyRouteKindProxyJump = 3,
};

@interface SSHKitLogEvent : NSObject

@property (nonatomic, readonly) SSHKitLogLevel level;
@property (nonatomic, copy, readonly) NSString *phase;
@property (nonatomic, copy, readonly) NSString *message;
@property (nonatomic, copy, readonly) NSDictionary<NSString *, NSString *> *metadata;
@property (nonatomic, readonly) NSDate *timestamp;

- (instancetype)initWithLevel:(SSHKitLogLevel)level
                        phase:(NSString *)phase
                      message:(NSString *)message
                     metadata:(NSDictionary<NSString *, NSString *> *)metadata;

@end

typedef void (^SSHKitLogHandler)(SSHKitLogEvent *event);

@interface SSHKitConfiguration : NSObject <NSCopying>

@property (nonatomic, copy) NSString *host;
@property (nonatomic) uint16_t port;
@property (nonatomic, copy) NSString *username;
@property (nonatomic, copy, nullable) SSHKitAuthentication *authentication;
@property (nonatomic) SSHKitAuthenticationKind authenticationKind;
@property (nonatomic, copy, nullable) NSString *password;
@property (nonatomic, copy, nullable) NSString *privateKeyPath;
@property (nonatomic, copy, nullable) NSString *privateKeyPassphrase;
@property (nonatomic, copy, nullable) SSHKitKeyboardInteractiveResponder keyboardInteractiveResponder;
@property (nonatomic, copy, nullable) NSString *identityAgentPath;
@property (nonatomic, copy, nullable) SSHKitHostKeyPolicy *hostKeyPolicy;
@property (nonatomic) SSHKitHostKeyPolicyKind hostKeyPolicyKind;
@property (nonatomic, copy, nullable) NSString *knownHostsPath;
@property (nonatomic, copy, nullable) NSString *pinnedHostKeySHA256Fingerprint;
@property (nonatomic, copy, nullable) NSString *trustedHostKeySHA256Fingerprint;
@property (nonatomic, copy, nullable) NSString *hostKeyTrustStoreError;
@property (nonatomic) NSTimeInterval timeout;
@property (nonatomic, copy, nullable) SSHKitLogHandler logHandler;
@property (nonatomic) SSHKitProxyRouteKind proxyRouteKind;
@property (nonatomic, copy, nullable) NSString *proxyHost;
@property (nonatomic) uint16_t proxyPort;
@property (nonatomic, copy, nullable) NSString *proxyUsername;
@property (nonatomic, copy, nullable) NSString *proxyPassword;
@property (nonatomic, copy, nullable) SSHKitConfiguration *proxyJumpConfiguration NS_SWIFT_NAME(proxyJump);
@property (nonatomic, copy, nullable) NSString *keyExchangeAlgorithms;
@property (nonatomic, copy, nullable) NSString *hostKeyAlgorithms;
@property (nonatomic, copy, nullable) NSString *publicKeyAcceptedAlgorithms;
@property (nonatomic, copy, nullable) NSString *ciphersClientToServer;
@property (nonatomic, copy, nullable) NSString *ciphersServerToClient;
@property (nonatomic, copy, nullable) NSString *macsClientToServer;
@property (nonatomic, copy, nullable) NSString *macsServerToClient;
@property (nonatomic, copy, nullable) NSNumber *minimumRSAKeySize;

- (instancetype)initWithHost:(NSString *)host username:(NSString *)username;

@end

NS_ASSUME_NONNULL_END
