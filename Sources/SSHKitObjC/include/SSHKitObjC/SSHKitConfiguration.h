#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

typedef NS_ENUM(NSInteger, SSHKitAuthenticationKind) {
    SSHKitAuthenticationKindPassword = 1,
    SSHKitAuthenticationKindPrivateKeyFile = 2,
    SSHKitAuthenticationKindKeyboardInteractive = 3,
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

typedef NS_ENUM(NSInteger, SSHKitHostKeyPolicyKind) {
    SSHKitHostKeyPolicyKindInsecureAcceptAnyHostKey = 1,
    SSHKitHostKeyPolicyKindKnownHostsFile = 2,
};

typedef NS_ENUM(NSInteger, SSHKitLogLevel) {
    SSHKitLogLevelDebug = 0,
    SSHKitLogLevelInfo = 1,
    SSHKitLogLevelWarning = 2,
    SSHKitLogLevelError = 3,
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
@property (nonatomic) SSHKitAuthenticationKind authenticationKind;
@property (nonatomic, copy, nullable) NSString *password;
@property (nonatomic, copy, nullable) NSString *privateKeyPath;
@property (nonatomic, copy, nullable) NSString *privateKeyPassphrase;
@property (nonatomic, copy, nullable) SSHKitKeyboardInteractiveResponder keyboardInteractiveResponder;
@property (nonatomic) SSHKitHostKeyPolicyKind hostKeyPolicyKind;
@property (nonatomic, copy, nullable) NSString *knownHostsPath;
@property (nonatomic) NSTimeInterval timeout;
@property (nonatomic, copy, nullable) SSHKitLogHandler logHandler;

- (instancetype)initWithHost:(NSString *)host username:(NSString *)username;

@end

NS_ASSUME_NONNULL_END
