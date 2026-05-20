#import <Foundation/Foundation.h>
#import <SSHKitObjC/SSHKitConfiguration.h>

NS_ASSUME_NONNULL_BEGIN

@interface SSHKitCommandResult : NSObject

@property (nonatomic, copy, readonly) NSData *standardOutput;
@property (nonatomic, copy, readonly) NSData *standardError;
@property (nonatomic, readonly) int32_t exitStatus;

- (instancetype)initWithStandardOutput:(NSData *)standardOutput
                         standardError:(NSData *)standardError
                            exitStatus:(int32_t)exitStatus;

@end

@interface SSHKitSFTPEntry : NSObject

@property (nonatomic, copy, readonly) NSString *filename;

- (instancetype)initWithFilename:(NSString *)filename;

@end

typedef void (^SSHKitCompletion)(NSError *_Nullable error);

typedef NS_ENUM(NSInteger, SSHKitAuthenticationMethod) {
    SSHKitAuthenticationMethodNone = 1,
    SSHKitAuthenticationMethodPassword = 2,
    SSHKitAuthenticationMethodPublicKey = 3,
    SSHKitAuthenticationMethodHostBased = 4,
    SSHKitAuthenticationMethodKeyboardInteractive = 5,
    SSHKitAuthenticationMethodGSSAPI = 6,
};

@interface SSHKitAuthenticationDiscoveryResult : NSObject

@property (nonatomic, copy, readonly) NSArray<NSNumber *> *methods;
@property (nonatomic, copy, nullable, readonly) NSString *issueBanner;
@property (nonatomic, copy, nullable, readonly) NSString *serverBanner;

- (instancetype)initWithMethods:(NSArray<NSNumber *> *)methods
                    issueBanner:(nullable NSString *)issueBanner
                   serverBanner:(nullable NSString *)serverBanner;

@end

typedef NS_ENUM(NSInteger, SSHKitCommandEventKind) {
    SSHKitCommandEventKindStandardOutput = 0,
    SSHKitCommandEventKindStandardError = 1,
    SSHKitCommandEventKindClosed = 2,
};

@interface SSHKitCommandEvent : NSObject

@property (nonatomic, readonly) SSHKitCommandEventKind kind;
@property (nonatomic, copy, readonly) NSData *data;
@property (nonatomic, readonly) int32_t exitStatus;

- (instancetype)initWithKind:(SSHKitCommandEventKind)kind data:(NSData *)data exitStatus:(int32_t)exitStatus;

@end

typedef void (^SSHKitCommandEventHandler)(SSHKitCommandEvent *event);

@interface SSHKitCommand : NSObject

- (void)writeData:(NSData *)data completion:(SSHKitCompletion)completion;
- (void)sendEOFWithCompletion:(SSHKitCompletion)completion;
- (void)closeWithCompletion:(SSHKitCompletion)completion;

@end

typedef NS_ENUM(NSInteger, SSHKitShellEventKind) {
    SSHKitShellEventKindStandardOutput = 0,
    SSHKitShellEventKindStandardError = 1,
    SSHKitShellEventKindClosed = 2,
};

@interface SSHKitShellEvent : NSObject

@property (nonatomic, readonly) SSHKitShellEventKind kind;
@property (nonatomic, copy, readonly) NSData *data;
@property (nonatomic, readonly) int32_t exitStatus;

- (instancetype)initWithKind:(SSHKitShellEventKind)kind data:(NSData *)data exitStatus:(int32_t)exitStatus;

@end

typedef void (^SSHKitShellEventHandler)(SSHKitShellEvent *event);

@interface SSHKitShell : NSObject

- (void)writeData:(NSData *)data completion:(SSHKitCompletion)completion;
- (void)resizeWithColumns:(uint16_t)columns rows:(uint16_t)rows completion:(SSHKitCompletion)completion;
- (void)closeWithCompletion:(SSHKitCompletion)completion;

@end

typedef void (^SSHKitSFTPListCompletion)(NSArray<SSHKitSFTPEntry *> *_Nullable entries, NSError *_Nullable error);

@interface SSHKitSFTPClient : NSObject

- (void)listDirectory:(NSString *)path completion:(SSHKitSFTPListCompletion)completion;
- (void)downloadFileAtPath:(NSString *)remotePath toLocalPath:(NSString *)localPath completion:(SSHKitCompletion)completion;
- (void)uploadFileAtPath:(NSString *)localPath toRemotePath:(NSString *)remotePath completion:(SSHKitCompletion)completion;
- (void)closeWithCompletion:(SSHKitCompletion)completion;

@end

typedef void (^SSHKitTunnelReadCompletion)(NSData *_Nullable data, NSError *_Nullable error);

@interface SSHKitTunnelChannel : NSObject

- (void)readDataWithMaximumLength:(NSUInteger)maximumLength completion:(SSHKitTunnelReadCompletion)completion;
- (void)writeData:(NSData *)data completion:(SSHKitCompletion)completion;
- (void)closeWithCompletion:(SSHKitCompletion)completion;

@end

typedef void (^SSHKitCommandCompletion)(SSHKitCommandResult *_Nullable result, NSError *_Nullable error);
typedef void (^SSHKitStreamingCommandCompletion)(SSHKitCommand *_Nullable command, NSError *_Nullable error);
typedef void (^SSHKitShellCompletion)(SSHKitShell *_Nullable shell, NSError *_Nullable error);
typedef void (^SSHKitSFTPCompletion)(SSHKitSFTPClient *_Nullable client, NSError *_Nullable error);
typedef void (^SSHKitTunnelChannelCompletion)(SSHKitTunnelChannel *_Nullable channel, NSError *_Nullable error);
typedef void (^SSHKitAuthenticationDiscoveryCompletion)(SSHKitAuthenticationDiscoveryResult *_Nullable result, NSError *_Nullable error);

@interface SSHKitConnection : NSObject

@property (nonatomic, copy, readonly) SSHKitConfiguration *configuration;

- (instancetype)initWithConfiguration:(SSHKitConfiguration *)configuration;
- (void)connectWithCompletion:(SSHKitCompletion)completion;
- (void)discoverAuthenticationMethodsWithCompletion:(SSHKitAuthenticationDiscoveryCompletion)completion;
- (void)executeCommand:(NSString *)command completion:(SSHKitCommandCompletion)completion;
- (void)executePTYCommand:(NSString *)command completion:(SSHKitCommandCompletion)completion;
- (void)openCommand:(NSString *)command
       eventHandler:(SSHKitCommandEventHandler)eventHandler
         completion:(SSHKitStreamingCommandCompletion)completion;
- (void)openShellWithTerminalType:(NSString *)terminalType
                          columns:(uint16_t)columns
                             rows:(uint16_t)rows
                     eventHandler:(SSHKitShellEventHandler)eventHandler
                       completion:(SSHKitShellCompletion)completion;
- (void)openSFTPWithCompletion:(SSHKitSFTPCompletion)completion;
- (void)openDirectTCPChannelToHost:(NSString *)host
                              port:(uint16_t)port
                        completion:(SSHKitTunnelChannelCompletion)completion;
- (void)disconnectWithCompletion:(SSHKitCompletion)completion;

@end

NS_ASSUME_NONNULL_END
