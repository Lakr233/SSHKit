#import <Foundation/Foundation.h>
#import <SSHKitObjC/SSHKitConfiguration.h>

NS_ASSUME_NONNULL_BEGIN

@interface SSHKitCommandResult : NSObject

@property (nonatomic, copy, readonly) NSData *standardOutput;
@property (nonatomic, copy, readonly) NSData *standardError;
@property (nonatomic, readonly) int32_t exitStatus;
@property (nonatomic, copy, nullable, readonly) NSString *exitSignal;

- (instancetype)initWithStandardOutput:(NSData *)standardOutput
                         standardError:(NSData *)standardError
                            exitStatus:(int32_t)exitStatus;
- (instancetype)initWithStandardOutput:(NSData *)standardOutput
                         standardError:(NSData *)standardError
                            exitStatus:(int32_t)exitStatus
                            exitSignal:(nullable NSString *)exitSignal;

@end

@class SSHKitSFTPAttributes;
@class SSHKitSFTPFileHandle;

@interface SSHKitSFTPEntry : NSObject

@property (nonatomic, copy, readonly) NSString *filename;
@property (nonatomic, nullable, readonly) SSHKitSFTPAttributes *attributes;

- (instancetype)initWithFilename:(NSString *)filename;
- (instancetype)initWithFilename:(NSString *)filename attributes:(nullable SSHKitSFTPAttributes *)attributes;

@end

@interface SSHKitSFTPAttributes : NSObject

@property (nonatomic, readonly) uint64_t size;
@property (nonatomic, readonly) uint32_t permissions;
@property (nonatomic, readonly) uint32_t uid;
@property (nonatomic, readonly) uint32_t gid;
@property (nonatomic, readonly) uint8_t type;
@property (nonatomic, nullable, readonly) NSDate *accessedAt;
@property (nonatomic, nullable, readonly) NSDate *modifiedAt;

- (instancetype)initWithSize:(uint64_t)size
                 permissions:(uint32_t)permissions
                         uid:(uint32_t)uid
                         gid:(uint32_t)gid
                        type:(uint8_t)type
                  accessedAt:(nullable NSDate *)accessedAt
                  modifiedAt:(nullable NSDate *)modifiedAt;

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

@interface SSHKitHostKeyDiscoveryResult : NSObject

@property (nonatomic, copy, readonly) NSString *host;
@property (nonatomic, readonly) uint16_t port;
@property (nonatomic, copy, readonly) NSString *fingerprint;

- (instancetype)initWithHost:(NSString *)host
                        port:(uint16_t)port
                 fingerprint:(NSString *)fingerprint;

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
@property (nonatomic, copy, nullable, readonly) NSString *exitSignal;

- (instancetype)initWithKind:(SSHKitCommandEventKind)kind data:(NSData *)data exitStatus:(int32_t)exitStatus;
- (instancetype)initWithKind:(SSHKitCommandEventKind)kind
                        data:(NSData *)data
                  exitStatus:(int32_t)exitStatus
                  exitSignal:(nullable NSString *)exitSignal;

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
typedef void (^SSHKitSFTPStringCompletion)(NSString *_Nullable value, NSError *_Nullable error);
typedef void (^SSHKitSFTPAttributesCompletion)(SSHKitSFTPAttributes *_Nullable attributes, NSError *_Nullable error);
typedef void (^SSHKitSFTPDataCompletion)(NSData *_Nullable data, NSError *_Nullable error);
typedef void (^SSHKitSFTPFileHandleCompletion)(SSHKitSFTPFileHandle *_Nullable handle, NSError *_Nullable error);
typedef void (^SSHKitSFTPFileSystemAttributesCompletion)(NSDictionary<NSString *, NSNumber *> *_Nullable attributes, NSError *_Nullable error);
typedef void (^SSHKitSFTPProgressHandler)(uint64_t completedBytes, uint64_t totalBytes);

typedef NS_OPTIONS(NSUInteger, SSHKitSFTPFileOpenFlags) {
    SSHKitSFTPFileOpenFlagRead = 1 << 0,
    SSHKitSFTPFileOpenFlagWrite = 1 << 1,
    SSHKitSFTPFileOpenFlagCreate = 1 << 2,
    SSHKitSFTPFileOpenFlagTruncate = 1 << 3,
    SSHKitSFTPFileOpenFlagAppend = 1 << 4,
};

@interface SSHKitSFTPFileHandle : NSObject

- (void)readDataWithMaximumLength:(NSUInteger)maximumLength completion:(SSHKitSFTPDataCompletion)completion;
- (void)writeData:(NSData *)data completion:(SSHKitCompletion)completion;
- (void)seekToOffset:(uint64_t)offset completion:(SSHKitCompletion)completion;
- (void)closeWithCompletion:(SSHKitCompletion)completion;

@end

@interface SSHKitSFTPClient : NSObject

- (void)listDirectory:(NSString *)path completion:(SSHKitSFTPListCompletion)completion;
- (void)realpath:(NSString *)path completion:(SSHKitSFTPStringCompletion)completion;
- (void)statPath:(NSString *)path completion:(SSHKitSFTPAttributesCompletion)completion;
- (void)lstatPath:(NSString *)path completion:(SSHKitSFTPAttributesCompletion)completion;
- (void)setPermissions:(uint32_t)permissions atPath:(NSString *)path completion:(SSHKitCompletion)completion;
- (void)fileSystemAttributesAtPath:(NSString *)path completion:(SSHKitSFTPFileSystemAttributesCompletion)completion;
- (void)createDirectoryAtPath:(NSString *)path permissions:(uint32_t)permissions completion:(SSHKitCompletion)completion;
- (void)removeDirectoryAtPath:(NSString *)path completion:(SSHKitCompletion)completion;
- (void)removeFileAtPath:(NSString *)path completion:(SSHKitCompletion)completion;
- (void)renamePath:(NSString *)sourcePath toPath:(NSString *)destinationPath completion:(SSHKitCompletion)completion;
- (void)readLinkAtPath:(NSString *)path completion:(SSHKitSFTPStringCompletion)completion;
- (void)createSymbolicLinkAtPath:(NSString *)linkPath targetPath:(NSString *)targetPath completion:(SSHKitCompletion)completion;
- (void)openFileAtPath:(NSString *)path flags:(SSHKitSFTPFileOpenFlags)flags permissions:(uint32_t)permissions completion:(SSHKitSFTPFileHandleCompletion)completion;
- (void)readFileAtPath:(NSString *)path completion:(SSHKitSFTPDataCompletion)completion;
- (void)writeData:(NSData *)data toFileAtPath:(NSString *)path completion:(SSHKitCompletion)completion;
- (void)downloadFileAtPath:(NSString *)remotePath toLocalPath:(NSString *)localPath completion:(SSHKitCompletion)completion;
- (void)downloadFileAtPath:(NSString *)remotePath toLocalPath:(NSString *)localPath progress:(nullable SSHKitSFTPProgressHandler)progress completion:(SSHKitCompletion)completion;
- (void)resumeDownloadFileAtPath:(NSString *)remotePath toLocalPath:(NSString *)localPath progress:(nullable SSHKitSFTPProgressHandler)progress completion:(SSHKitCompletion)completion;
- (void)uploadFileAtPath:(NSString *)localPath toRemotePath:(NSString *)remotePath completion:(SSHKitCompletion)completion;
- (void)uploadFileAtPath:(NSString *)localPath toRemotePath:(NSString *)remotePath progress:(nullable SSHKitSFTPProgressHandler)progress completion:(SSHKitCompletion)completion;
- (void)resumeUploadFileAtPath:(NSString *)localPath toRemotePath:(NSString *)remotePath progress:(nullable SSHKitSFTPProgressHandler)progress completion:(SSHKitCompletion)completion;
- (void)closeWithCompletion:(SSHKitCompletion)completion;

@end

typedef void (^SSHKitTunnelReadCompletion)(NSData *_Nullable data, NSError *_Nullable error);

@interface SSHKitTunnelChannel : NSObject

- (void)readDataWithMaximumLength:(NSUInteger)maximumLength completion:(SSHKitTunnelReadCompletion)completion;
- (void)writeData:(NSData *)data completion:(SSHKitCompletion)completion;
- (void)closeWithCompletion:(SSHKitCompletion)completion;

@end

@interface SSHKitPortForward : NSObject

@property (nonatomic, copy, readonly) NSString *boundHost;
@property (nonatomic, readonly) uint16_t boundPort;

- (void)closeWithCompletion:(SSHKitCompletion)completion;

@end

typedef void (^SSHKitCommandCompletion)(SSHKitCommandResult *_Nullable result, NSError *_Nullable error);
typedef void (^SSHKitStreamingCommandCompletion)(SSHKitCommand *_Nullable command, NSError *_Nullable error);
typedef void (^SSHKitShellCompletion)(SSHKitShell *_Nullable shell, NSError *_Nullable error);
typedef void (^SSHKitSFTPCompletion)(SSHKitSFTPClient *_Nullable client, NSError *_Nullable error);
typedef void (^SSHKitTunnelChannelCompletion)(SSHKitTunnelChannel *_Nullable channel, NSError *_Nullable error);
typedef void (^SSHKitPortForwardCompletion)(SSHKitPortForward *_Nullable forward, NSError *_Nullable error);
typedef void (^SSHKitAuthenticationDiscoveryCompletion)(SSHKitAuthenticationDiscoveryResult *_Nullable result, NSError *_Nullable error);
typedef void (^SSHKitHostKeyDiscoveryCompletion)(SSHKitHostKeyDiscoveryResult *_Nullable result, NSError *_Nullable error);

@interface SSHKitConnection : NSObject

@property (nonatomic, copy, readonly) SSHKitConfiguration *configuration;
@property (nonatomic, copy, nullable, readonly) NSString *hostKeySHA256Fingerprint;

- (instancetype)initWithConfiguration:(SSHKitConfiguration *)configuration;
- (void)connectWithCompletion:(SSHKitCompletion)completion;
- (void)discoverAuthenticationMethodsWithCompletion:(SSHKitAuthenticationDiscoveryCompletion)completion;
- (void)discoverHostKeyWithCompletion:(SSHKitHostKeyDiscoveryCompletion)completion;
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
- (void)startLocalForwardFromHost:(NSString *)localHost
                              port:(uint16_t)localPort
                            toHost:(NSString *)remoteHost
                        targetPort:(uint16_t)remotePort
                        completion:(SSHKitPortForwardCompletion)completion;
- (void)startRemoteForwardFromHost:(NSString *)remoteHost
                               port:(uint16_t)remotePort
                             toHost:(NSString *)localHost
                         targetPort:(uint16_t)localPort
                         completion:(SSHKitPortForwardCompletion)completion;
- (void)startDynamicForwardFromHost:(NSString *)localHost
                                port:(uint16_t)localPort
                            username:(nullable NSString *)username
                            password:(nullable NSString *)password
                          completion:(SSHKitPortForwardCompletion)completion;
- (void)disconnectWithCompletion:(SSHKitCompletion)completion;

@end

NS_ASSUME_NONNULL_END
