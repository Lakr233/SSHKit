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

typedef void (^SSHKitCompletion)(NSError *_Nullable error);

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

typedef void (^SSHKitCommandCompletion)(SSHKitCommandResult *_Nullable result, NSError *_Nullable error);
typedef void (^SSHKitShellCompletion)(SSHKitShell *_Nullable shell, NSError *_Nullable error);

@interface SSHKitConnection : NSObject

@property (nonatomic, copy, readonly) SSHKitConfiguration *configuration;

- (instancetype)initWithConfiguration:(SSHKitConfiguration *)configuration;
- (void)connectWithCompletion:(SSHKitCompletion)completion;
- (void)executeCommand:(NSString *)command completion:(SSHKitCommandCompletion)completion;
- (void)executePTYCommand:(NSString *)command completion:(SSHKitCommandCompletion)completion;
- (void)openShellWithTerminalType:(NSString *)terminalType
                          columns:(uint16_t)columns
                             rows:(uint16_t)rows
                     eventHandler:(SSHKitShellEventHandler)eventHandler
                       completion:(SSHKitShellCompletion)completion;
- (void)disconnectWithCompletion:(SSHKitCompletion)completion;

@end

NS_ASSUME_NONNULL_END
