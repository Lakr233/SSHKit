#import <Foundation/Foundation.h>
#import <SSHKitObjC/GSSHSessionConfiguration.h>

NS_ASSUME_NONNULL_BEGIN

@interface GSSHCommandResult : NSObject

@property (nonatomic, copy, readonly) NSData *standardOutput;
@property (nonatomic, copy, readonly) NSData *standardError;
@property (nonatomic, readonly) int32_t exitStatus;

- (instancetype)initWithStandardOutput:(NSData *)standardOutput
                         standardError:(NSData *)standardError
                            exitStatus:(int32_t)exitStatus;

@end

typedef void (^GSSHCompletion)(NSError *_Nullable error);
typedef void (^GSSHCommandCompletion)(GSSHCommandResult *_Nullable result, NSError *_Nullable error);

@interface GSSHSession : NSObject

@property (nonatomic, copy, readonly) GSSHSessionConfiguration *configuration;

- (instancetype)initWithConfiguration:(GSSHSessionConfiguration *)configuration;
- (void)connectWithCompletion:(GSSHCompletion)completion;
- (void)executeCommand:(NSString *)command completion:(GSSHCommandCompletion)completion;
- (void)disconnectWithCompletion:(GSSHCompletion)completion;

@end

NS_ASSUME_NONNULL_END
