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
typedef void (^SSHKitCommandCompletion)(SSHKitCommandResult *_Nullable result, NSError *_Nullable error);

@interface SSHKitConnection : NSObject

@property (nonatomic, copy, readonly) SSHKitConfiguration *configuration;

- (instancetype)initWithConfiguration:(SSHKitConfiguration *)configuration;
- (void)connectWithCompletion:(SSHKitCompletion)completion;
- (void)executeCommand:(NSString *)command completion:(SSHKitCommandCompletion)completion;
- (void)disconnectWithCompletion:(SSHKitCompletion)completion;

@end

NS_ASSUME_NONNULL_END
