#import <Foundation/Foundation.h>

@class SSHKitCommandResult;
@class SSHKitConfiguration;

NS_ASSUME_NONNULL_BEGIN

@interface SSHCoreOpenSSHClient : NSObject

- (instancetype)initWithConfiguration:(SSHKitConfiguration *)configuration;
- (BOOL)verifyConnectionWithError:(NSError **)error;
- (nullable SSHKitCommandResult *)executeCommand:(NSString *)command error:(NSError **)error;
- (void)cancelCurrentTask;

@end

NS_ASSUME_NONNULL_END
