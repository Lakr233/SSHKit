#import <Foundation/Foundation.h>
#import <SSHKitObjC/SSHKitConnection.h>

@class SSHKitCommandResult;
@class SSHKitConfiguration;
@class SSHKitShell;

typedef void (^SSHCoreShellClosedBlock)(int32_t exitStatus);

NS_ASSUME_NONNULL_BEGIN

@interface SSHCoreOpenSSHClient : NSObject

- (instancetype)initWithConfiguration:(SSHKitConfiguration *)configuration;
- (BOOL)verifyConnectionWithError:(NSError **)error;
- (nullable SSHKitCommandResult *)executeCommand:(NSString *)command error:(NSError **)error;
- (nullable SSHKitCommandResult *)executePTYCommand:(NSString *)command error:(NSError **)error;
- (nullable SSHKitShell *)openShellWithTerminalType:(NSString *)terminalType
                                            columns:(uint16_t)columns
                                               rows:(uint16_t)rows
                                       eventHandler:(SSHKitShellEventHandler)eventHandler
                                           onClosed:(SSHCoreShellClosedBlock)onClosed
                                              error:(NSError **)error;
- (void)cancelCurrentTask;

@end

NS_ASSUME_NONNULL_END
