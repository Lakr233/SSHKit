#import <Foundation/Foundation.h>
#import <SSHKitObjC/SSHKitConnection.h>

@class SSHKitCommandResult;
@class SSHKitConfiguration;
@class SSHKitCommand;
@class SSHKitShell;
@class SSHKitSFTPClient;
@class SSHKitPortForward;
@class SSHKitTunnelChannel;
@class SSHCoreSessionWorker;

typedef void (^SSHCoreShellClosedBlock)(int32_t exitStatus);
typedef void (^SSHCoreCommandClosedBlock)(int32_t exitStatus);
typedef void (^SSHCoreSFTPCloseHandler)(void);
typedef void (^SSHCoreTunnelCloseHandler)(void);

NS_ASSUME_NONNULL_BEGIN

@interface SSHCoreOpenSSHClient : NSObject

- (instancetype)initWithConfiguration:(SSHKitConfiguration *)configuration worker:(SSHCoreSessionWorker *)worker;
- (BOOL)verifyConnectionWithError:(NSError **)error;
- (nullable SSHKitAuthenticationDiscoveryResult *)discoverAuthenticationMethodsWithError:(NSError **)error;
- (nullable SSHKitCommandResult *)executeCommand:(NSString *)command error:(NSError **)error;
- (nullable SSHKitCommandResult *)executePTYCommand:(NSString *)command error:(NSError **)error;
- (nullable SSHKitCommand *)openCommand:(NSString *)command
                           eventHandler:(SSHKitCommandEventHandler)eventHandler
                               onClosed:(SSHCoreCommandClosedBlock)onClosed
                                  error:(NSError **)error;
- (nullable SSHKitShell *)openShellWithTerminalType:(NSString *)terminalType
                                            columns:(uint16_t)columns
                                               rows:(uint16_t)rows
                                       eventHandler:(SSHKitShellEventHandler)eventHandler
                                           onClosed:(SSHCoreShellClosedBlock)onClosed
                                              error:(NSError **)error;
- (nullable SSHKitSFTPClient *)openSFTPWithCloseHandler:(SSHCoreSFTPCloseHandler)closeHandler error:(NSError **)error;
- (nullable SSHKitTunnelChannel *)openDirectTCPChannelToHost:(NSString *)host
                                                       port:(uint16_t)port
                                               closeHandler:(SSHCoreTunnelCloseHandler)closeHandler
                                                      error:(NSError **)error;
- (nullable SSHKitPortForward *)startLocalForwardFromHost:(NSString *)localHost
                                                     port:(uint16_t)localPort
                                                   toHost:(NSString *)remoteHost
                                               targetPort:(uint16_t)remotePort
                                             closeHandler:(SSHCoreTunnelCloseHandler)closeHandler
                                                    error:(NSError **)error;
- (void)cancelCurrentTask;
- (void)cancelCurrentTaskAndWaitUntilExit;
- (void)closeSession;

@end

NS_ASSUME_NONNULL_END
