#import <Foundation/Foundation.h>

#import <CLibSSH/CLibSSH.h>

#import "SSHCoreOpenSSHClient.h"

NS_ASSUME_NONNULL_BEGIN

@interface SSHCoreLibSSHLocalForwardRuntime : NSObject

- (instancetype)initWithSession:(ssh_session)session
                 listenerSocket:(int)listenerSocket
                      boundHost:(NSString *)boundHost
                      boundPort:(uint16_t)boundPort
                     targetHost:(nullable NSString *)targetHost
                     targetPort:(uint16_t)targetPort
                  socksUsername:(nullable NSString *)socksUsername
                  socksPassword:(nullable NSString *)socksPassword
                    workerQueue:(dispatch_queue_t)workerQueue
                   closeHandler:(SSHCoreTunnelCloseHandler)closeHandler
                         client:(SSHCoreOpenSSHClient *)client;
- (void)start;
- (void)closeWithCompletion:(SSHKitCompletion)completion;
- (void)invalidateOnWorkerQueue;

@end

NS_ASSUME_NONNULL_END
