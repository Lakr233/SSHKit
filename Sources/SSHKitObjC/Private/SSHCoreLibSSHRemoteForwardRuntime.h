#import <Foundation/Foundation.h>

#import <CLibSSH/CLibSSH.h>

#import "SSHCoreOpenSSHClient.h"

NS_ASSUME_NONNULL_BEGIN

@interface SSHCoreLibSSHRemoteForwardRuntime : NSObject

- (instancetype)initWithSession:(ssh_session)session
                     remoteHost:(NSString *)remoteHost
                     remotePort:(uint16_t)remotePort
                      boundPort:(uint16_t)boundPort
                     targetHost:(NSString *)targetHost
                     targetPort:(uint16_t)targetPort
                    workerQueue:(dispatch_queue_t)workerQueue
                   closeHandler:(SSHCoreTunnelCloseHandler)closeHandler
                         client:(SSHCoreOpenSSHClient *)client;
- (void)start;
- (void)closeWithCompletion:(SSHKitCompletion)completion;
- (void)invalidateOnWorkerQueue;

@end

NS_ASSUME_NONNULL_END
