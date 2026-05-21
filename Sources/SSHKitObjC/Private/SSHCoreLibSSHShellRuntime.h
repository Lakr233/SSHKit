#import <Foundation/Foundation.h>

#import <CLibSSH/CLibSSH.h>
#import <SSHKitObjC/SSHKitConnection.h>

#import "SSHCoreOpenSSHClient.h"

NS_ASSUME_NONNULL_BEGIN

typedef void (^SSHCoreRuntimeLogBlock)(SSHKitLogLevel level, NSString *phase, NSString *message, NSDictionary<NSString *, NSString *> *metadata);

@interface SSHCoreLibSSHShellRuntime : NSObject

- (instancetype)initWithChannel:(ssh_channel)channel
                    workerQueue:(dispatch_queue_t)workerQueue
                   eventHandler:(SSHKitShellEventHandler)eventHandler
                       onClosed:(SSHCoreShellClosedBlock)onClosed
                       logBlock:(SSHCoreRuntimeLogBlock)logBlock;
- (void)start;
- (void)writeData:(NSData *)data completion:(SSHKitCompletion)completion;
- (void)resizeWithColumns:(uint16_t)columns rows:(uint16_t)rows completion:(SSHKitCompletion)completion;
- (void)closeWithCompletion:(SSHKitCompletion)completion;
- (void)invalidateOnWorkerQueue;

@end

NS_ASSUME_NONNULL_END
