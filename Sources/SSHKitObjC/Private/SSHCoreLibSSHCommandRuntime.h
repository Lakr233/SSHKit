#import <Foundation/Foundation.h>

#import <CLibSSH/CLibSSH.h>
#import <SSHKitObjC/SSHKitConnection.h>

#import "SSHCoreOpenSSHClient.h"

NS_ASSUME_NONNULL_BEGIN

@interface SSHCoreLibSSHCommandRuntime : NSObject

- (instancetype)initWithChannel:(ssh_channel)channel
                    workerQueue:(dispatch_queue_t)workerQueue
                   eventHandler:(SSHKitCommandEventHandler)eventHandler
                       onClosed:(SSHCoreCommandClosedBlock)onClosed;
- (void)start;
- (void)writeData:(NSData *)data completion:(SSHKitCompletion)completion;
- (void)sendEOFWithCompletion:(SSHKitCompletion)completion;
- (void)closeWithCompletion:(SSHKitCompletion)completion;
- (void)invalidateOnWorkerQueue;

@end

NS_ASSUME_NONNULL_END
