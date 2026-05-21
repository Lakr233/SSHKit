#import <Foundation/Foundation.h>

#import <CLibSSH/CLibSSH.h>
#import <SSHKitObjC/SSHKitConnection.h>
#import <SSHKitObjC/SSHKitError.h>

#import "SSHCoreOpenSSHClient.h"

NS_ASSUME_NONNULL_BEGIN

@interface SSHCoreLibSSHTunnelRuntime : NSObject

- (instancetype)initWithChannel:(ssh_channel)channel
                    workerQueue:(dispatch_queue_t)workerQueue
                    isCancelled:(BOOL (^)(void))isCancelled
                   closeHandler:(SSHCoreTunnelCloseHandler)closeHandler;
- (void)readDataWithMaximumLength:(NSUInteger)maximumLength completion:(SSHKitTunnelReadCompletion)completion;
- (void)writeData:(NSData *)data completion:(SSHKitCompletion)completion;
- (void)closeWithCompletion:(SSHKitCompletion)completion;
- (BOOL)isTunnelCancelled;
- (NSError *)tunnelErrorWithCode:(SSHKitErrorCode)code fallback:(NSString *)fallback cancelled:(BOOL)cancelled;
- (void)closeAfterTerminalTunnelFailure;
- (void)invalidateOnWorkerQueue;

@end

NS_ASSUME_NONNULL_END
