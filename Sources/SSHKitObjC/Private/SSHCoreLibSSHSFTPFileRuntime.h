#import <Foundation/Foundation.h>

#import <CLibSSH/CLibSSH.h>
#import <SSHKitObjC/SSHKitConnection.h>

#import "SSHCoreOpenSSHClient.h"

NS_ASSUME_NONNULL_BEGIN

@class SSHCoreLibSSHSFTPRuntime;

@interface SSHCoreLibSSHSFTPFileRuntime : NSObject

- (instancetype)initWithFile:(sftp_file)file
                       owner:(SSHCoreLibSSHSFTPRuntime *)owner
                 workerQueue:(dispatch_queue_t)workerQueue
                      client:(SSHCoreOpenSSHClient *)client;
- (void)readDataWithMaximumLength:(NSUInteger)maximumLength completion:(SSHKitSFTPDataCompletion)completion;
- (void)writeData:(NSData *)data completion:(SSHKitCompletion)completion;
- (void)seekToOffset:(uint64_t)offset completion:(SSHKitCompletion)completion;
- (void)closeWithCompletion:(SSHKitCompletion)completion;
- (void)invalidateOnWorkerQueue;

@end

NS_ASSUME_NONNULL_END
