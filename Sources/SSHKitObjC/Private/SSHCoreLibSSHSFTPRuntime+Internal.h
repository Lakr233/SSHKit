#import "SSHCoreLibSSHSFTPRuntime.h"

#import <CLibSSH/CLibSSH.h>
#import <SSHKitObjC/SSHKitConnection.h>

@class SSHCoreLibSSHSFTPFileRuntime;
@class SSHCoreOpenSSHClient;

NS_ASSUME_NONNULL_BEGIN

@interface SSHCoreLibSSHSFTPRuntime ()

@property (nonatomic, nullable) sftp_session sftp;
@property (nonatomic) dispatch_queue_t workerQueue;
@property (nonatomic, copy, nullable) SSHCoreSFTPCloseHandler closeHandler;
@property (nonatomic, weak, nullable) SSHCoreOpenSSHClient *client;
@property (nonatomic) BOOL closed;
@property (nonatomic) BOOL runningOperation;
@property (nonatomic) BOOL didCallCloseHandler;
@property (nonatomic) NSHashTable<SSHCoreLibSSHSFTPFileRuntime *> *fileRuntimes;

- (SSHKitSFTPAttributes *)attributesFromSFTPAttributes:(sftp_attributes)attributes;
- (BOOL)beginOperationWithError:(NSError **)error;
- (void)endOperation;

@end

NS_ASSUME_NONNULL_END
