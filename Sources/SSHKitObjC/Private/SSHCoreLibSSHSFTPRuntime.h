#import <Foundation/Foundation.h>

#import <CLibSSH/CLibSSH.h>
#import <SSHKitObjC/SSHKitConnection.h>

#import "SSHCoreOpenSSHClient.h"

NS_ASSUME_NONNULL_BEGIN

@class SSHCoreLibSSHSFTPFileRuntime;

@interface SSHCoreLibSSHSFTPRuntime : NSObject

- (instancetype)initWithSession:(sftp_session)sftp
                    workerQueue:(dispatch_queue_t)workerQueue
                   closeHandler:(SSHCoreSFTPCloseHandler)closeHandler
                         client:(SSHCoreOpenSSHClient *)client;
- (void)listDirectory:(NSString *)path completion:(SSHKitSFTPListCompletion)completion;
- (void)realpath:(NSString *)path completion:(SSHKitSFTPStringCompletion)completion;
- (void)statPath:(NSString *)path followSymlink:(BOOL)followSymlink completion:(SSHKitSFTPAttributesCompletion)completion;
- (void)setPermissions:(uint32_t)permissions atPath:(NSString *)path completion:(SSHKitCompletion)completion;
- (void)fileSystemAttributesAtPath:(NSString *)path completion:(SSHKitSFTPFileSystemAttributesCompletion)completion;
- (void)createDirectoryAtPath:(NSString *)path permissions:(uint32_t)permissions completion:(SSHKitCompletion)completion;
- (void)removeDirectoryAtPath:(NSString *)path completion:(SSHKitCompletion)completion;
- (void)removeFileAtPath:(NSString *)path completion:(SSHKitCompletion)completion;
- (void)renamePath:(NSString *)sourcePath toPath:(NSString *)destinationPath completion:(SSHKitCompletion)completion;
- (void)readLinkAtPath:(NSString *)path completion:(SSHKitSFTPStringCompletion)completion;
- (void)createSymbolicLinkAtPath:(NSString *)linkPath targetPath:(NSString *)targetPath completion:(SSHKitCompletion)completion;
- (void)openFileAtPath:(NSString *)path flags:(SSHKitSFTPFileOpenFlags)flags permissions:(uint32_t)permissions completion:(SSHKitSFTPFileHandleCompletion)completion;
- (void)readFileAtPath:(NSString *)path completion:(SSHKitSFTPDataCompletion)completion;
- (void)writeData:(NSData *)data toFileAtPath:(NSString *)path completion:(SSHKitCompletion)completion;
- (void)downloadFileAtPath:(NSString *)remotePath toLocalPath:(NSString *)localPath resume:(BOOL)resume progress:(SSHKitSFTPProgressHandler)progress completion:(SSHKitCompletion)completion;
- (void)uploadFileAtPath:(NSString *)localPath toRemotePath:(NSString *)remotePath resume:(BOOL)resume progress:(SSHKitSFTPProgressHandler)progress completion:(SSHKitCompletion)completion;
- (void)closeWithCompletion:(SSHKitCompletion)completion;
- (void)invalidateOnWorkerQueue;
- (void)registerFileRuntime:(SSHCoreLibSSHSFTPFileRuntime *)fileRuntime;
- (void)unregisterFileRuntime:(SSHCoreLibSSHSFTPFileRuntime *)fileRuntime;
- (BOOL)isOpenOnWorkerQueue;

@end

NS_ASSUME_NONNULL_END
