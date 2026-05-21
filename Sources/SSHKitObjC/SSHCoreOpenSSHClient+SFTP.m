#import "SSHCoreOpenSSHClient+SFTP.h"

#import "SSHCoreOpenSSHClient+Internal.h"

#import <SSHKitObjC/SSHKitConfiguration.h>
#import <SSHKitObjC/SSHKitError.h>

#import "SSHCoreLibSSHSFTPRuntime.h"
#import "SSHKitSFTPClient+Private.h"

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wobjc-protocol-method-implementation"

@implementation SSHCoreOpenSSHClient (SFTP)

- (nullable SSHKitSFTPClient *)openSFTPWithCloseHandler:(SSHCoreSFTPCloseHandler)closeHandler error:(NSError **)error {
    [self emitLogLevel:SSHKitLogLevelInfo phase:@"sftp" message:@"SSH SFTP open started." metadata:@{}];
    if (self.session == NULL) {
        if (error) {
            *error = SSHKitMakeError(SSHKitErrorCodeInvalidState, @"SSH session is not connected.");
        }
        return nil;
    }

    sftp_session sftp = sftp_new(self.session);
    if (sftp == NULL) {
        if (error) {
            *error = [self libSSHErrorWithCode:SSHKitErrorCodeConnectionFailed fallback:@"Unable to allocate SFTP session."];
        }
        return nil;
    }

    if (sftp_init(sftp) != SSH_OK) {
        if (error) {
            *error = [self sftpErrorForOperation:@"SFTP init" sftp:sftp];
        }
        sftp_free(sftp);
        return nil;
    }

    __weak SSHCoreOpenSSHClient *weakSelf = self;
    SSHCoreLibSSHSFTPRuntime *runtime = [[SSHCoreLibSSHSFTPRuntime alloc] initWithSession:sftp
                                                                              workerQueue:self.worker.queue
                                                                             closeHandler:^{
        [weakSelf clearCurrentTask];
        closeHandler();
    }
                                                                                   client:self];
    [self.taskLock lock];
    self.currentTask = runtime;
    [self.taskLock unlock];
    [self emitLogLevel:SSHKitLogLevelInfo phase:@"sftp" message:@"SSH SFTP opened." metadata:@{}];
    return [[SSHKitSFTPClient alloc] initWithListBlock:^(NSString *path, SSHKitSFTPListCompletion completion) {
        [runtime listDirectory:path completion:completion];
    } realpathBlock:^(NSString *path, SSHKitSFTPStringCompletion completion) {
        [runtime realpath:path completion:completion];
    } statBlock:^(NSString *path, SSHKitSFTPAttributesCompletion completion) {
        [runtime statPath:path followSymlink:YES completion:completion];
    } lstatBlock:^(NSString *path, SSHKitSFTPAttributesCompletion completion) {
        [runtime statPath:path followSymlink:NO completion:completion];
    } setPermissionsBlock:^(NSString *path, uint32_t permissions, SSHKitCompletion completion) {
        [runtime setPermissions:permissions atPath:path completion:completion];
    } fileSystemAttributesBlock:^(NSString *path, SSHKitSFTPFileSystemAttributesCompletion completion) {
        [runtime fileSystemAttributesAtPath:path completion:completion];
    } createDirectoryBlock:^(NSString *path, uint32_t permissions, SSHKitCompletion completion) {
        [runtime createDirectoryAtPath:path permissions:permissions completion:completion];
    } removeDirectoryBlock:^(NSString *path, SSHKitCompletion completion) {
        [runtime removeDirectoryAtPath:path completion:completion];
    } removeFileBlock:^(NSString *path, SSHKitCompletion completion) {
        [runtime removeFileAtPath:path completion:completion];
    } renameBlock:^(NSString *sourcePath, NSString *destinationPath, SSHKitCompletion completion) {
        [runtime renamePath:sourcePath toPath:destinationPath completion:completion];
    } readLinkBlock:^(NSString *path, SSHKitSFTPStringCompletion completion) {
        [runtime readLinkAtPath:path completion:completion];
    } createSymbolicLinkBlock:^(NSString *targetPath, NSString *linkPath, SSHKitCompletion completion) {
        [runtime createSymbolicLinkAtPath:linkPath targetPath:targetPath completion:completion];
    } openFileBlock:^(NSString *path, SSHKitSFTPFileOpenFlags flags, uint32_t permissions, SSHKitSFTPFileHandleCompletion completion) {
        [runtime openFileAtPath:path flags:flags permissions:permissions completion:completion];
    } readFileBlock:^(NSString *path, SSHKitSFTPDataCompletion completion) {
        [runtime readFileAtPath:path completion:completion];
    } writeDataBlock:^(NSString *path, NSData *data, SSHKitCompletion completion) {
        [runtime writeData:data toFileAtPath:path completion:completion];
    } downloadBlock:^(NSString *remotePath, NSString *localPath, BOOL resume, SSHKitSFTPProgressHandler progress, SSHKitCompletion completion) {
        [runtime downloadFileAtPath:remotePath toLocalPath:localPath resume:resume progress:progress completion:completion];
    } uploadBlock:^(NSString *localPath, NSString *remotePath, BOOL resume, SSHKitSFTPProgressHandler progress, SSHKitCompletion completion) {
        [runtime uploadFileAtPath:localPath toRemotePath:remotePath resume:resume progress:progress completion:completion];
    } closeBlock:^(SSHKitCompletion completion) {
        [runtime closeWithCompletion:completion];
    }];
}

@end

#pragma clang diagnostic pop
