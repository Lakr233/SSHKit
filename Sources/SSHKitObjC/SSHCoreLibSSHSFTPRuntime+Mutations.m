#import "SSHCoreLibSSHSFTPRuntime+Mutations.h"

#import "SSHCoreLibSSHSFTPRuntime+Internal.h"
#import "SSHCoreOpenSSHClient+Internal.h"

#import <SSHKitObjC/SSHKitError.h>

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wobjc-protocol-method-implementation"

@implementation SSHCoreLibSSHSFTPRuntime (Mutations)

- (void)setPermissions:(uint32_t)permissions atPath:(NSString *)path completion:(SSHKitCompletion)completion {
    dispatch_async(self.workerQueue, ^{
        NSError *startError = nil;
        if (![self beginOperationWithError:&startError]) {
            completion(startError);
            return;
        }

        int result = sftp_chmod(self.sftp, path.UTF8String, (mode_t)permissions);
        [self endOperation];
        completion(result == SSH_OK ? nil : [self.client sftpErrorForOperation:@"SFTP chmod" sftp:self.sftp]);
    });
}

- (void)createDirectoryAtPath:(NSString *)path permissions:(uint32_t)permissions completion:(SSHKitCompletion)completion {
    dispatch_async(self.workerQueue, ^{
        NSError *startError = nil;
        if (![self beginOperationWithError:&startError]) {
            completion(startError);
            return;
        }

        int result = sftp_mkdir(self.sftp, path.UTF8String, (mode_t)permissions);
        [self endOperation];
        completion(result == SSH_OK ? nil : [self.client sftpErrorForOperation:@"SFTP mkdir" sftp:self.sftp]);
    });
}

- (void)removeDirectoryAtPath:(NSString *)path completion:(SSHKitCompletion)completion {
    dispatch_async(self.workerQueue, ^{
        NSError *startError = nil;
        if (![self beginOperationWithError:&startError]) {
            completion(startError);
            return;
        }

        int result = sftp_rmdir(self.sftp, path.UTF8String);
        [self endOperation];
        completion(result == SSH_OK ? nil : [self.client sftpErrorForOperation:@"SFTP rmdir" sftp:self.sftp]);
    });
}

- (void)removeFileAtPath:(NSString *)path completion:(SSHKitCompletion)completion {
    dispatch_async(self.workerQueue, ^{
        NSError *startError = nil;
        if (![self beginOperationWithError:&startError]) {
            completion(startError);
            return;
        }

        int result = sftp_unlink(self.sftp, path.UTF8String);
        [self endOperation];
        completion(result == SSH_OK ? nil : [self.client sftpErrorForOperation:@"SFTP unlink" sftp:self.sftp]);
    });
}

- (void)renamePath:(NSString *)sourcePath toPath:(NSString *)destinationPath completion:(SSHKitCompletion)completion {
    dispatch_async(self.workerQueue, ^{
        NSError *startError = nil;
        if (![self beginOperationWithError:&startError]) {
            completion(startError);
            return;
        }

        int result = sftp_rename(self.sftp, sourcePath.UTF8String, destinationPath.UTF8String);
        [self endOperation];
        completion(result == SSH_OK ? nil : [self.client sftpErrorForOperation:@"SFTP rename" sftp:self.sftp]);
    });
}

- (void)createSymbolicLinkAtPath:(NSString *)linkPath targetPath:(NSString *)targetPath completion:(SSHKitCompletion)completion {
    dispatch_async(self.workerQueue, ^{
        NSError *startError = nil;
        if (![self beginOperationWithError:&startError]) {
            completion(startError);
            return;
        }

        int result = sftp_symlink(self.sftp, targetPath.UTF8String, linkPath.UTF8String);
        [self endOperation];
        completion(result == SSH_OK ? nil : [self.client sftpErrorForOperation:@"SFTP symlink" sftp:self.sftp]);
    });
}

@end

#pragma clang diagnostic pop
