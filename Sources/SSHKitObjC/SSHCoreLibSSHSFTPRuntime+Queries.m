#import "SSHCoreLibSSHSFTPRuntime+Queries.h"

#import "SSHCoreLibSSHSFTPRuntime+Internal.h"
#import "SSHCoreOpenSSHClient+Internal.h"
#import "SSHKitSFTPClient+Private.h"

#import <SSHKitObjC/SSHKitError.h>

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wobjc-protocol-method-implementation"

@implementation SSHCoreLibSSHSFTPRuntime (Queries)

- (void)listDirectory:(NSString *)path completion:(SSHKitSFTPListCompletion)completion {
    dispatch_async(self.workerQueue, ^{
        NSError *startError = nil;
        if (![self beginOperationWithError:&startError]) {
            completion(nil, startError);
            return;
        }

        NSMutableArray<SSHKitSFTPEntry *> *entries = [[NSMutableArray alloc] init];
        sftp_dir directory = sftp_opendir(self.sftp, path.UTF8String);
        if (directory == NULL) {
            NSError *error = [self.client sftpErrorForOperation:@"SFTP list" sftp:self.sftp];
            [self endOperation];
            completion(nil, error);
            return;
        }

        while (YES) {
            sftp_attributes attributes = sftp_readdir(self.sftp, directory);
            if (attributes == NULL) {
                break;
            }

            if (attributes->name != NULL) {
                NSString *filename = [NSString stringWithUTF8String:attributes->name];
                if (![filename isEqualToString:@"."] && ![filename isEqualToString:@".."]) {
                    [entries addObject:[[SSHKitSFTPEntry alloc] initWithFilename:filename attributes:[self attributesFromSFTPAttributes:attributes]]];
                }
            }
            sftp_attributes_free(attributes);
        }

        BOOL reachedEOF = sftp_dir_eof(directory) != 0;
        int readdirStatus = reachedEOF ? SSH_FX_OK : sftp_get_error(self.sftp);
        sftp_closedir(directory);
        [self endOperation];
        if (!reachedEOF) {
            completion(nil, [self.client sftpErrorForOperation:@"SFTP list" status:readdirStatus]);
            return;
        }

        completion(entries, nil);
    });
}

- (void)realpath:(NSString *)path completion:(SSHKitSFTPStringCompletion)completion {
    dispatch_async(self.workerQueue, ^{
        NSError *startError = nil;
        if (![self beginOperationWithError:&startError]) {
            completion(nil, startError);
            return;
        }

        char *canonicalPath = sftp_canonicalize_path(self.sftp, path.UTF8String);
        [self endOperation];
        if (canonicalPath == NULL) {
            completion(nil, [self.client sftpErrorForOperation:@"SFTP realpath" sftp:self.sftp]);
            return;
        }

        NSString *value = [NSString stringWithUTF8String:canonicalPath];
        free(canonicalPath);
        completion(value, nil);
    });
}

- (void)statPath:(NSString *)path followSymlink:(BOOL)followSymlink completion:(SSHKitSFTPAttributesCompletion)completion {
    dispatch_async(self.workerQueue, ^{
        NSError *startError = nil;
        if (![self beginOperationWithError:&startError]) {
            completion(nil, startError);
            return;
        }

        sftp_attributes attributes = followSymlink ? sftp_stat(self.sftp, path.UTF8String) : sftp_lstat(self.sftp, path.UTF8String);
        [self endOperation];
        if (attributes == NULL) {
            completion(nil, [self.client sftpErrorForOperation:followSymlink ? @"SFTP stat" : @"SFTP lstat" sftp:self.sftp]);
            return;
        }

        SSHKitSFTPAttributes *result = [self attributesFromSFTPAttributes:attributes];
        sftp_attributes_free(attributes);
        completion(result, nil);
    });
}

- (void)fileSystemAttributesAtPath:(NSString *)path completion:(SSHKitSFTPFileSystemAttributesCompletion)completion {
    dispatch_async(self.workerQueue, ^{
        NSError *startError = nil;
        if (![self beginOperationWithError:&startError]) {
            completion(nil, startError);
            return;
        }

        sftp_statvfs_t statvfs = sftp_statvfs(self.sftp, path.UTF8String);
        [self endOperation];
        if (statvfs == NULL) {
            completion(nil, [self.client sftpErrorForOperation:@"SFTP statvfs" sftp:self.sftp]);
            return;
        }

        NSDictionary<NSString *, NSNumber *> *attributes = @{
            @"blockSize": @(statvfs->f_bsize),
            @"fundamentalBlockSize": @(statvfs->f_frsize),
            @"blocks": @(statvfs->f_blocks),
            @"freeBlocks": @(statvfs->f_bfree),
            @"availableBlocks": @(statvfs->f_bavail),
            @"files": @(statvfs->f_files),
            @"freeFiles": @(statvfs->f_ffree),
        };
        sftp_statvfs_free(statvfs);
        completion(attributes, nil);
    });
}

- (void)readLinkAtPath:(NSString *)path completion:(SSHKitSFTPStringCompletion)completion {
    dispatch_async(self.workerQueue, ^{
        NSError *startError = nil;
        if (![self beginOperationWithError:&startError]) {
            completion(nil, startError);
            return;
        }

        char *target = sftp_readlink(self.sftp, path.UTF8String);
        [self endOperation];
        if (target == NULL) {
            completion(nil, [self.client sftpErrorForOperation:@"SFTP readlink" sftp:self.sftp]);
            return;
        }

        NSString *value = [NSString stringWithUTF8String:target];
        free(target);
        completion(value, nil);
    });
}

@end

#pragma clang diagnostic pop
