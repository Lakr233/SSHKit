#import "SSHCoreLibSSHSFTPRuntime+Transfer.h"

#import "SSHCoreLibSSHSFTPRuntime+Internal.h"
#import "SSHCoreOpenSSHClient+Internal.h"

#import <SSHKitObjC/SSHKitError.h>

#include <sys/stat.h>
#include <unistd.h>

static const uint64_t SSHCoreSFTPMaximumReadFileSize = 64 * 1024 * 1024;

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wobjc-protocol-method-implementation"

@implementation SSHCoreLibSSHSFTPRuntime (Transfer)

- (void)readFileAtPath:(NSString *)path completion:(SSHKitSFTPDataCompletion)completion {
    dispatch_async(self.workerQueue, ^{
        NSError *startError = nil;
        if (![self beginOperationWithError:&startError]) {
            completion(nil, startError);
            return;
        }

        NSMutableData *data = [[NSMutableData alloc] init];
        NSError *error = [self readRemotePath:path intoData:data progress:nil];
        [self endOperation];
        completion(error == nil ? data : nil, error);
    });
}

- (void)writeData:(NSData *)data toFileAtPath:(NSString *)path completion:(SSHKitCompletion)completion {
    dispatch_async(self.workerQueue, ^{
        NSError *startError = nil;
        if (![self beginOperationWithError:&startError]) {
            completion(startError);
            return;
        }

        NSError *error = [self writeData:data toRemotePath:path progress:nil];
        [self endOperation];
        completion(error);
    });
}

- (void)downloadFileAtPath:(NSString *)remotePath toLocalPath:(NSString *)localPath resume:(BOOL)resume progress:(SSHKitSFTPProgressHandler)progress completion:(SSHKitCompletion)completion {
    dispatch_async(self.workerQueue, ^{
        NSError *startError = nil;
        if (![self beginOperationWithError:&startError]) {
            completion(startError);
            return;
        }

        NSError *error = [self downloadRemotePath:remotePath toLocalPath:localPath resume:resume progress:progress];
        [self endOperation];
        completion(error);
    });
}

- (void)uploadFileAtPath:(NSString *)localPath toRemotePath:(NSString *)remotePath resume:(BOOL)resume progress:(SSHKitSFTPProgressHandler)progress completion:(SSHKitCompletion)completion {
    dispatch_async(self.workerQueue, ^{
        NSError *startError = nil;
        if (![self beginOperationWithError:&startError]) {
            completion(startError);
            return;
        }

        NSError *error = [self uploadLocalPath:localPath toRemotePath:remotePath resume:resume progress:progress];
        [self endOperation];
        completion(error);
    });
}

- (NSError *)readRemotePath:(NSString *)remotePath intoData:(NSMutableData *)data progress:(SSHKitSFTPProgressHandler)progress {
    sftp_file remoteFile = sftp_open(self.sftp, remotePath.UTF8String, O_RDONLY, 0);
    if (remoteFile == NULL) {
        return [self.client sftpErrorForOperation:@"SFTP read open" sftp:self.sftp];
    }

    uint64_t totalBytes = 0;
    sftp_attributes attributes = sftp_stat(self.sftp, remotePath.UTF8String);
    if (attributes != NULL) {
        totalBytes = attributes->size;
        sftp_attributes_free(attributes);
    } else {
        sftp_close(remoteFile);
        return [self.client sftpErrorForOperation:@"SFTP read stat" sftp:self.sftp];
    }
    if (totalBytes > SSHCoreSFTPMaximumReadFileSize) {
        sftp_close(remoteFile);
        return SSHKitMakeError(SSHKitErrorCodeSFTPFailure, @"SFTP read exceeds the maximum in-memory read size.");
    }
    uint64_t completedBytes = 0;
    char buffer[32768];
    while (YES) {
        ssize_t bytesRead = sftp_read(remoteFile, buffer, sizeof(buffer));
        if (bytesRead < 0) {
            sftp_close(remoteFile);
            return [self.client sftpErrorForOperation:@"SFTP read" sftp:self.sftp];
        }
        if (bytesRead == 0) {
            break;
        }

        if (data.length + (NSUInteger)bytesRead > SSHCoreSFTPMaximumReadFileSize) {
            sftp_close(remoteFile);
            return SSHKitMakeError(SSHKitErrorCodeSFTPFailure, @"SFTP read exceeds the maximum in-memory read size.");
        }
        [data appendBytes:buffer length:(NSUInteger)bytesRead];
        completedBytes += (uint64_t)bytesRead;
        if (progress != nil) {
            progress(completedBytes, totalBytes);
        }
    }

    if (sftp_close(remoteFile) != SSH_OK) {
        return [self.client sftpErrorForOperation:@"SFTP read close" sftp:self.sftp];
    }
    return nil;
}

- (NSError *)writeData:(NSData *)data toRemotePath:(NSString *)remotePath progress:(SSHKitSFTPProgressHandler)progress {
    sftp_file remoteFile = sftp_open(self.sftp, remotePath.UTF8String, O_CREAT | O_TRUNC | O_WRONLY, 0600);
    if (remoteFile == NULL) {
        return [self.client sftpErrorForOperation:@"SFTP write open" sftp:self.sftp];
    }

    const uint8_t *bytes = data.bytes;
    NSUInteger remaining = data.length;
    uint64_t completedBytes = 0;
    uint64_t totalBytes = (uint64_t)data.length;
    while (remaining > 0) {
        size_t chunkLength = MIN(remaining, (NSUInteger)32768);
        ssize_t bytesWritten = sftp_write(remoteFile, bytes, chunkLength);
        if (bytesWritten < 0) {
            sftp_close(remoteFile);
            return [self.client sftpErrorForOperation:@"SFTP write" sftp:self.sftp];
        }
        if (bytesWritten == 0) {
            sftp_close(remoteFile);
            return SSHKitMakeError(SSHKitErrorCodeConnectionFailed, @"SFTP write made no progress.");
        }
        bytes += bytesWritten;
        remaining -= (NSUInteger)bytesWritten;
        completedBytes += (uint64_t)bytesWritten;
        if (progress != nil) {
            progress(completedBytes, totalBytes);
        }
    }

    if (sftp_close(remoteFile) != SSH_OK) {
        return [self.client sftpErrorForOperation:@"SFTP write close" sftp:self.sftp];
    }
    return nil;
}

- (NSError *)downloadRemotePath:(NSString *)remotePath toLocalPath:(NSString *)localPath resume:(BOOL)resume progress:(SSHKitSFTPProgressHandler)progress {
    sftp_file remoteFile = sftp_open(self.sftp, remotePath.UTF8String, O_RDONLY, 0);
    if (remoteFile == NULL) {
        return [self.client sftpErrorForOperation:@"SFTP download open" sftp:self.sftp];
    }

    sftp_attributes attributes = sftp_stat(self.sftp, remotePath.UTF8String);
    if (attributes == NULL) {
        sftp_close(remoteFile);
        return [self.client sftpErrorForOperation:@"SFTP download stat" sftp:self.sftp];
    }
    uint64_t totalBytes = attributes->size;
    sftp_attributes_free(attributes);

    int openFlags = O_CREAT | O_WRONLY | (resume ? O_APPEND : O_TRUNC);
    int localFileDescriptor = open(localPath.fileSystemRepresentation, openFlags, 0600);
    if (localFileDescriptor < 0) {
        sftp_close(remoteFile);
        return SSHKitMakeError(SSHKitErrorCodeUnavailable, [NSString stringWithFormat:@"Unable to open local download file: %s", strerror(errno)]);
    }

    uint64_t completedBytes = 0;
    if (resume) {
        off_t localOffset = lseek(localFileDescriptor, 0, SEEK_END);
        if (localOffset < 0) {
            close(localFileDescriptor);
            sftp_close(remoteFile);
            return SSHKitMakeError(SSHKitErrorCodeUnavailable, [NSString stringWithFormat:@"Unable to seek local download file: %s", strerror(errno)]);
        }
        completedBytes = (uint64_t)localOffset;
        if (completedBytes > totalBytes) {
            close(localFileDescriptor);
            sftp_close(remoteFile);
            return SSHKitMakeError(SSHKitErrorCodeUnavailable, @"Local partial download is larger than the remote file.");
        }
        if (sftp_seek64(remoteFile, completedBytes) != SSH_OK) {
            close(localFileDescriptor);
            sftp_close(remoteFile);
            return [self.client sftpErrorForOperation:@"SFTP download seek" sftp:self.sftp];
        }
    }

    char buffer[32768];
    while (YES) {
        ssize_t bytesRead = sftp_read(remoteFile, buffer, sizeof(buffer));
        if (bytesRead < 0) {
            close(localFileDescriptor);
            sftp_close(remoteFile);
            return [self.client sftpErrorForOperation:@"SFTP download read" sftp:self.sftp];
        }
        if (bytesRead == 0) {
            break;
        }

        ssize_t bytesWritten = write(localFileDescriptor, buffer, (size_t)bytesRead);
        if (bytesWritten != bytesRead) {
            close(localFileDescriptor);
            sftp_close(remoteFile);
            return SSHKitMakeError(SSHKitErrorCodeUnavailable, [NSString stringWithFormat:@"Unable to write local download file: %s", strerror(errno)]);
        }
        completedBytes += (uint64_t)bytesRead;
        if (progress != nil) {
            progress(completedBytes, totalBytes);
        }
    }

    if (close(localFileDescriptor) != 0) {
        sftp_close(remoteFile);
        return SSHKitMakeError(SSHKitErrorCodeUnavailable, [NSString stringWithFormat:@"Unable to close local download file: %s", strerror(errno)]);
    }
    if (sftp_close(remoteFile) != SSH_OK) {
        return [self.client sftpErrorForOperation:@"SFTP download close" sftp:self.sftp];
    }
    return nil;
}

- (NSError *)uploadLocalPath:(NSString *)localPath toRemotePath:(NSString *)remotePath resume:(BOOL)resume progress:(SSHKitSFTPProgressHandler)progress {
    int localFileDescriptor = open(localPath.fileSystemRepresentation, O_RDONLY);
    if (localFileDescriptor < 0) {
        return SSHKitMakeError(SSHKitErrorCodeUnavailable, [NSString stringWithFormat:@"Unable to open local upload file: %s", strerror(errno)]);
    }

    struct stat localStat;
    if (fstat(localFileDescriptor, &localStat) != 0) {
        close(localFileDescriptor);
        return SSHKitMakeError(SSHKitErrorCodeUnavailable, [NSString stringWithFormat:@"Unable to stat local upload file: %s", strerror(errno)]);
    }
    uint64_t totalBytes = (uint64_t)localStat.st_size;
    uint64_t completedBytes = 0;
    if (resume) {
        sftp_attributes remoteAttributes = sftp_stat(self.sftp, remotePath.UTF8String);
        if (remoteAttributes == NULL) {
            close(localFileDescriptor);
            return [self.client sftpErrorForOperation:@"SFTP resume upload stat" sftp:self.sftp];
        }
        completedBytes = remoteAttributes->size;
        sftp_attributes_free(remoteAttributes);
    }
    int remoteFlags = O_CREAT | O_WRONLY | (resume ? 0 : O_TRUNC);
    sftp_file remoteFile = sftp_open(self.sftp, remotePath.UTF8String, remoteFlags, 0600);
    if (remoteFile == NULL) {
        close(localFileDescriptor);
        return [self.client sftpErrorForOperation:@"SFTP upload open" sftp:self.sftp];
    }

    if (resume) {
        if (completedBytes > totalBytes) {
            close(localFileDescriptor);
            sftp_close(remoteFile);
            return SSHKitMakeError(SSHKitErrorCodeUnavailable, @"Remote partial upload is larger than the local file.");
        }
        if (lseek(localFileDescriptor, (off_t)completedBytes, SEEK_SET) < 0 ||
            sftp_seek64(remoteFile, completedBytes) != SSH_OK) {
            close(localFileDescriptor);
            sftp_close(remoteFile);
            return SSHKitMakeError(SSHKitErrorCodeUnavailable, @"Unable to seek resumable upload offsets.");
        }
    }

    char buffer[32768];
    while (YES) {
        ssize_t bytesRead = read(localFileDescriptor, buffer, sizeof(buffer));
        if (bytesRead < 0) {
            close(localFileDescriptor);
            sftp_close(remoteFile);
            return SSHKitMakeError(SSHKitErrorCodeUnavailable, [NSString stringWithFormat:@"Unable to read local upload file: %s", strerror(errno)]);
        }
        if (bytesRead == 0) {
            break;
        }

        ssize_t writtenTotal = 0;
        while (writtenTotal < bytesRead) {
            ssize_t bytesWritten = sftp_write(remoteFile, buffer + writtenTotal, (size_t)(bytesRead - writtenTotal));
            if (bytesWritten < 0) {
                close(localFileDescriptor);
                sftp_close(remoteFile);
                return [self.client sftpErrorForOperation:@"SFTP upload write" sftp:self.sftp];
            }
            if (bytesWritten == 0) {
                close(localFileDescriptor);
                sftp_close(remoteFile);
                return SSHKitMakeError(SSHKitErrorCodeConnectionFailed, @"SFTP upload write made no progress.");
            }
            writtenTotal += bytesWritten;
            completedBytes += (uint64_t)bytesWritten;
            if (progress != nil) {
                progress(completedBytes, totalBytes);
            }
        }
    }

    if (close(localFileDescriptor) != 0) {
        sftp_close(remoteFile);
        return SSHKitMakeError(SSHKitErrorCodeUnavailable, [NSString stringWithFormat:@"Unable to close local upload file: %s", strerror(errno)]);
    }
    if (sftp_close(remoteFile) != SSH_OK) {
        return [self.client sftpErrorForOperation:@"SFTP upload close" sftp:self.sftp];
    }
    return nil;
}

@end

#pragma clang diagnostic pop
