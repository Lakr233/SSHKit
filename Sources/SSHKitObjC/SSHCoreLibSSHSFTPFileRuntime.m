#import "SSHCoreLibSSHSFTPFileRuntime.h"

#import <SSHKitObjC/SSHKitError.h>

#import "SSHCoreLibSSHSFTPRuntime.h"
#import "SSHCoreOpenSSHClient+Internal.h"
#import "SSHKitSFTPClient+Private.h"

@interface SSHCoreLibSSHSFTPFileRuntime ()

@property (nonatomic) sftp_file file;
@property (nonatomic) SSHCoreLibSSHSFTPRuntime *owner;
@property (nonatomic) dispatch_queue_t workerQueue;
@property (nonatomic) SSHCoreOpenSSHClient *client;
@property (nonatomic) BOOL closed;

@end

@implementation SSHCoreLibSSHSFTPFileRuntime

- (instancetype)initWithFile:(sftp_file)file
                       owner:(SSHCoreLibSSHSFTPRuntime *)owner
                 workerQueue:(dispatch_queue_t)workerQueue
                       client:(SSHCoreOpenSSHClient *)client {
    NSParameterAssert(file != NULL);
    NSParameterAssert(owner != nil);
    NSParameterAssert(workerQueue != nil);

    self = [super init];
    if (self) {
        _file = file;
        _owner = owner;
        _workerQueue = workerQueue;
        _client = client;
    }
    return self;
}

- (void)readDataWithMaximumLength:(NSUInteger)maximumLength completion:(SSHKitSFTPDataCompletion)completion {
    dispatch_async(self.workerQueue, ^{
        NSError *stateError = nil;
        if (![self ensureOpenWithError:&stateError]) {
            completion(nil, stateError);
            return;
        }

        uint32_t boundedLength = (uint32_t)MIN(maximumLength, (NSUInteger)32768);
        NSMutableData *data = [NSMutableData dataWithLength:(NSUInteger)boundedLength];
        ssize_t bytesRead = sftp_read(self.file, data.mutableBytes, boundedLength);
        if (bytesRead < 0) {
            completion(nil, [self.client sftpErrorForOperation:@"SFTP file read" status:sftp_get_error(self.file->sftp)]);
            return;
        }

        data.length = (NSUInteger)bytesRead;
        completion(data, nil);
    });
}

- (void)writeData:(NSData *)data completion:(SSHKitCompletion)completion {
    dispatch_async(self.workerQueue, ^{
        NSError *stateError = nil;
        if (![self ensureOpenWithError:&stateError]) {
            completion(stateError);
            return;
        }

        const uint8_t *bytes = data.bytes;
        NSUInteger remaining = data.length;
        while (remaining > 0) {
            ssize_t bytesWritten = sftp_write(self.file, bytes, remaining);
            if (bytesWritten < 0) {
                completion([self.client sftpErrorForOperation:@"SFTP file write" status:sftp_get_error(self.file->sftp)]);
                return;
            }
            if (bytesWritten == 0) {
                completion(SSHKitMakeError(SSHKitErrorCodeConnectionFailed, @"SFTP file write made no progress."));
                return;
            }
            bytes += bytesWritten;
            remaining -= (NSUInteger)bytesWritten;
        }
        completion(nil);
    });
}

- (void)seekToOffset:(uint64_t)offset completion:(SSHKitCompletion)completion {
    dispatch_async(self.workerQueue, ^{
        NSError *stateError = nil;
        if (![self ensureOpenWithError:&stateError]) {
            completion(stateError);
            return;
        }

        int result = sftp_seek64(self.file, offset);
        completion(result == SSH_OK ? nil : [self.client sftpErrorForOperation:@"SFTP file seek" status:sftp_get_error(self.file->sftp)]);
    });
}

- (void)closeWithCompletion:(SSHKitCompletion)completion {
    dispatch_async(self.workerQueue, ^{
        if (self.closed || self.file == NULL) {
            completion(nil);
            return;
        }

        sftp_file file = self.file;
        self.file = NULL;
        self.closed = YES;
        int result = sftp_close(file);
        [self.owner unregisterFileRuntime:self];
        completion(result == SSH_OK ? nil : SSHKitMakeError(SSHKitErrorCodeSFTPFailure, @"SFTP file close failed."));
    });
}

- (BOOL)ensureOpenWithError:(NSError **)error {
    if (!self.closed && self.file != NULL && [self.owner isOpenOnWorkerQueue]) {
        return YES;
    }

    NSAssert(NO, @"SFTP file handle is closed.");
    if (error) {
        *error = SSHKitMakeError(SSHKitErrorCodeInvalidState, @"SFTP file handle is closed.");
    }
    return NO;
}

- (void)invalidateOnWorkerQueue {
    if (self.closed) {
        return;
    }

    self.closed = YES;
    sftp_file file = self.file;
    self.file = NULL;
    if (file != NULL) {
        sftp_close(file);
    }
    [self.owner unregisterFileRuntime:self];
}

- (void)dealloc {
    sftp_file file = self.file;
    if (file == NULL) {
        return;
    }
    SSHCoreLibSSHSFTPRuntime *owner = self.owner;
    dispatch_async(self.workerQueue, ^{
        sftp_close(file);
        (void)owner;
    });
}

@end
