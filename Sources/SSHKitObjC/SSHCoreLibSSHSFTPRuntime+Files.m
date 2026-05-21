#import "SSHCoreLibSSHSFTPRuntime+Files.h"

#import "SSHCoreLibSSHSFTPRuntime+Internal.h"
#import "SSHCoreLibSSHSFTPFileRuntime.h"
#import "SSHCoreOpenSSHClient+Internal.h"
#import "SSHKitSFTPClient+Private.h"

#import <SSHKitObjC/SSHKitError.h>

#include <fcntl.h>

static int SSHCoreSFTPFileOpenFlagsToPOSIX(SSHKitSFTPFileOpenFlags flags) {
    BOOL wantsRead = (flags & SSHKitSFTPFileOpenFlagRead) == SSHKitSFTPFileOpenFlagRead;
    BOOL wantsWrite = (flags & SSHKitSFTPFileOpenFlagWrite) == SSHKitSFTPFileOpenFlagWrite;
    int posixFlags = O_RDONLY;
    if (wantsRead && wantsWrite) {
        posixFlags = O_RDWR;
    } else if (wantsWrite) {
        posixFlags = O_WRONLY;
    }
    if ((flags & SSHKitSFTPFileOpenFlagCreate) == SSHKitSFTPFileOpenFlagCreate) {
        posixFlags |= O_CREAT;
    }
    if ((flags & SSHKitSFTPFileOpenFlagTruncate) == SSHKitSFTPFileOpenFlagTruncate) {
        posixFlags |= O_TRUNC;
    }
    if ((flags & SSHKitSFTPFileOpenFlagAppend) == SSHKitSFTPFileOpenFlagAppend) {
        posixFlags |= O_APPEND;
    }
    return posixFlags;
}

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wobjc-protocol-method-implementation"

@implementation SSHCoreLibSSHSFTPRuntime (Files)

- (void)openFileAtPath:(NSString *)path flags:(SSHKitSFTPFileOpenFlags)flags permissions:(uint32_t)permissions completion:(SSHKitSFTPFileHandleCompletion)completion {
    dispatch_async(self.workerQueue, ^{
        NSError *startError = nil;
        if (![self beginOperationWithError:&startError]) {
            completion(nil, startError);
            return;
        }

        sftp_file file = sftp_open(self.sftp, path.UTF8String, SSHCoreSFTPFileOpenFlagsToPOSIX(flags), permissions);
        if (file == NULL) {
            NSError *error = [self.client sftpErrorForOperation:@"SFTP file open" sftp:self.sftp];
            [self endOperation];
            completion(nil, error);
            return;
        }

        SSHCoreLibSSHSFTPFileRuntime *fileRuntime = [[SSHCoreLibSSHSFTPFileRuntime alloc] initWithFile:file
                                                                                                 owner:self
                                                                                           workerQueue:self.workerQueue
                                                                                                 client:self.client];
        [self registerFileRuntime:fileRuntime];
        SSHKitSFTPFileHandle *handle = [[SSHKitSFTPFileHandle alloc] initWithReadBlock:^(NSUInteger maximumLength, SSHKitSFTPDataCompletion readCompletion) {
            [fileRuntime readDataWithMaximumLength:maximumLength completion:readCompletion];
        } writeBlock:^(NSData *data, SSHKitCompletion writeCompletion) {
            [fileRuntime writeData:data completion:writeCompletion];
        } seekBlock:^(uint64_t offset, SSHKitCompletion seekCompletion) {
            [fileRuntime seekToOffset:offset completion:seekCompletion];
        } closeBlock:^(SSHKitCompletion closeCompletion) {
            [fileRuntime closeWithCompletion:closeCompletion];
        }];
        [self endOperation];
        completion(handle, nil);
    });
}

@end

#pragma clang diagnostic pop
