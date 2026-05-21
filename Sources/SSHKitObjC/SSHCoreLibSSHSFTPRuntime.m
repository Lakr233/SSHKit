#import "SSHCoreLibSSHSFTPRuntime.h"
#import "SSHCoreLibSSHSFTPRuntime+Internal.h"

#import <SSHKitObjC/SSHKitError.h>

#import "SSHCoreLibSSHSFTPFileRuntime.h"
#import "SSHCoreOpenSSHClient+Internal.h"
#import "SSHKitSFTPClient+Private.h"

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wincomplete-implementation"

@implementation SSHCoreLibSSHSFTPRuntime

- (instancetype)initWithSession:(sftp_session)sftp
                    workerQueue:(dispatch_queue_t)workerQueue
                    closeHandler:(SSHCoreSFTPCloseHandler)closeHandler
                          client:(SSHCoreOpenSSHClient *)client {
    NSParameterAssert(sftp != NULL);
    NSParameterAssert(workerQueue != nil);

    self = [super init];
    if (self) {
        _sftp = sftp;
        _workerQueue = workerQueue;
        _closeHandler = [closeHandler copy];
        _client = client;
        _fileRuntimes = [NSHashTable weakObjectsHashTable];
    }
    return self;
}

- (SSHKitSFTPAttributes *)attributesFromSFTPAttributes:(sftp_attributes)attributes {
    NSDate *accessedAt = attributes->atime64 > 0 ? [NSDate dateWithTimeIntervalSince1970:(NSTimeInterval)attributes->atime64] : nil;
    NSDate *modifiedAt = attributes->mtime64 > 0 ? [NSDate dateWithTimeIntervalSince1970:(NSTimeInterval)attributes->mtime64] : nil;
    return [[SSHKitSFTPAttributes alloc] initWithSize:attributes->size
                                         permissions:attributes->permissions
                                                 uid:attributes->uid
                                                 gid:attributes->gid
                                                type:attributes->type
                                          accessedAt:accessedAt
                                          modifiedAt:modifiedAt];
}

- (void)closeWithCompletion:(SSHKitCompletion)completion {
    dispatch_async(self.workerQueue, ^{
        if (self.closed) {
            completion(nil);
            return;
        }

        self.closed = YES;
        for (SSHCoreLibSSHSFTPFileRuntime *fileRuntime in self.fileRuntimes.allObjects) {
            [fileRuntime invalidateOnWorkerQueue];
        }
        [self.fileRuntimes removeAllObjects];
        sftp_session sftp = self.sftp;
        self.sftp = NULL;
        if (sftp != NULL) {
            sftp_free(sftp);
        }
        [self callCloseHandlerIfNeeded];
        completion(nil);
    });
}

- (BOOL)beginOperationWithError:(NSError **)error {
    if (self.closed || self.sftp == NULL) {
        if (error) {
            *error = SSHKitMakeError(SSHKitErrorCodeInvalidState, @"SFTP client is closed.");
        }
        return NO;
    }
    NSAssert(!self.runningOperation, @"SFTP client operation reentered the serial worker queue.");

    self.runningOperation = YES;
    return YES;
}

- (void)endOperation {
    self.runningOperation = NO;
}

- (void)callCloseHandlerIfNeeded {
    if (self.didCallCloseHandler) {
        return;
    }
    self.didCallCloseHandler = YES;
    self.closeHandler();
}

- (void)invalidateOnWorkerQueue {
    self.closed = YES;
    for (SSHCoreLibSSHSFTPFileRuntime *fileRuntime in self.fileRuntimes.allObjects) {
        [fileRuntime invalidateOnWorkerQueue];
    }
    [self.fileRuntimes removeAllObjects];
    sftp_session sftp = self.sftp;
    self.sftp = NULL;
    if (sftp != NULL) {
        sftp_free(sftp);
    }
    [self callCloseHandlerIfNeeded];
}

- (void)registerFileRuntime:(SSHCoreLibSSHSFTPFileRuntime *)fileRuntime {
    [self.fileRuntimes addObject:fileRuntime];
}

- (void)unregisterFileRuntime:(SSHCoreLibSSHSFTPFileRuntime *)fileRuntime {
    [self.fileRuntimes removeObject:fileRuntime];
}

- (BOOL)isOpenOnWorkerQueue {
    return !self.closed && self.sftp != NULL;
}

- (void)dealloc {
    sftp_session sftp = self.sftp;
    if (sftp == NULL) {
        return;
    }
    SSHCoreSFTPCloseHandler closeHandler = self.closeHandler;
    NSArray<SSHCoreLibSSHSFTPFileRuntime *> *fileRuntimes = self.fileRuntimes.allObjects;
    dispatch_async(self.workerQueue, ^{
        for (SSHCoreLibSSHSFTPFileRuntime *fileRuntime in fileRuntimes) {
            [fileRuntime invalidateOnWorkerQueue];
        }
        sftp_free(sftp);
        closeHandler();
    });
}

@end

#pragma clang diagnostic pop
