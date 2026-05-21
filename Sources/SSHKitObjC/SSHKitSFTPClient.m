#import <SSHKitObjC/SSHKitConnection.h>

#import "SSHKitSFTPClient+Private.h"

@implementation SSHKitSFTPFileHandle

- (instancetype)initWithReadBlock:(SSHKitSFTPFileReadBlock)readBlock
                        writeBlock:(SSHKitSFTPFileWriteBlock)writeBlock
                         seekBlock:(SSHKitSFTPFileSeekBlock)seekBlock
                        closeBlock:(SSHKitSFTPFileCloseBlock)closeBlock {
    self = [super init];
    if (self) {
        _readBlock = [readBlock copy];
        _writeBlock = [writeBlock copy];
        _seekBlock = [seekBlock copy];
        _closeBlock = [closeBlock copy];
    }
    return self;
}

- (void)readDataWithMaximumLength:(NSUInteger)maximumLength completion:(SSHKitSFTPDataCompletion)completion {
    NSParameterAssert(maximumLength > 0);
    self.readBlock(maximumLength, completion);
}

- (void)writeData:(NSData *)data completion:(SSHKitCompletion)completion {
    NSParameterAssert(data.length > 0);
    self.writeBlock(data, completion);
}

- (void)seekToOffset:(uint64_t)offset completion:(SSHKitCompletion)completion {
    self.seekBlock(offset, completion);
}

- (void)closeWithCompletion:(SSHKitCompletion)completion {
    self.closeBlock(completion);
}

@end

@implementation SSHKitSFTPClient

- (instancetype)initWithListBlock:(SSHKitSFTPListBlock)listBlock
                    realpathBlock:(SSHKitSFTPStringBlock)realpathBlock
                        statBlock:(SSHKitSFTPAttributesBlock)statBlock
                       lstatBlock:(SSHKitSFTPAttributesBlock)lstatBlock
              setPermissionsBlock:(SSHKitSFTPSetPermissionsBlock)setPermissionsBlock
        fileSystemAttributesBlock:(SSHKitSFTPFileSystemAttributesBlock)fileSystemAttributesBlock
             createDirectoryBlock:(SSHKitSFTPDirectoryBlock)createDirectoryBlock
             removeDirectoryBlock:(SSHKitSFTPPathBlock)removeDirectoryBlock
                  removeFileBlock:(SSHKitSFTPPathBlock)removeFileBlock
                      renameBlock:(SSHKitSFTPTwoPathBlock)renameBlock
                    readLinkBlock:(SSHKitSFTPStringBlock)readLinkBlock
          createSymbolicLinkBlock:(SSHKitSFTPTwoPathBlock)createSymbolicLinkBlock
                     openFileBlock:(SSHKitSFTPOpenFileBlock)openFileBlock
                    readFileBlock:(SSHKitSFTPReadDataBlock)readFileBlock
                   writeDataBlock:(SSHKitSFTPWriteDataBlock)writeDataBlock
                    downloadBlock:(SSHKitSFTPTransferBlock)downloadBlock
                       uploadBlock:(SSHKitSFTPTransferBlock)uploadBlock
                        closeBlock:(SSHKitSFTPCloseBlock)closeBlock {
    self = [super init];
    if (self) {
        _listBlock = [listBlock copy];
        _realpathBlock = [realpathBlock copy];
        _statBlock = [statBlock copy];
        _lstatBlock = [lstatBlock copy];
        _setPermissionsBlock = [setPermissionsBlock copy];
        _fileSystemAttributesBlock = [fileSystemAttributesBlock copy];
        _createDirectoryBlock = [createDirectoryBlock copy];
        _removeDirectoryBlock = [removeDirectoryBlock copy];
        _removeFileBlock = [removeFileBlock copy];
        _renameBlock = [renameBlock copy];
        _readLinkBlock = [readLinkBlock copy];
        _createSymbolicLinkBlock = [createSymbolicLinkBlock copy];
        _openFileBlock = [openFileBlock copy];
        _readFileBlock = [readFileBlock copy];
        _writeDataBlock = [writeDataBlock copy];
        _downloadBlock = [downloadBlock copy];
        _uploadBlock = [uploadBlock copy];
        _closeBlock = [closeBlock copy];
    }
    return self;
}

- (void)listDirectory:(NSString *)path completion:(SSHKitSFTPListCompletion)completion {
    NSParameterAssert(path.length > 0);
    self.listBlock(path, completion);
}

- (void)realpath:(NSString *)path completion:(SSHKitSFTPStringCompletion)completion {
    NSParameterAssert(path.length > 0);
    self.realpathBlock(path, completion);
}

- (void)statPath:(NSString *)path completion:(SSHKitSFTPAttributesCompletion)completion {
    NSParameterAssert(path.length > 0);
    self.statBlock(path, completion);
}

- (void)lstatPath:(NSString *)path completion:(SSHKitSFTPAttributesCompletion)completion {
    NSParameterAssert(path.length > 0);
    self.lstatBlock(path, completion);
}

- (void)setPermissions:(uint32_t)permissions atPath:(NSString *)path completion:(SSHKitCompletion)completion {
    NSParameterAssert(path.length > 0);
    self.setPermissionsBlock(path, permissions, completion);
}

- (void)fileSystemAttributesAtPath:(NSString *)path completion:(SSHKitSFTPFileSystemAttributesCompletion)completion {
    NSParameterAssert(path.length > 0);
    self.fileSystemAttributesBlock(path, completion);
}

- (void)createDirectoryAtPath:(NSString *)path permissions:(uint32_t)permissions completion:(SSHKitCompletion)completion {
    NSParameterAssert(path.length > 0);
    self.createDirectoryBlock(path, permissions, completion);
}

- (void)removeDirectoryAtPath:(NSString *)path completion:(SSHKitCompletion)completion {
    NSParameterAssert(path.length > 0);
    self.removeDirectoryBlock(path, completion);
}

- (void)removeFileAtPath:(NSString *)path completion:(SSHKitCompletion)completion {
    NSParameterAssert(path.length > 0);
    self.removeFileBlock(path, completion);
}

- (void)renamePath:(NSString *)sourcePath toPath:(NSString *)destinationPath completion:(SSHKitCompletion)completion {
    NSParameterAssert(sourcePath.length > 0);
    NSParameterAssert(destinationPath.length > 0);
    self.renameBlock(sourcePath, destinationPath, completion);
}

- (void)readLinkAtPath:(NSString *)path completion:(SSHKitSFTPStringCompletion)completion {
    NSParameterAssert(path.length > 0);
    self.readLinkBlock(path, completion);
}

- (void)createSymbolicLinkAtPath:(NSString *)linkPath targetPath:(NSString *)targetPath completion:(SSHKitCompletion)completion {
    NSParameterAssert(linkPath.length > 0);
    NSParameterAssert(targetPath.length > 0);
    self.createSymbolicLinkBlock(targetPath, linkPath, completion);
}

- (void)openFileAtPath:(NSString *)path flags:(SSHKitSFTPFileOpenFlags)flags permissions:(uint32_t)permissions completion:(SSHKitSFTPFileHandleCompletion)completion {
    NSParameterAssert(path.length > 0);
    NSParameterAssert(flags != 0);
    self.openFileBlock(path, flags, permissions, completion);
}

- (void)readFileAtPath:(NSString *)path completion:(SSHKitSFTPDataCompletion)completion {
    NSParameterAssert(path.length > 0);
    self.readFileBlock(path, completion);
}

- (void)writeData:(NSData *)data toFileAtPath:(NSString *)path completion:(SSHKitCompletion)completion {
    NSParameterAssert(data != nil);
    NSParameterAssert(path.length > 0);
    self.writeDataBlock(path, data, completion);
}

- (void)downloadFileAtPath:(NSString *)remotePath toLocalPath:(NSString *)localPath completion:(SSHKitCompletion)completion {
    [self downloadFileAtPath:remotePath toLocalPath:localPath progress:nil completion:completion];
}

- (void)downloadFileAtPath:(NSString *)remotePath toLocalPath:(NSString *)localPath progress:(SSHKitSFTPProgressHandler)progress completion:(SSHKitCompletion)completion {
    NSParameterAssert(remotePath.length > 0);
    NSParameterAssert(localPath.length > 0);
    self.downloadBlock(remotePath, localPath, NO, progress, completion);
}

- (void)resumeDownloadFileAtPath:(NSString *)remotePath toLocalPath:(NSString *)localPath progress:(SSHKitSFTPProgressHandler)progress completion:(SSHKitCompletion)completion {
    NSParameterAssert(remotePath.length > 0);
    NSParameterAssert(localPath.length > 0);
    self.downloadBlock(remotePath, localPath, YES, progress, completion);
}

- (void)uploadFileAtPath:(NSString *)localPath toRemotePath:(NSString *)remotePath completion:(SSHKitCompletion)completion {
    [self uploadFileAtPath:localPath toRemotePath:remotePath progress:nil completion:completion];
}

- (void)uploadFileAtPath:(NSString *)localPath toRemotePath:(NSString *)remotePath progress:(SSHKitSFTPProgressHandler)progress completion:(SSHKitCompletion)completion {
    NSParameterAssert(localPath.length > 0);
    NSParameterAssert(remotePath.length > 0);
    self.uploadBlock(localPath, remotePath, NO, progress, completion);
}

- (void)resumeUploadFileAtPath:(NSString *)localPath toRemotePath:(NSString *)remotePath progress:(SSHKitSFTPProgressHandler)progress completion:(SSHKitCompletion)completion {
    NSParameterAssert(localPath.length > 0);
    NSParameterAssert(remotePath.length > 0);
    self.uploadBlock(localPath, remotePath, YES, progress, completion);
}

- (void)closeWithCompletion:(SSHKitCompletion)completion {
    self.closeBlock(completion);
}

@end
