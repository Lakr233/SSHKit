#import <Foundation/Foundation.h>
#import <SSHKitObjC/SSHKitConnection.h>

NS_ASSUME_NONNULL_BEGIN

typedef void (^SSHKitSFTPListBlock)(NSString *path, SSHKitSFTPListCompletion completion);
typedef void (^SSHKitSFTPStringBlock)(NSString *path, SSHKitSFTPStringCompletion completion);
typedef void (^SSHKitSFTPAttributesBlock)(NSString *path, SSHKitSFTPAttributesCompletion completion);
typedef void (^SSHKitSFTPSetPermissionsBlock)(NSString *path, uint32_t permissions, SSHKitCompletion completion);
typedef void (^SSHKitSFTPFileSystemAttributesBlock)(NSString *path, SSHKitSFTPFileSystemAttributesCompletion completion);
typedef void (^SSHKitSFTPDirectoryBlock)(NSString *path, uint32_t permissions, SSHKitCompletion completion);
typedef void (^SSHKitSFTPPathBlock)(NSString *path, SSHKitCompletion completion);
typedef void (^SSHKitSFTPTwoPathBlock)(NSString *sourcePath, NSString *destinationPath, SSHKitCompletion completion);
typedef void (^SSHKitSFTPOpenFileBlock)(NSString *path, SSHKitSFTPFileOpenFlags flags, uint32_t permissions, SSHKitSFTPFileHandleCompletion completion);
typedef void (^SSHKitSFTPReadDataBlock)(NSString *path, SSHKitSFTPDataCompletion completion);
typedef void (^SSHKitSFTPWriteDataBlock)(NSString *path, NSData *data, SSHKitCompletion completion);
typedef void (^SSHKitSFTPTransferBlock)(NSString *sourcePath, NSString *destinationPath, BOOL resume, SSHKitSFTPProgressHandler progress, SSHKitCompletion completion);
typedef void (^SSHKitSFTPCloseBlock)(SSHKitCompletion completion);
typedef void (^SSHKitSFTPFileReadBlock)(NSUInteger maximumLength, SSHKitSFTPDataCompletion completion);
typedef void (^SSHKitSFTPFileWriteBlock)(NSData *data, SSHKitCompletion completion);
typedef void (^SSHKitSFTPFileSeekBlock)(uint64_t offset, SSHKitCompletion completion);
typedef void (^SSHKitSFTPFileCloseBlock)(SSHKitCompletion completion);

@interface SSHKitSFTPFileHandle ()

@property (nonatomic, copy) SSHKitSFTPFileReadBlock readBlock;
@property (nonatomic, copy) SSHKitSFTPFileWriteBlock writeBlock;
@property (nonatomic, copy) SSHKitSFTPFileSeekBlock seekBlock;
@property (nonatomic, copy) SSHKitSFTPFileCloseBlock closeBlock;

- (instancetype)initWithReadBlock:(SSHKitSFTPFileReadBlock)readBlock
                        writeBlock:(SSHKitSFTPFileWriteBlock)writeBlock
                         seekBlock:(SSHKitSFTPFileSeekBlock)seekBlock
                        closeBlock:(SSHKitSFTPFileCloseBlock)closeBlock;

@end

@interface SSHKitSFTPClient ()

@property (nonatomic, copy) SSHKitSFTPListBlock listBlock;
@property (nonatomic, copy) SSHKitSFTPStringBlock realpathBlock;
@property (nonatomic, copy) SSHKitSFTPAttributesBlock statBlock;
@property (nonatomic, copy) SSHKitSFTPAttributesBlock lstatBlock;
@property (nonatomic, copy) SSHKitSFTPSetPermissionsBlock setPermissionsBlock;
@property (nonatomic, copy) SSHKitSFTPFileSystemAttributesBlock fileSystemAttributesBlock;
@property (nonatomic, copy) SSHKitSFTPDirectoryBlock createDirectoryBlock;
@property (nonatomic, copy) SSHKitSFTPPathBlock removeDirectoryBlock;
@property (nonatomic, copy) SSHKitSFTPPathBlock removeFileBlock;
@property (nonatomic, copy) SSHKitSFTPTwoPathBlock renameBlock;
@property (nonatomic, copy) SSHKitSFTPStringBlock readLinkBlock;
@property (nonatomic, copy) SSHKitSFTPTwoPathBlock createSymbolicLinkBlock;
@property (nonatomic, copy) SSHKitSFTPOpenFileBlock openFileBlock;
@property (nonatomic, copy) SSHKitSFTPReadDataBlock readFileBlock;
@property (nonatomic, copy) SSHKitSFTPWriteDataBlock writeDataBlock;
@property (nonatomic, copy) SSHKitSFTPTransferBlock downloadBlock;
@property (nonatomic, copy) SSHKitSFTPTransferBlock uploadBlock;
@property (nonatomic, copy) SSHKitSFTPCloseBlock closeBlock;

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
                        closeBlock:(SSHKitSFTPCloseBlock)closeBlock;

@end

NS_ASSUME_NONNULL_END
