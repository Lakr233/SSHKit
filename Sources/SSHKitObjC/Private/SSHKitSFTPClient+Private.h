#import <Foundation/Foundation.h>
#import <SSHKitObjC/SSHKitConnection.h>

NS_ASSUME_NONNULL_BEGIN

typedef void (^SSHKitSFTPListBlock)(NSString *path, SSHKitSFTPListCompletion completion);
typedef void (^SSHKitSFTPTransferBlock)(NSString *sourcePath, NSString *destinationPath, SSHKitCompletion completion);
typedef void (^SSHKitSFTPCloseBlock)(SSHKitCompletion completion);

@interface SSHKitSFTPClient ()

@property (nonatomic, copy) SSHKitSFTPListBlock listBlock;
@property (nonatomic, copy) SSHKitSFTPTransferBlock downloadBlock;
@property (nonatomic, copy) SSHKitSFTPTransferBlock uploadBlock;
@property (nonatomic, copy) SSHKitSFTPCloseBlock closeBlock;

- (instancetype)initWithListBlock:(SSHKitSFTPListBlock)listBlock
                    downloadBlock:(SSHKitSFTPTransferBlock)downloadBlock
                       uploadBlock:(SSHKitSFTPTransferBlock)uploadBlock
                        closeBlock:(SSHKitSFTPCloseBlock)closeBlock;

@end

NS_ASSUME_NONNULL_END
