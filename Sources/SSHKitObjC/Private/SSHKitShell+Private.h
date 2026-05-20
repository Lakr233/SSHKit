#import <Foundation/Foundation.h>
#import <SSHKitObjC/SSHKitConnection.h>

NS_ASSUME_NONNULL_BEGIN

typedef void (^SSHKitShellDataBlock)(NSData *data, SSHKitCompletion completion);
typedef void (^SSHKitShellResizeBlock)(uint16_t columns, uint16_t rows, SSHKitCompletion completion);
typedef void (^SSHKitShellCloseBlock)(SSHKitCompletion completion);

@interface SSHKitShell ()

@property (nonatomic, copy) SSHKitShellDataBlock writeBlock;
@property (nonatomic, copy) SSHKitShellResizeBlock resizeBlock;
@property (nonatomic, copy) SSHKitShellCloseBlock closeBlock;

- (instancetype)initWithWriteBlock:(SSHKitShellDataBlock)writeBlock
                       resizeBlock:(SSHKitShellResizeBlock)resizeBlock
                        closeBlock:(SSHKitShellCloseBlock)closeBlock;

@end

NS_ASSUME_NONNULL_END
