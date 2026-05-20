#import <Foundation/Foundation.h>
#import <SSHKitObjC/SSHKitConnection.h>

NS_ASSUME_NONNULL_BEGIN

typedef void (^SSHKitShellDataBlock)(NSData *data, SSHKitCompletion completion);
typedef void (^SSHKitShellResizeBlock)(uint16_t columns, uint16_t rows, SSHKitCompletion completion);
typedef void (^SSHKitShellCloseBlock)(SSHKitCompletion completion);
typedef void (^SSHKitShellStartBlock)(void);

@interface SSHKitShell ()

@property (nonatomic, copy) SSHKitShellDataBlock writeBlock;
@property (nonatomic, copy) SSHKitShellResizeBlock resizeBlock;
@property (nonatomic, copy) SSHKitShellCloseBlock closeBlock;
@property (nonatomic, copy) SSHKitShellStartBlock startBlock;

- (instancetype)initWithWriteBlock:(SSHKitShellDataBlock)writeBlock
                       resizeBlock:(SSHKitShellResizeBlock)resizeBlock
                        closeBlock:(SSHKitShellCloseBlock)closeBlock
                        startBlock:(SSHKitShellStartBlock)startBlock;
- (void)startEventDelivery;

@end

NS_ASSUME_NONNULL_END
