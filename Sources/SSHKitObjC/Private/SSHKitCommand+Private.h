#import <Foundation/Foundation.h>
#import <SSHKitObjC/SSHKitConnection.h>

NS_ASSUME_NONNULL_BEGIN

typedef void (^SSHKitCommandDataBlock)(NSData *data, SSHKitCompletion completion);
typedef void (^SSHKitCommandCompletionBlock)(SSHKitCompletion completion);
typedef void (^SSHKitCommandStartBlock)(void);

@interface SSHKitCommand ()

@property (nonatomic, copy) SSHKitCommandDataBlock writeBlock;
@property (nonatomic, copy) SSHKitCommandCompletionBlock eofBlock;
@property (nonatomic, copy) SSHKitCommandCompletionBlock closeBlock;
@property (nonatomic, copy) SSHKitCommandStartBlock startBlock;

- (instancetype)initWithWriteBlock:(SSHKitCommandDataBlock)writeBlock
                          eofBlock:(SSHKitCommandCompletionBlock)eofBlock
                        closeBlock:(SSHKitCommandCompletionBlock)closeBlock
                         startBlock:(SSHKitCommandStartBlock)startBlock;
- (void)startEventDelivery;

@end

NS_ASSUME_NONNULL_END
