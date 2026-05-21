#import <SSHKitObjC/SSHKitConnection.h>

#import "SSHKitShell+Private.h"

@implementation SSHKitShell

- (instancetype)initWithWriteBlock:(SSHKitShellDataBlock)writeBlock
                       resizeBlock:(SSHKitShellResizeBlock)resizeBlock
                        closeBlock:(SSHKitShellCloseBlock)closeBlock
                        startBlock:(SSHKitShellStartBlock)startBlock {
    self = [super init];
    if (self) {
        _writeBlock = [writeBlock copy];
        _resizeBlock = [resizeBlock copy];
        _closeBlock = [closeBlock copy];
        _startBlock = [startBlock copy];
    }
    return self;
}

- (void)writeData:(NSData *)data completion:(SSHKitCompletion)completion {
    NSParameterAssert(data.length > 0);
    self.writeBlock(data, completion);
}

- (void)resizeWithColumns:(uint16_t)columns rows:(uint16_t)rows completion:(SSHKitCompletion)completion {
    NSParameterAssert(columns > 0);
    NSParameterAssert(rows > 0);
    self.resizeBlock(columns, rows, completion);
}

- (void)closeWithCompletion:(SSHKitCompletion)completion {
    self.closeBlock(completion);
}

- (void)startEventDelivery {
    self.startBlock();
}

@end
