#import <SSHKitObjC/SSHKitConnection.h>

#import "SSHKitCommand+Private.h"

@implementation SSHKitCommand

- (instancetype)initWithWriteBlock:(SSHKitCommandDataBlock)writeBlock
                          eofBlock:(SSHKitCommandCompletionBlock)eofBlock
                        closeBlock:(SSHKitCommandCompletionBlock)closeBlock
                         startBlock:(SSHKitCommandStartBlock)startBlock {
    self = [super init];
    if (self) {
        _writeBlock = [writeBlock copy];
        _eofBlock = [eofBlock copy];
        _closeBlock = [closeBlock copy];
        _startBlock = [startBlock copy];
    }
    return self;
}

- (void)writeData:(NSData *)data completion:(SSHKitCompletion)completion {
    NSParameterAssert(data.length > 0);
    self.writeBlock(data, completion);
}

- (void)sendEOFWithCompletion:(SSHKitCompletion)completion {
    self.eofBlock(completion);
}

- (void)closeWithCompletion:(SSHKitCompletion)completion {
    self.closeBlock(completion);
}

- (void)startEventDelivery {
    self.startBlock();
}

@end
