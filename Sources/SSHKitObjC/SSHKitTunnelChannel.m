#import <SSHKitObjC/SSHKitConnection.h>

#import "SSHKitTunnelChannel+Private.h"

@implementation SSHKitTunnelChannel

- (instancetype)initWithReadBlock:(SSHKitTunnelReadBlock)readBlock
                       writeBlock:(SSHKitTunnelDataBlock)writeBlock
                       closeBlock:(SSHKitTunnelCloseBlock)closeBlock {
    self = [super init];
    if (self) {
        _readBlock = [readBlock copy];
        _writeBlock = [writeBlock copy];
        _closeBlock = [closeBlock copy];
    }
    return self;
}

- (void)readDataWithMaximumLength:(NSUInteger)maximumLength completion:(SSHKitTunnelReadCompletion)completion {
    NSParameterAssert(maximumLength > 0);
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_DEFAULT, 0), ^{
        self.readBlock(maximumLength, completion);
    });
}

- (void)writeData:(NSData *)data completion:(SSHKitCompletion)completion {
    NSParameterAssert(data.length > 0);
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_DEFAULT, 0), ^{
        self.writeBlock(data, completion);
    });
}

- (void)closeWithCompletion:(SSHKitCompletion)completion {
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_DEFAULT, 0), ^{
        self.closeBlock(completion);
    });
}

@end
