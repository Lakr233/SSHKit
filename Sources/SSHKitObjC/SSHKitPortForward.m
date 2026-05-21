#import <SSHKitObjC/SSHKitConnection.h>

#import "SSHKitPortForward+Private.h"

@implementation SSHKitPortForward

- (instancetype)initWithBoundHost:(NSString *)boundHost
                         boundPort:(uint16_t)boundPort
                         closeBlock:(SSHKitPortForwardCloseBlock)closeBlock {
    self = [super init];
    if (self) {
        _boundHost = [boundHost copy];
        _boundPort = boundPort;
        _closeBlock = [closeBlock copy];
    }
    return self;
}

- (void)closeWithCompletion:(SSHKitCompletion)completion {
    self.closeBlock(completion);
}

@end
