#import "SSHCoreCancellationToken.h"

@interface SSHCoreCancellationToken ()

@property (nonatomic) NSLock *lock;
@property (nonatomic) BOOL storedCancelled;

@end

@implementation SSHCoreCancellationToken

- (instancetype)init {
    self = [super init];
    if (self) {
        _lock = [[NSLock alloc] init];
    }
    return self;
}

- (BOOL)isCancelled {
    [self.lock lock];
    BOOL cancelled = self.storedCancelled;
    [self.lock unlock];
    return cancelled;
}

- (void)cancel {
    [self.lock lock];
    self.storedCancelled = YES;
    [self.lock unlock];
}

@end
