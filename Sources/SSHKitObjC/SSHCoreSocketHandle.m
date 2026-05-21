#import "SSHCoreSocketHandle.h"

#include <errno.h>
#include <sys/socket.h>
#include <unistd.h>

@interface SSHCoreSocketHandle ()

@property (nonatomic) NSLock *lock;
@property (nonatomic) int storedFileDescriptor;

@end

@implementation SSHCoreSocketHandle

- (instancetype)initWithFileDescriptor:(int)fileDescriptor {
    NSParameterAssert(fileDescriptor >= 0);

    self = [super init];
    if (self) {
        _lock = [[NSLock alloc] init];
        _storedFileDescriptor = fileDescriptor;
    }
    return self;
}

- (int)fileDescriptor {
    [self.lock lock];
    int fileDescriptor = self.storedFileDescriptor;
    [self.lock unlock];
    return fileDescriptor;
}

- (void)shutdownNow {
    [self.lock lock];
    int fileDescriptor = self.storedFileDescriptor;
    if (fileDescriptor >= 0) {
        int result = shutdown(fileDescriptor, SHUT_RDWR);
        if (result != 0 && errno != ENOTCONN && errno != EBADF) {
#ifdef DEBUG
            NSLog(@"SSHCoreSocketHandle shutdown failed for fd %d: %d", fileDescriptor, errno);
#endif
        }
    }
    [self.lock unlock];
}

- (int)takeFileDescriptorForClose {
    [self.lock lock];
    int fileDescriptor = self.storedFileDescriptor;
    self.storedFileDescriptor = -1;
    [self.lock unlock];
    return fileDescriptor;
}

@end
