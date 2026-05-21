#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface SSHCoreSocketHandle : NSObject

@property (nonatomic, readonly) int fileDescriptor;

- (instancetype)initWithFileDescriptor:(int)fileDescriptor;
- (void)shutdownNow;
- (int)takeFileDescriptorForClose;

@end

NS_ASSUME_NONNULL_END
