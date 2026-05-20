#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface SSHCoreCancellationToken : NSObject

@property (nonatomic, readonly, getter=isCancelled) BOOL cancelled;

- (void)cancel;

@end

NS_ASSUME_NONNULL_END
