#import <Foundation/Foundation.h>
#import <SSHKitObjC/SSHKitConnection.h>

NS_ASSUME_NONNULL_BEGIN

typedef void (^SSHKitPortForwardCloseBlock)(SSHKitCompletion completion);

@interface SSHKitPortForward ()

@property (nonatomic, copy, readwrite) NSString *boundHost;
@property (nonatomic, readwrite) uint16_t boundPort;
@property (nonatomic, copy) SSHKitPortForwardCloseBlock closeBlock;

- (instancetype)initWithBoundHost:(NSString *)boundHost
                         boundPort:(uint16_t)boundPort
                         closeBlock:(SSHKitPortForwardCloseBlock)closeBlock;

@end

NS_ASSUME_NONNULL_END
