#import <SSHKitObjC/SSHKitConnection.h>

typedef void (^SSHKitTunnelReadBlock)(NSUInteger maximumLength, SSHKitTunnelReadCompletion completion);
typedef void (^SSHKitTunnelDataBlock)(NSData *data, SSHKitCompletion completion);
typedef void (^SSHKitTunnelCloseBlock)(SSHKitCompletion completion);

@interface SSHKitTunnelChannel ()

@property (nonatomic, copy) SSHKitTunnelReadBlock readBlock;
@property (nonatomic, copy) SSHKitTunnelDataBlock writeBlock;
@property (nonatomic, copy) SSHKitTunnelCloseBlock closeBlock;

- (instancetype)initWithReadBlock:(SSHKitTunnelReadBlock)readBlock
                       writeBlock:(SSHKitTunnelDataBlock)writeBlock
                       closeBlock:(SSHKitTunnelCloseBlock)closeBlock;

@end
