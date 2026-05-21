#import "SSHCoreOpenSSHClient.h"

#import <CLibSSH/CLibSSH.h>
#import <SSHKitObjC/SSHKitConnection.h>

@class SSHKitPortForward;
@class SSHKitTunnelChannel;

NS_ASSUME_NONNULL_BEGIN

@interface SSHCoreOpenSSHClient (Tunnels)

- (int)openLocalForwardListenerAtHost:(NSString *)host port:(uint16_t)port boundPort:(uint16_t *)boundPort error:(NSError **)error;
- (uint16_t)boundPortForSocket:(int)socket fallback:(uint16_t)fallback;

@end

NS_ASSUME_NONNULL_END
