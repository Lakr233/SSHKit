#import "SSHCoreOpenSSHClient.h"

#import <CLibSSH/CLibSSH.h>
#import <SSHKitObjC/SSHKitConnection.h>

NS_ASSUME_NONNULL_BEGIN

@interface SSHCoreOpenSSHClient (Connect)

- (BOOL)connectLibSSHSessionWithError:(NSError **)error;
- (BOOL)connectLibSSHSessionWithoutAuthenticationWithError:(NSError **)error;
- (BOOL)connectLibSSHSessionForHostKeyDiscoveryWithError:(NSError **)error;

@end

NS_ASSUME_NONNULL_END
