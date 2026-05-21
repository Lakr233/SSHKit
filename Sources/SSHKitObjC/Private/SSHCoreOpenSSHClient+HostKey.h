#import "SSHCoreOpenSSHClient.h"

#import <CLibSSH/CLibSSH.h>
#import <SSHKitObjC/SSHKitConnection.h>

NS_ASSUME_NONNULL_BEGIN

@interface SSHCoreOpenSSHClient (HostKey)

- (BOOL)verifyLibSSHHostKeyForSession:(ssh_session)session error:(NSError **)error;

@end

NS_ASSUME_NONNULL_END
