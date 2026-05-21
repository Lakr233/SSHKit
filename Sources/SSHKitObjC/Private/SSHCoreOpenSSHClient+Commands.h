#import "SSHCoreOpenSSHClient.h"

#import <CLibSSH/CLibSSH.h>
#import <SSHKitObjC/SSHKitConnection.h>

@class SSHKitCommandResult;

NS_ASSUME_NONNULL_BEGIN

@interface SSHCoreOpenSSHClient (Commands)

- (nullable SSHKitCommandResult *)executeLibSSHCommand:(NSString *)command requestPTY:(BOOL)requestPTY error:(NSError **)error;
- (nullable ssh_channel)openSessionChannelWithError:(NSError **)error;
- (BOOL)readLibSSHChannel:(ssh_channel)channel standardOutput:(NSMutableData *)standardOutput standardError:(NSMutableData *)standardError error:(NSError **)error;

@end

NS_ASSUME_NONNULL_END
