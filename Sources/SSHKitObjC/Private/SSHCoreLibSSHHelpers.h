#import <Foundation/Foundation.h>

#import <CLibSSH/CLibSSH.h>
#import <SSHKitObjC/SSHKitConfiguration.h>

@class SSHKitConfiguration;

NS_ASSUME_NONNULL_BEGIN

extern const int32_t SSHCoreAbnormalExitStatus;

NSString *_Nullable SSHCoreSHA256FingerprintForSession(ssh_session session);
BOOL SSHCoreFingerprintMatches(NSString *_Nullable actualFingerprint, NSString *_Nullable expectedFingerprint);
BOOL SSHCoreApplyAlgorithmProfile(ssh_session session, SSHKitConfiguration *configuration, NSString *_Nullable *_Nullable failedField);

void SSHCoreCloseDescriptor(int *fileDescriptor);
void SSHCoreShutdownDescriptor(int fileDescriptor);
void SSHCoreFreeForwardChannel(ssh_channel channel);

NSString *SSHCoreAuthenticationName(SSHKitAuthenticationKind kind);
NSString *SSHCoreHostKeyPolicyName(SSHKitHostKeyPolicyKind kind);

NS_ASSUME_NONNULL_END
