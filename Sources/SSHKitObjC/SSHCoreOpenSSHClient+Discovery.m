#import "SSHCoreOpenSSHClient+Discovery.h"

#import "SSHCoreOpenSSHClient+Internal.h"
#import "SSHCoreOpenSSHClient+Connect.h"

#import <SSHKitObjC/SSHKitConfiguration.h>
#import <SSHKitObjC/SSHKitError.h>

static NSString *_Nullable SSHCoreNullableStringFromCString(const char *string) {
    return string != NULL ? [NSString stringWithUTF8String:string] : nil;
}

static NSArray<NSNumber *> *SSHCoreAuthenticationMethodsFromMask(int methodMask) {
    NSMutableArray<NSNumber *> *methods = [[NSMutableArray alloc] init];
    if ((methodMask & SSH_AUTH_METHOD_NONE) != 0) {
        [methods addObject:@(SSHKitAuthenticationMethodNone)];
    }
    if ((methodMask & SSH_AUTH_METHOD_PASSWORD) != 0) {
        [methods addObject:@(SSHKitAuthenticationMethodPassword)];
    }
    if ((methodMask & SSH_AUTH_METHOD_PUBLICKEY) != 0) {
        [methods addObject:@(SSHKitAuthenticationMethodPublicKey)];
    }
    if ((methodMask & SSH_AUTH_METHOD_HOSTBASED) != 0) {
        [methods addObject:@(SSHKitAuthenticationMethodHostBased)];
    }
    if ((methodMask & SSH_AUTH_METHOD_INTERACTIVE) != 0) {
        [methods addObject:@(SSHKitAuthenticationMethodKeyboardInteractive)];
    }
    if ((methodMask & SSH_AUTH_METHOD_GSSAPI_MIC) != 0 || (methodMask & SSH_AUTH_METHOD_GSSAPI_KEYEX) != 0) {
        [methods addObject:@(SSHKitAuthenticationMethodGSSAPI)];
    }
    return methods;
}

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wobjc-protocol-method-implementation"

@implementation SSHCoreOpenSSHClient (Discovery)

- (nullable SSHKitAuthenticationDiscoveryResult *)discoverAuthenticationMethodsWithError:(NSError **)error {
    [self emitLogLevel:SSHKitLogLevelInfo phase:@"authDiscovery" message:@"SSH authentication discovery started." metadata:@{}];
    if (![self connectLibSSHSessionWithoutAuthenticationWithError:error]) {
        return nil;
    }

    [self.taskLock lock];
    ssh_session session = self.session;
    [self.taskLock unlock];

    int noneStatus = ssh_userauth_none(session, NULL);
    int methodMask = noneStatus == SSH_AUTH_SUCCESS ? SSH_AUTH_METHOD_NONE : ssh_userauth_list(session, NULL);
    if (methodMask == SSH_AUTH_METHOD_UNKNOWN && noneStatus != SSH_AUTH_SUCCESS) {
        if (error) {
            *error = [self libSSHErrorWithSession:session code:SSHKitErrorCodeAuthenticationFailed fallback:@"Unable to discover SSH authentication methods."];
        }
        [self emitLogLevel:SSHKitLogLevelError phase:@"authDiscovery" message:@"SSH authentication discovery failed." metadata:@{}];
        return nil;
    }

    char *issueBanner = ssh_get_issue_banner(session);
    NSString *issueBannerString = issueBanner != NULL ? [NSString stringWithUTF8String:issueBanner] : nil;
    free(issueBanner);

    const char *serverBanner = ssh_get_serverbanner(session);
    NSArray<NSNumber *> *methods = SSHCoreAuthenticationMethodsFromMask(methodMask);
    [self emitLogLevel:SSHKitLogLevelInfo
                 phase:@"authDiscovery"
               message:@"SSH authentication discovery succeeded."
              metadata:@{@"methodCount": [NSString stringWithFormat:@"%lu", (unsigned long)methods.count]}];
    return [[SSHKitAuthenticationDiscoveryResult alloc] initWithMethods:methods
	                                                            issueBanner:issueBannerString
	                                                           serverBanner:SSHCoreNullableStringFromCString(serverBanner)];
}

- (nullable SSHKitHostKeyDiscoveryResult *)discoverHostKeyWithError:(NSError **)error {
    [self emitLogLevel:SSHKitLogLevelInfo phase:@"hostKeyDiscovery" message:@"SSH host key discovery started." metadata:@{}];
    if (![self connectLibSSHSessionForHostKeyDiscoveryWithError:error]) {
        return nil;
    }

    NSString *fingerprint = self.hostKeySHA256Fingerprint;
    if (fingerprint.length == 0) {
        if (error) {
            *error = SSHKitMakeError(SSHKitErrorCodeHostKeyVerificationFailed, @"SSH host key discovery completed without a fingerprint.");
        }
        [self emitLogLevel:SSHKitLogLevelError phase:@"hostKeyDiscovery" message:@"SSH host key discovery failed." metadata:@{}];
        return nil;
    }

    [self emitLogLevel:SSHKitLogLevelInfo
                 phase:@"hostKeyDiscovery"
               message:@"SSH host key discovery succeeded."
              metadata:@{@"fingerprint": fingerprint}];
    return [[SSHKitHostKeyDiscoveryResult alloc] initWithHost:self.configuration.host
                                                        port:self.configuration.port
                                                 fingerprint:fingerprint];
}

@end

#pragma clang diagnostic pop
