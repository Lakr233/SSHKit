#import <SSHKitObjC/GSSHError.h>

NSErrorDomain const GSSHErrorDomain = @"SSHKitObjC.GSSHError";

NSError *GSSHMakeError(GSSHErrorCode code, NSString *message) {
    return [NSError errorWithDomain:GSSHErrorDomain
                               code:code
                           userInfo:@{NSLocalizedDescriptionKey: message}];
}
