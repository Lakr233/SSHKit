#import <SSHKitObjC/SSHKitError.h>

NSErrorDomain const SSHKitErrorDomain = @"SSHKitObjC.SSHKitError";

NSError *SSHKitMakeError(SSHKitErrorCode code, NSString *message) {
    return [NSError errorWithDomain:SSHKitErrorDomain
                               code:code
                           userInfo:@{NSLocalizedDescriptionKey: message}];
}
