#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

FOUNDATION_EXPORT NSErrorDomain const SSHKitErrorDomain;

typedef NS_ERROR_ENUM(SSHKitErrorDomain, SSHKitErrorCode) {
    SSHKitErrorCodeUnavailable = 1,
    SSHKitErrorCodeInvalidState = 2,
    SSHKitErrorCodeConnectionFailed = 3,
    SSHKitErrorCodeAuthenticationFailed = 4,
    SSHKitErrorCodeCommandFailed = 5,
    SSHKitErrorCodeHostKeyVerificationFailed = 6,
    SSHKitErrorCodeCancelled = 7,
};

NSError *SSHKitMakeError(SSHKitErrorCode code, NSString *message);

NS_ASSUME_NONNULL_END
