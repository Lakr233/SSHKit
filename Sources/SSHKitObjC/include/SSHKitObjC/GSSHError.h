#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

FOUNDATION_EXPORT NSErrorDomain const GSSHErrorDomain;

typedef NS_ERROR_ENUM(GSSHErrorDomain, GSSHErrorCode) {
    GSSHErrorCodeUnavailable = 1,
    GSSHErrorCodeInvalidState = 2,
    GSSHErrorCodeConnectionFailed = 3,
    GSSHErrorCodeAuthenticationFailed = 4,
    GSSHErrorCodeCommandFailed = 5,
};

NSError *GSSHMakeError(GSSHErrorCode code, NSString *message);

NS_ASSUME_NONNULL_END
