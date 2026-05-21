#import <Foundation/Foundation.h>
#import <SSHKitObjC/SSHKitConnection.h>

NS_ASSUME_NONNULL_BEGIN

typedef void (^SSHKitConnectCompletion)(SSHKitConnection *_Nullable connection, NSError *_Nullable error);

@interface SSHKitClient : NSObject

+ (void)connectWithConfiguration:(SSHKitConfiguration *)configuration completion:(SSHKitConnectCompletion)completion;
+ (void)discoverAuthenticationMethodsWithConfiguration:(SSHKitConfiguration *)configuration completion:(SSHKitAuthenticationDiscoveryCompletion)completion;

@end

NS_ASSUME_NONNULL_END
