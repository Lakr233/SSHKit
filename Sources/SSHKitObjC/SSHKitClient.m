#import <SSHKitObjC/SSHKitClient.h>

@implementation SSHKitClient

+ (void)connectWithConfiguration:(SSHKitConfiguration *)configuration completion:(SSHKitConnectCompletion)completion {
    NSParameterAssert(configuration != nil);
    NSParameterAssert(completion != nil);

    SSHKitConnection *connection = [[SSHKitConnection alloc] initWithConfiguration:configuration];
    [connection connectWithCompletion:^(NSError *error) {
        if (error != nil) {
            completion(nil, error);
            return;
        }
        completion(connection, nil);
    }];
}

+ (void)discoverAuthenticationMethodsWithConfiguration:(SSHKitConfiguration *)configuration completion:(SSHKitAuthenticationDiscoveryCompletion)completion {
    NSParameterAssert(configuration != nil);
    NSParameterAssert(completion != nil);

    SSHKitConnection *connection = [[SSHKitConnection alloc] initWithConfiguration:configuration];
    [connection discoverAuthenticationMethodsWithCompletion:completion];
}

@end
