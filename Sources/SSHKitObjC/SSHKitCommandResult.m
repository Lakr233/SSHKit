#import <SSHKitObjC/SSHKitConnection.h>

@implementation SSHKitCommandResult

- (instancetype)initWithStandardOutput:(NSData *)standardOutput
                         standardError:(NSData *)standardError
                            exitStatus:(int32_t)exitStatus {
    return [self initWithStandardOutput:standardOutput standardError:standardError exitStatus:exitStatus exitSignal:nil];
}

- (instancetype)initWithStandardOutput:(NSData *)standardOutput
                         standardError:(NSData *)standardError
                            exitStatus:(int32_t)exitStatus
                            exitSignal:(NSString *)exitSignal {
    self = [super init];
    if (self) {
        _standardOutput = [standardOutput copy];
        _standardError = [standardError copy];
        _exitStatus = exitStatus;
        _exitSignal = [exitSignal copy];
    }
    return self;
}

@end

@implementation SSHKitAuthenticationDiscoveryResult

- (instancetype)initWithMethods:(NSArray<NSNumber *> *)methods
                    issueBanner:(NSString *)issueBanner
                   serverBanner:(NSString *)serverBanner {
    self = [super init];
    if (self) {
        _methods = [methods copy];
        _issueBanner = [issueBanner copy];
        _serverBanner = [serverBanner copy];
    }
    return self;
}

@end

@implementation SSHKitHostKeyDiscoveryResult

- (instancetype)initWithHost:(NSString *)host
                        port:(uint16_t)port
                 fingerprint:(NSString *)fingerprint {
    NSParameterAssert(host.length > 0);
    NSParameterAssert(port > 0);
    NSParameterAssert(fingerprint.length > 0);

    self = [super init];
    if (self) {
        _host = [host copy];
        _port = port;
        _fingerprint = [fingerprint copy];
    }
    return self;
}

@end

@implementation SSHKitCommandEvent

- (instancetype)initWithKind:(SSHKitCommandEventKind)kind data:(NSData *)data exitStatus:(int32_t)exitStatus {
    return [self initWithKind:kind data:data exitStatus:exitStatus exitSignal:nil];
}

- (instancetype)initWithKind:(SSHKitCommandEventKind)kind
                        data:(NSData *)data
                  exitStatus:(int32_t)exitStatus
                  exitSignal:(NSString *)exitSignal {
    self = [super init];
    if (self) {
        _kind = kind;
        _data = [data copy];
        _exitStatus = exitStatus;
        _exitSignal = [exitSignal copy];
    }
    return self;
}

@end

@implementation SSHKitShellEvent

- (instancetype)initWithKind:(SSHKitShellEventKind)kind data:(NSData *)data exitStatus:(int32_t)exitStatus {
    self = [super init];
    if (self) {
        _kind = kind;
        _data = [data copy];
        _exitStatus = exitStatus;
    }
    return self;
}

@end
