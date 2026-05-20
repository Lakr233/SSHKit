#import <SSHKitObjC/SSHKitConfiguration.h>

@implementation SSHKitConfiguration

- (instancetype)initWithHost:(NSString *)host username:(NSString *)username {
    NSParameterAssert(host.length > 0);
    NSParameterAssert(username.length > 0);

    self = [super init];
    if (self) {
        _host = [host copy];
        _username = [username copy];
        _port = 22;
        _authenticationKind = SSHKitAuthenticationKindPassword;
        _hostKeyPolicyKind = SSHKitHostKeyPolicyKindKnownHostsFile;
        _timeout = 30;
    }
    return self;
}

- (void)setPort:(uint16_t)port {
    NSParameterAssert(port > 0);
    _port = port;
}

- (void)setTimeout:(NSTimeInterval)timeout {
    NSParameterAssert(timeout > 0);
    _timeout = timeout;
}

- (id)copyWithZone:(NSZone *)zone {
    SSHKitConfiguration *copy = [[[self class] allocWithZone:zone] initWithHost:self.host username:self.username];
    copy.port = self.port;
    copy.authenticationKind = self.authenticationKind;
    copy.password = self.password;
    copy.privateKeyPath = self.privateKeyPath;
    copy.privateKeyPassphrase = self.privateKeyPassphrase;
    copy.hostKeyPolicyKind = self.hostKeyPolicyKind;
    copy.knownHostsPath = self.knownHostsPath;
    copy.timeout = self.timeout;
    return copy;
}

@end
