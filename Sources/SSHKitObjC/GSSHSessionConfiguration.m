#import <SSHKitObjC/GSSHSessionConfiguration.h>

@implementation GSSHSessionConfiguration

- (instancetype)initWithHost:(NSString *)host username:(NSString *)username {
    self = [super init];
    if (self) {
        _host = [host copy];
        _username = [username copy];
        _port = 22;
        _authenticationKind = GSSHAuthenticationKindPassword;
        _hostKeyPolicyKind = GSSHHostKeyPolicyKindKnownHostsFile;
        _timeout = 30;
    }
    return self;
}

- (id)copyWithZone:(NSZone *)zone {
    GSSHSessionConfiguration *copy = [[[self class] allocWithZone:zone] initWithHost:self.host username:self.username];
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
