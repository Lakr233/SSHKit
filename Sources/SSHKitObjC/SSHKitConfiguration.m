#import <SSHKitObjC/SSHKitConfiguration.h>

@implementation SSHKitLogEvent

- (instancetype)initWithLevel:(SSHKitLogLevel)level
                        phase:(NSString *)phase
                      message:(NSString *)message
                     metadata:(NSDictionary<NSString *, NSString *> *)metadata {
    NSParameterAssert(phase.length > 0);
    NSParameterAssert(message.length > 0);
    NSParameterAssert(metadata != nil);

    self = [super init];
    if (self) {
        _level = level;
        _phase = [phase copy];
        _message = [message copy];
        _metadata = [metadata copy];
        _timestamp = [NSDate date];
    }
    return self;
}

@end

@implementation SSHKitKeyboardInteractivePrompt

- (instancetype)initWithPrompt:(NSString *)prompt echo:(BOOL)echo {
    NSParameterAssert(prompt != nil);

    self = [super init];
    if (self) {
        _prompt = [prompt copy];
        _echo = echo;
    }
    return self;
}

@end

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
        _proxyRouteKind = SSHKitProxyRouteKindNone;
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
    copy.keyboardInteractiveResponder = self.keyboardInteractiveResponder;
    copy.identityAgentPath = self.identityAgentPath;
    copy.hostKeyPolicyKind = self.hostKeyPolicyKind;
    copy.knownHostsPath = self.knownHostsPath;
    copy.timeout = self.timeout;
    copy.logHandler = self.logHandler;
    copy.proxyRouteKind = self.proxyRouteKind;
    copy.proxyHost = self.proxyHost;
    copy.proxyPort = self.proxyPort;
    copy.proxyUsername = self.proxyUsername;
    copy.proxyPassword = self.proxyPassword;
    copy.proxyJumpConfiguration = self.proxyJumpConfiguration;
    copy.keyExchangeAlgorithms = self.keyExchangeAlgorithms;
    copy.hostKeyAlgorithms = self.hostKeyAlgorithms;
    copy.publicKeyAcceptedAlgorithms = self.publicKeyAcceptedAlgorithms;
    copy.ciphersClientToServer = self.ciphersClientToServer;
    copy.ciphersServerToClient = self.ciphersServerToClient;
    copy.macsClientToServer = self.macsClientToServer;
    copy.macsServerToClient = self.macsServerToClient;
    copy.minimumRSAKeySize = self.minimumRSAKeySize;
    return copy;
}

@end
