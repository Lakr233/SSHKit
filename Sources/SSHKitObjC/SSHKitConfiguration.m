#import <SSHKitObjC/SSHKitConfiguration.h>
#import <SSHKitObjC/SSHKitError.h>
#import <Security/Security.h>

static NSString *SSHKitNormalizeSHA256Fingerprint(NSString *fingerprint) {
    NSString *trimmed = [fingerprint stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet];
    if (trimmed.length == 0) {
        return @"";
    }
    if ([trimmed rangeOfString:@"SHA256:" options:NSCaseInsensitiveSearch].location == 0) {
        return trimmed;
    }
    return [@"SHA256:" stringByAppendingString:trimmed];
}

static NSString *SSHKitTrustStoreKey(NSString *host, uint16_t port) {
    return [NSString stringWithFormat:@"hostKey:%@:%u", host.lowercaseString, port];
}

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

@implementation SSHKitAuthentication

+ (instancetype)password:(NSString *)password {
    NSParameterAssert(password != nil);

    SSHKitAuthentication *authentication = [[self alloc] init];
    authentication->_kind = SSHKitAuthenticationKindPassword;
    authentication->_password = [password copy];
    return authentication;
}

+ (instancetype)privateKeyFileAtPath:(NSString *)path passphrase:(NSString *)passphrase {
    NSParameterAssert(path.length > 0);

    SSHKitAuthentication *authentication = [[self alloc] init];
    authentication->_kind = SSHKitAuthenticationKindPrivateKeyFile;
    authentication->_privateKeyPath = [path copy];
    authentication->_privateKeyPassphrase = [passphrase copy];
    return authentication;
}

+ (instancetype)keyboardInteractiveWithResponder:(SSHKitKeyboardInteractiveResponder)responder {
    NSParameterAssert(responder != nil);

    SSHKitAuthentication *authentication = [[self alloc] init];
    authentication->_kind = SSHKitAuthenticationKindKeyboardInteractive;
    authentication->_keyboardInteractiveResponder = [responder copy];
    return authentication;
}

+ (instancetype)agent {
    return [self agentWithSocketPath:nil];
}

+ (instancetype)agentWithSocketPath:(NSString *)socketPath {
    SSHKitAuthentication *authentication = [[self alloc] init];
    authentication->_kind = SSHKitAuthenticationKindAgent;
    authentication->_identityAgentPath = [socketPath copy];
    return authentication;
}

- (id)copyWithZone:(NSZone *)zone {
    SSHKitAuthentication *copy = [[[self class] allocWithZone:zone] init];
    copy->_kind = self.kind;
    copy->_password = [self.password copy];
    copy->_privateKeyPath = [self.privateKeyPath copy];
    copy->_privateKeyPassphrase = [self.privateKeyPassphrase copy];
    copy->_keyboardInteractiveResponder = [self.keyboardInteractiveResponder copy];
    copy->_identityAgentPath = [self.identityAgentPath copy];
    return copy;
}

@end

@implementation SSHKitHostTrustStore

- (NSString *)fingerprintForHost:(NSString *)host port:(uint16_t)port error:(NSError **)error {
    NSParameterAssert(host.length > 0);
    NSParameterAssert(port > 0);
    (void)error;
    [self doesNotRecognizeSelector:_cmd];
    return nil;
}

- (BOOL)saveFingerprint:(NSString *)fingerprint host:(NSString *)host port:(uint16_t)port error:(NSError **)error {
    NSParameterAssert(fingerprint.length > 0);
    NSParameterAssert(host.length > 0);
    NSParameterAssert(port > 0);
    (void)error;
    [self doesNotRecognizeSelector:_cmd];
    return NO;
}

- (BOOL)removeFingerprintForHost:(NSString *)host port:(uint16_t)port error:(NSError **)error {
    NSParameterAssert(host.length > 0);
    NSParameterAssert(port > 0);
    (void)error;
    [self doesNotRecognizeSelector:_cmd];
    return NO;
}

@end

@interface SSHKitMemoryTrustStore ()
@property (nonatomic) NSLock *lock;
@property (nonatomic) NSMutableDictionary<NSString *, NSString *> *fingerprints;
@end

@implementation SSHKitMemoryTrustStore

- (instancetype)init {
    return [self initWithFingerprints:nil];
}

- (instancetype)initWithFingerprints:(NSDictionary<NSString *, NSString *> *)fingerprints {
    self = [super init];
    if (self) {
        _lock = [[NSLock alloc] init];
        _fingerprints = [fingerprints mutableCopy] ?: [[NSMutableDictionary alloc] init];
    }
    return self;
}

- (NSString *)fingerprintForHost:(NSString *)host port:(uint16_t)port error:(NSError **)error {
    NSParameterAssert(host.length > 0);
    NSParameterAssert(port > 0);
    (void)error;

    [self.lock lock];
    NSString *fingerprint = self.fingerprints[SSHKitTrustStoreKey(host, port)];
    [self.lock unlock];
    return fingerprint;
}

- (BOOL)saveFingerprint:(NSString *)fingerprint host:(NSString *)host port:(uint16_t)port error:(NSError **)error {
    NSParameterAssert(fingerprint.length > 0);
    NSParameterAssert(host.length > 0);
    NSParameterAssert(port > 0);
    (void)error;

    [self.lock lock];
    self.fingerprints[SSHKitTrustStoreKey(host, port)] = SSHKitNormalizeSHA256Fingerprint(fingerprint);
    [self.lock unlock];
    return YES;
}

- (BOOL)removeFingerprintForHost:(NSString *)host port:(uint16_t)port error:(NSError **)error {
    NSParameterAssert(host.length > 0);
    NSParameterAssert(port > 0);
    (void)error;

    [self.lock lock];
    [self.fingerprints removeObjectForKey:SSHKitTrustStoreKey(host, port)];
    [self.lock unlock];
    return YES;
}

@end

@interface SSHKitKeychainTrustStore ()
@property (nonatomic, copy) NSString *service;
@end

@implementation SSHKitKeychainTrustStore

+ (NSString *)defaultService {
    return @"wiki.qaq.sshkit";
}

- (instancetype)init {
    return [self initWithService:SSHKitKeychainTrustStore.defaultService];
}

- (instancetype)initWithService:(NSString *)service {
    NSParameterAssert(service.length > 0);

    self = [super init];
    if (self) {
        _service = [service copy];
    }
    return self;
}

- (NSString *)fingerprintForHost:(NSString *)host port:(uint16_t)port error:(NSError **)error {
    NSParameterAssert(host.length > 0);
    NSParameterAssert(port > 0);

    NSMutableDictionary *query = [[self queryForHost:host port:port] mutableCopy];
    query[(__bridge NSString *)kSecReturnData] = @YES;
    query[(__bridge NSString *)kSecMatchLimit] = (__bridge id)kSecMatchLimitOne;

    CFTypeRef result = NULL;
    OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)query, &result);
    if (status == errSecItemNotFound) {
        return nil;
    }
    if (status != errSecSuccess) {
        if (error != NULL) {
            *error = [NSError errorWithDomain:NSOSStatusErrorDomain code:status userInfo:nil];
        }
        return nil;
    }

    NSData *data = CFBridgingRelease(result);
    return [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
}

- (BOOL)saveFingerprint:(NSString *)fingerprint host:(NSString *)host port:(uint16_t)port error:(NSError **)error {
    NSParameterAssert(fingerprint.length > 0);
    NSParameterAssert(host.length > 0);
    NSParameterAssert(port > 0);

    NSDictionary *query = [self queryForHost:host port:port];
    SecItemDelete((__bridge CFDictionaryRef)query);

    NSMutableDictionary *item = [query mutableCopy];
    item[(__bridge NSString *)kSecValueData] = [SSHKitNormalizeSHA256Fingerprint(fingerprint) dataUsingEncoding:NSUTF8StringEncoding];
    OSStatus status = SecItemAdd((__bridge CFDictionaryRef)item, NULL);
    if (status == errSecSuccess) {
        return YES;
    }
    if (error != NULL) {
        *error = [NSError errorWithDomain:NSOSStatusErrorDomain code:status userInfo:nil];
    }
    return NO;
}

- (BOOL)removeFingerprintForHost:(NSString *)host port:(uint16_t)port error:(NSError **)error {
    NSParameterAssert(host.length > 0);
    NSParameterAssert(port > 0);

    OSStatus status = SecItemDelete((__bridge CFDictionaryRef)[self queryForHost:host port:port]);
    if (status == errSecSuccess || status == errSecItemNotFound) {
        return YES;
    }
    if (error != NULL) {
        *error = [NSError errorWithDomain:NSOSStatusErrorDomain code:status userInfo:nil];
    }
    return NO;
}

- (NSDictionary *)queryForHost:(NSString *)host port:(uint16_t)port {
    return @{
        (__bridge NSString *)kSecClass: (__bridge NSString *)kSecClassGenericPassword,
        (__bridge NSString *)kSecAttrService: self.service,
        (__bridge NSString *)kSecAttrAccount: SSHKitTrustStoreKey(host, port),
    };
}

@end

@implementation SSHKitHostKeyPolicy

+ (instancetype)knownHostsFile:(NSString *)path {
    NSParameterAssert(path.length > 0);

    SSHKitHostKeyPolicy *policy = [[self alloc] init];
    policy->_kind = SSHKitHostKeyPolicyKindKnownHostsFile;
    policy->_knownHostsPath = [path copy];
    return policy;
}

+ (instancetype)pinnedFingerprint:(NSString *)fingerprint {
    NSParameterAssert(fingerprint.length > 0);

    SSHKitHostKeyPolicy *policy = [[self alloc] init];
    policy->_kind = SSHKitHostKeyPolicyKindPinnedFingerprint;
    policy->_pinnedFingerprint = SSHKitNormalizeSHA256Fingerprint(fingerprint);
    return policy;
}

+ (instancetype)trustStore:(SSHKitHostTrustStore *)trustStore {
    NSParameterAssert(trustStore != nil);

    SSHKitHostKeyPolicy *policy = [[self alloc] init];
    policy->_kind = SSHKitHostKeyPolicyKindTrustedFingerprint;
    policy->_trustStore = trustStore;
    return policy;
}

+ (instancetype)keychainTrustStoreWithService:(NSString *)service {
    return [self trustStore:[[SSHKitKeychainTrustStore alloc] initWithService:service]];
}

+ (instancetype)memoryTrustStore {
    return [self trustStore:[[SSHKitMemoryTrustStore alloc] init]];
}

+ (instancetype)insecureAcceptAnyHostKey {
    SSHKitHostKeyPolicy *policy = [[self alloc] init];
    policy->_kind = SSHKitHostKeyPolicyKindInsecureAcceptAnyHostKey;
    return policy;
}

- (id)copyWithZone:(NSZone *)zone {
    SSHKitHostKeyPolicy *copy = [[[self class] allocWithZone:zone] init];
    copy->_kind = self.kind;
    copy->_knownHostsPath = [self.knownHostsPath copy];
    copy->_pinnedFingerprint = [self.pinnedFingerprint copy];
    copy->_trustStore = self.trustStore;
    return copy;
}

@end

@interface SSHKitLogRecorder ()
@property (nonatomic) NSLock *lock;
@property (nonatomic) NSUInteger capacity;
@property (nonatomic) NSMutableArray<SSHKitLogEvent *> *storedEvents;
@end

@implementation SSHKitLogRecorder

- (instancetype)initWithCapacity:(NSUInteger)capacity {
    NSParameterAssert(capacity > 0);

    self = [super init];
    if (self) {
        _capacity = capacity;
        _lock = [[NSLock alloc] init];
        _storedEvents = [[NSMutableArray alloc] init];
    }
    return self;
}

- (void)recordEvent:(SSHKitLogEvent *)event {
    NSParameterAssert(event != nil);

    [self.lock lock];
    [self.storedEvents addObject:event];
    while (self.storedEvents.count > self.capacity) {
        [self.storedEvents removeObjectAtIndex:0];
    }
    [self.lock unlock];
}

- (NSArray<SSHKitLogEvent *> *)events {
    [self.lock lock];
    NSArray<SSHKitLogEvent *> *events = [self.storedEvents copy];
    [self.lock unlock];
    return events;
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

- (void)setAuthentication:(SSHKitAuthentication *)authentication {
    _authentication = [authentication copy];
    [self applyAuthentication:_authentication];
}

- (void)setHostKeyPolicy:(SSHKitHostKeyPolicy *)hostKeyPolicy {
    _hostKeyPolicy = [hostKeyPolicy copy];
    [self applyHostKeyPolicy:_hostKeyPolicy resolveTrustStore:NO];
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
    copy.pinnedHostKeySHA256Fingerprint = self.pinnedHostKeySHA256Fingerprint;
    copy.trustedHostKeySHA256Fingerprint = self.trustedHostKeySHA256Fingerprint;
    copy.hostKeyTrustStoreError = self.hostKeyTrustStoreError;
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
    copy->_authentication = [self.authentication copy];
    copy->_hostKeyPolicy = [self.hostKeyPolicy copy];
    return copy;
}

- (SSHKitConfiguration *)sshkit_resolvedConfiguration {
    SSHKitConfiguration *configuration = [self copy];
    [configuration applyAuthentication:configuration.authentication];
    [configuration applyHostKeyPolicy:configuration.hostKeyPolicy resolveTrustStore:YES];
    return configuration;
}

- (void)applyAuthentication:(SSHKitAuthentication *)authentication {
    if (authentication == nil) {
        return;
    }

    self.authenticationKind = authentication.kind;
    self.password = authentication.password;
    self.privateKeyPath = authentication.privateKeyPath;
    self.privateKeyPassphrase = authentication.privateKeyPassphrase;
    self.keyboardInteractiveResponder = authentication.keyboardInteractiveResponder;
    self.identityAgentPath = authentication.identityAgentPath;
}

- (void)applyHostKeyPolicy:(SSHKitHostKeyPolicy *)hostKeyPolicy resolveTrustStore:(BOOL)resolveTrustStore {
    if (hostKeyPolicy == nil) {
        return;
    }

    self.hostKeyPolicyKind = hostKeyPolicy.kind;
    self.knownHostsPath = hostKeyPolicy.knownHostsPath;
    self.pinnedHostKeySHA256Fingerprint = hostKeyPolicy.pinnedFingerprint;
    self.trustedHostKeySHA256Fingerprint = nil;
    self.hostKeyTrustStoreError = nil;

    if (hostKeyPolicy.kind != SSHKitHostKeyPolicyKindTrustedFingerprint || resolveTrustStore == NO) {
        return;
    }

    NSError *error = nil;
    NSString *fingerprint = [hostKeyPolicy.trustStore fingerprintForHost:self.host port:self.port error:&error];
    if (error != nil) {
        self.hostKeyTrustStoreError = error.localizedDescription;
        return;
    }
    self.trustedHostKeySHA256Fingerprint = fingerprint;
}

@end
