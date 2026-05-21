#import "SSHCoreOpenSSHClient.h"

#import <CLibSSH/CLibSSH.h>
#import <SSHKitObjC/SSHKitConfiguration.h>
#import <SSHKitObjC/SSHKitConnection.h>
#import <SSHKitObjC/SSHKitError.h>
#include <libssh/callbacks.h>
#import "SSHCoreSessionWorker.h"
#import "SSHCoreSocketHandle.h"
#import "SSHKitCommand+Private.h"
#import "SSHKitPortForward+Private.h"
#import "SSHKitSFTPClient+Private.h"
#import "SSHKitShell+Private.h"
#import "SSHKitTunnelChannel+Private.h"

#include <objc/message.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <math.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

@class SSHCoreOpenSSHClient;

static const int32_t SSHCoreAbnormalExitStatus = -1;
static const uint64_t SSHCoreSFTPMaximumReadFileSize = 64 * 1024 * 1024;

static NSString *SSHCoreNormalizeSHA256Fingerprint(NSString *fingerprint) {
    NSString *trimmed = [fingerprint stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet];
    if (trimmed.length == 0) {
        return @"";
    }
    if ([trimmed rangeOfString:@"SHA256:" options:NSCaseInsensitiveSearch].location == 0) {
        return trimmed;
    }
    return [@"SHA256:" stringByAppendingString:trimmed];
}

static NSString *SSHCoreSHA256FingerprintForSession(ssh_session session) {
    ssh_key key = NULL;
    unsigned char *hash = NULL;
    size_t hashLength = 0;
    char *fingerprint = NULL;
    NSString *result = nil;

    if (ssh_get_server_publickey(session, &key) != SSH_OK || key == NULL) {
        goto cleanup;
    }
    if (ssh_get_publickey_hash(key, SSH_PUBLICKEY_HASH_SHA256, &hash, &hashLength) != SSH_OK || hash == NULL) {
        goto cleanup;
    }
    fingerprint = ssh_get_fingerprint_hash(SSH_PUBLICKEY_HASH_SHA256, hash, hashLength);
    if (fingerprint == NULL) {
        goto cleanup;
    }
    result = @(fingerprint);

cleanup:
    if (fingerprint != NULL) {
        SSH_STRING_FREE_CHAR(fingerprint);
    }
    if (hash != NULL) {
        ssh_clean_pubkey_hash(&hash);
    }
    if (key != NULL) {
        ssh_key_free(key);
    }
    return result;
}

static BOOL SSHCoreFingerprintMatches(NSString *actualFingerprint, NSString *expectedFingerprint) {
    NSString *actual = SSHCoreNormalizeSHA256Fingerprint(actualFingerprint);
    NSString *expected = SSHCoreNormalizeSHA256Fingerprint(expectedFingerprint);
    return actual.length > 0 && expected.length > 0 && [actual isEqualToString:expected];
}

static BOOL SSHCoreSetAlgorithmString(ssh_session session, enum ssh_options_e option, NSString *value, NSString *name, NSString **failedField) {
    if (value.length == 0) {
        return YES;
    }
    if (ssh_options_set(session, option, value.UTF8String) == SSH_OK) {
        return YES;
    }
    if (failedField) {
        *failedField = name;
    }
    return NO;
}

static BOOL SSHCoreSetAlgorithmNumber(ssh_session session, enum ssh_options_e option, NSNumber *value, NSString *name, NSString **failedField) {
    if (value == nil) {
        return YES;
    }
    int intValue = value.intValue;
    if (ssh_options_set(session, option, &intValue) == SSH_OK) {
        return YES;
    }
    if (failedField) {
        *failedField = name;
    }
    return NO;
}

static BOOL SSHCoreApplyAlgorithmProfile(ssh_session session, SSHKitConfiguration *configuration, NSString **failedField) {
    return SSHCoreSetAlgorithmString(session, SSH_OPTIONS_KEY_EXCHANGE, configuration.keyExchangeAlgorithms, @"keyExchangeAlgorithms", failedField) &&
           SSHCoreSetAlgorithmString(session, SSH_OPTIONS_HOSTKEYS, configuration.hostKeyAlgorithms, @"hostKeyAlgorithms", failedField) &&
           SSHCoreSetAlgorithmString(session, SSH_OPTIONS_PUBLICKEY_ACCEPTED_TYPES, configuration.publicKeyAcceptedAlgorithms, @"publicKeyAcceptedAlgorithms", failedField) &&
           SSHCoreSetAlgorithmString(session, SSH_OPTIONS_CIPHERS_C_S, configuration.ciphersClientToServer, @"ciphersClientToServer", failedField) &&
           SSHCoreSetAlgorithmString(session, SSH_OPTIONS_CIPHERS_S_C, configuration.ciphersServerToClient, @"ciphersServerToClient", failedField) &&
           SSHCoreSetAlgorithmString(session, SSH_OPTIONS_HMAC_C_S, configuration.macsClientToServer, @"macsClientToServer", failedField) &&
           SSHCoreSetAlgorithmString(session, SSH_OPTIONS_HMAC_S_C, configuration.macsServerToClient, @"macsServerToClient", failedField) &&
           SSHCoreSetAlgorithmNumber(session, SSH_OPTIONS_RSA_MIN_SIZE, configuration.minimumRSAKeySize, @"minimumRSAKeySize", failedField);
}

static int SSHCoreProxyJumpBeforeConnection(ssh_session session, void *userdata) {
    SSHKitConfiguration *configuration = (__bridge SSHKitConfiguration *)userdata;
    long timeout = (long)ceil(configuration.timeout);
    if (ssh_options_set(session, SSH_OPTIONS_TIMEOUT, &timeout) != SSH_OK) {
        return SSH_ERROR;
    }
    if (!SSHCoreApplyAlgorithmProfile(session, configuration, NULL)) {
        return SSH_ERROR;
    }
    if (configuration.hostKeyPolicyKind == SSHKitHostKeyPolicyKindKnownHostsFile) {
        if (configuration.knownHostsPath.length == 0) {
            return SSH_ERROR;
        }
        if (ssh_options_set(session, SSH_OPTIONS_KNOWNHOSTS, configuration.knownHostsPath.UTF8String) != SSH_OK) {
            return SSH_ERROR;
        }
    }
    if (configuration.authenticationKind == SSHKitAuthenticationKindAgent && configuration.identityAgentPath.length > 0) {
        if (ssh_options_set(session, SSH_OPTIONS_IDENTITY_AGENT, configuration.identityAgentPath.UTF8String) != SSH_OK) {
            return SSH_ERROR;
        }
    }
    return SSH_OK;
}

static int SSHCoreProxyJumpVerifyKnownHost(ssh_session session, void *userdata) {
    SSHKitConfiguration *configuration = (__bridge SSHKitConfiguration *)userdata;
    if (configuration.hostKeyPolicyKind == SSHKitHostKeyPolicyKindInsecureAcceptAnyHostKey) {
        return SSH_OK;
    }
    NSString *fingerprint = SSHCoreSHA256FingerprintForSession(session);
    if (configuration.hostKeyPolicyKind == SSHKitHostKeyPolicyKindPinnedFingerprint) {
        return SSHCoreFingerprintMatches(fingerprint, configuration.pinnedHostKeySHA256Fingerprint) ? SSH_OK : SSH_ERROR;
    }
    if (configuration.hostKeyPolicyKind == SSHKitHostKeyPolicyKindTrustedFingerprint) {
        return configuration.hostKeyTrustStoreError.length == 0 &&
               SSHCoreFingerprintMatches(fingerprint, configuration.trustedHostKeySHA256Fingerprint)
                   ? SSH_OK
                   : SSH_ERROR;
    }
    return ssh_session_is_known_server(session) == SSH_KNOWN_HOSTS_OK ? SSH_OK : SSH_ERROR;
}

static int SSHCoreProxyJumpAuthenticate(ssh_session session, void *userdata) {
    SSHKitConfiguration *configuration = (__bridge SSHKitConfiguration *)userdata;
    int rc = SSH_AUTH_DENIED;
    switch (configuration.authenticationKind) {
        case SSHKitAuthenticationKindPassword:
            if (configuration.password.length == 0) {
                return SSH_ERROR;
            }
            rc = ssh_userauth_password(session, NULL, configuration.password.UTF8String);
            break;
        case SSHKitAuthenticationKindPrivateKeyFile: {
            if (configuration.privateKeyPath.length == 0) {
                return SSH_ERROR;
            }
            ssh_key privateKey = NULL;
            const char *passphrase = configuration.privateKeyPassphrase.length > 0 ? configuration.privateKeyPassphrase.UTF8String : NULL;
            if (ssh_pki_import_privkey_file(configuration.privateKeyPath.UTF8String, passphrase, NULL, NULL, &privateKey) != SSH_OK) {
                return SSH_ERROR;
            }
            rc = ssh_userauth_publickey(session, NULL, privateKey);
            ssh_key_free(privateKey);
            break;
        }
        case SSHKitAuthenticationKindKeyboardInteractive:
            return SSH_ERROR;
        case SSHKitAuthenticationKindAgent:
            rc = ssh_userauth_agent(session, NULL);
            break;
    }
    return rc == SSH_AUTH_SUCCESS ? SSH_OK : SSH_ERROR;
}

static int SSHCoreSFTPFileOpenFlagsToPOSIX(SSHKitSFTPFileOpenFlags flags) {
    BOOL wantsRead = (flags & SSHKitSFTPFileOpenFlagRead) == SSHKitSFTPFileOpenFlagRead;
    BOOL wantsWrite = (flags & SSHKitSFTPFileOpenFlagWrite) == SSHKitSFTPFileOpenFlagWrite;
    int posixFlags = O_RDONLY;
    if (wantsRead && wantsWrite) {
        posixFlags = O_RDWR;
    } else if (wantsWrite) {
        posixFlags = O_WRONLY;
    }
    if ((flags & SSHKitSFTPFileOpenFlagCreate) == SSHKitSFTPFileOpenFlagCreate) {
        posixFlags |= O_CREAT;
    }
    if ((flags & SSHKitSFTPFileOpenFlagTruncate) == SSHKitSFTPFileOpenFlagTruncate) {
        posixFlags |= O_TRUNC;
    }
    if ((flags & SSHKitSFTPFileOpenFlagAppend) == SSHKitSFTPFileOpenFlagAppend) {
        posixFlags |= O_APPEND;
    }
    return posixFlags;
}

static void SSHCoreCloseDescriptor(int *fileDescriptor) {
    if (*fileDescriptor < 0) {
        return;
    }

    shutdown(*fileDescriptor, SHUT_RDWR);
    close(*fileDescriptor);
    *fileDescriptor = -1;
}

static void SSHCoreShutdownDescriptor(int fileDescriptor) {
    if (fileDescriptor < 0) {
        return;
    }

    shutdown(fileDescriptor, SHUT_RDWR);
}

static NSString *SSHCoreStringFromCString(const char *string) {
    return string != NULL ? [NSString stringWithUTF8String:string] : @"";
}

static NSString *_Nullable SSHCoreNullableStringFromCString(const char *string) {
    return string != NULL ? [NSString stringWithUTF8String:string] : nil;
}

static NSArray<NSNumber *> *SSHCoreAuthenticationMethodsFromMask(int methodMask) {
    NSMutableArray<NSNumber *> *methods = [[NSMutableArray alloc] init];
    if ((methodMask & SSH_AUTH_METHOD_NONE) != 0) {
        [methods addObject:@(SSHKitAuthenticationMethodNone)];
    }
    if ((methodMask & SSH_AUTH_METHOD_PASSWORD) != 0) {
        [methods addObject:@(SSHKitAuthenticationMethodPassword)];
    }
    if ((methodMask & SSH_AUTH_METHOD_PUBLICKEY) != 0) {
        [methods addObject:@(SSHKitAuthenticationMethodPublicKey)];
    }
    if ((methodMask & SSH_AUTH_METHOD_HOSTBASED) != 0) {
        [methods addObject:@(SSHKitAuthenticationMethodHostBased)];
    }
    if ((methodMask & SSH_AUTH_METHOD_INTERACTIVE) != 0) {
        [methods addObject:@(SSHKitAuthenticationMethodKeyboardInteractive)];
    }
    if ((methodMask & SSH_AUTH_METHOD_GSSAPI_MIC) != 0 || (methodMask & SSH_AUTH_METHOD_GSSAPI_KEYEX) != 0) {
        [methods addObject:@(SSHKitAuthenticationMethodGSSAPI)];
    }
    return methods;
}

static NSString *SSHCoreAuthenticationName(SSHKitAuthenticationKind kind) {
    switch (kind) {
        case SSHKitAuthenticationKindPassword:
            return @"password";
        case SSHKitAuthenticationKindPrivateKeyFile:
            return @"privateKeyFile";
        case SSHKitAuthenticationKindKeyboardInteractive:
            return @"keyboardInteractive";
        case SSHKitAuthenticationKindAgent:
            return @"agent";
    }
}

static NSString *SSHCoreHostKeyPolicyName(SSHKitHostKeyPolicyKind kind) {
    switch (kind) {
        case SSHKitHostKeyPolicyKindInsecureAcceptAnyHostKey:
            return @"insecureAcceptAnyHostKey";
        case SSHKitHostKeyPolicyKindKnownHostsFile:
            return @"knownHostsFile";
        case SSHKitHostKeyPolicyKindPinnedFingerprint:
            return @"pinnedFingerprint";
        case SSHKitHostKeyPolicyKindTrustedFingerprint:
            return @"trustedFingerprint";
    }
}

@interface SSHCoreLibSSHCommandRuntime : NSObject

- (instancetype)initWithChannel:(ssh_channel)channel
                    workerQueue:(dispatch_queue_t)workerQueue
                    eventHandler:(SSHKitCommandEventHandler)eventHandler
                        onClosed:(SSHCoreCommandClosedBlock)onClosed;
- (void)start;
- (void)writeData:(NSData *)data completion:(SSHKitCompletion)completion;
- (void)sendEOFWithCompletion:(SSHKitCompletion)completion;
- (void)closeWithCompletion:(SSHKitCompletion)completion;
- (void)invalidateOnWorkerQueue;

@end

@interface SSHCoreLibSSHCommandRuntime ()

@property (nonatomic) ssh_channel channel;
@property (nonatomic) dispatch_queue_t workerQueue;
@property (nonatomic, copy) SSHKitCommandEventHandler eventHandler;
@property (nonatomic, copy) SSHCoreCommandClosedBlock onClosed;
@property (nonatomic) BOOL finished;
@property (nonatomic) BOOL didSendEOF;

@end

@implementation SSHCoreLibSSHCommandRuntime

- (instancetype)initWithChannel:(ssh_channel)channel
                    workerQueue:(dispatch_queue_t)workerQueue
                    eventHandler:(SSHKitCommandEventHandler)eventHandler
                        onClosed:(SSHCoreCommandClosedBlock)onClosed {
    NSParameterAssert(channel != NULL);
    NSParameterAssert(workerQueue != nil);

    self = [super init];
    if (self) {
        _channel = channel;
        _workerQueue = workerQueue;
        _eventHandler = [eventHandler copy];
        _onClosed = [onClosed copy];
    }
    return self;
}

- (void)start {
    dispatch_async(self.workerQueue, ^{
        [self readAvailableDataAndScheduleNextRead];
    });
}

- (void)writeData:(NSData *)data completion:(SSHKitCompletion)completion {
    dispatch_async(self.workerQueue, ^{
        if (self.finished || self.didSendEOF || self.channel == NULL) {
            completion(SSHKitMakeError(SSHKitErrorCodeInvalidState, @"SSH command input is closed."));
            return;
        }

        const uint8_t *bytes = data.bytes;
        NSUInteger remaining = data.length;
        while (remaining > 0) {
            uint32_t chunkLength = remaining > UINT32_MAX ? UINT32_MAX : (uint32_t)remaining;
            int written = ssh_channel_write(self.channel, bytes, chunkLength);
            if (written == SSH_ERROR) {
                completion(SSHKitMakeError(SSHKitErrorCodeConnectionFailed, @"Unable to write to SSH command."));
                return;
            }
            if (written <= 0) {
                completion(SSHKitMakeError(SSHKitErrorCodeConnectionFailed, @"SSH command write made no progress."));
                return;
            }
            bytes += written;
            remaining -= (NSUInteger)written;
        }

        completion(nil);
    });
}

- (void)sendEOFWithCompletion:(SSHKitCompletion)completion {
    dispatch_async(self.workerQueue, ^{
        if (self.finished || self.didSendEOF || self.channel == NULL) {
            completion(SSHKitMakeError(SSHKitErrorCodeInvalidState, @"SSH command input is closed."));
            return;
        }

        if (ssh_channel_send_eof(self.channel) != SSH_OK) {
            completion(SSHKitMakeError(SSHKitErrorCodeConnectionFailed, @"Unable to send SSH command EOF."));
            return;
        }

        self.didSendEOF = YES;
        completion(nil);
    });
}

- (void)closeWithCompletion:(SSHKitCompletion)completion {
    dispatch_async(self.workerQueue, ^{
        if (self.finished) {
            completion(nil);
            return;
        }

        [self finishWithExitStatus:SSHCoreAbnormalExitStatus exitSignal:nil];
        completion(nil);
    });
}

- (void)readAvailableDataAndScheduleNextRead {
    if (self.finished || self.channel == NULL) {
        return;
    }

    if (![self drainStream:0 eventKind:SSHKitCommandEventKindStandardOutput] ||
        ![self drainStream:1 eventKind:SSHKitCommandEventKindStandardError]) {
        [self finishWithExitStatus:SSHCoreAbnormalExitStatus exitSignal:nil];
        return;
    }

    if (ssh_channel_is_eof(self.channel) || ssh_channel_is_closed(self.channel)) {
        int32_t exitStatus = SSHCoreAbnormalExitStatus;
        NSString *exitSignal = nil;
        [self getExitStatus:&exitStatus exitSignal:&exitSignal];
        [self finishWithExitStatus:exitStatus exitSignal:exitSignal];
        return;
    }

    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 50 * NSEC_PER_MSEC), self.workerQueue, ^{
        [self readAvailableDataAndScheduleNextRead];
    });
}

- (BOOL)drainStream:(int)isStderr eventKind:(SSHKitCommandEventKind)eventKind {
    char buffer[32768];
    while (YES) {
        int byteCount = ssh_channel_read_nonblocking(self.channel, buffer, sizeof(buffer), isStderr);
        if (byteCount == SSH_ERROR) {
            return NO;
        }
        if (byteCount <= 0) {
            return YES;
        }

        NSData *data = [NSData dataWithBytes:buffer length:(NSUInteger)byteCount];
        SSHKitCommandEvent *event = [[SSHKitCommandEvent alloc] initWithKind:eventKind data:data exitStatus:0];
        self.eventHandler(event);
    }
}

- (BOOL)getExitStatus:(int32_t *)exitStatus exitSignal:(NSString **)exitSignal {
    uint32_t exitCode = 0;
    char *rawExitSignal = NULL;
    if (self.channel == NULL) {
        if (exitStatus != NULL) {
            *exitStatus = SSHCoreAbnormalExitStatus;
        }
        if (exitSignal != NULL) {
            *exitSignal = nil;
        }
        return NO;
    }

    int exitState = ssh_channel_get_exit_state(self.channel, &exitCode, &rawExitSignal, NULL);
    if (exitState != SSH_OK) {
        free(rawExitSignal);
        if (exitStatus != NULL) {
            *exitStatus = SSHCoreAbnormalExitStatus;
        }
        if (exitSignal != NULL) {
            *exitSignal = nil;
        }
        return NO;
    }

    if (exitStatus != NULL) {
        *exitStatus = (int32_t)exitCode;
    }
    if (exitSignal != NULL) {
        *exitSignal = rawExitSignal != NULL ? [NSString stringWithUTF8String:rawExitSignal] : nil;
    }
    free(rawExitSignal);
    return YES;
}

- (void)finishWithExitStatus:(int32_t)exitStatus exitSignal:(NSString *)exitSignal {
    if (self.finished) {
        return;
    }

    self.finished = YES;
    ssh_channel channel = self.channel;
    self.channel = NULL;
    if (channel != NULL) {
        ssh_channel_send_eof(channel);
        ssh_channel_close(channel);
        ssh_channel_free(channel);
    }

    self.onClosed(exitStatus, exitSignal);
}

- (void)invalidateOnWorkerQueue {
    if (self.finished) {
        return;
    }

    self.finished = YES;
    ssh_channel channel = self.channel;
    self.channel = NULL;
    if (channel != NULL) {
        ssh_channel_send_eof(channel);
        ssh_channel_close(channel);
        ssh_channel_free(channel);
    }
}

- (void)dealloc {
    ssh_channel channel = self.channel;
    if (channel == NULL) {
        return;
    }
    dispatch_async(self.workerQueue, ^{
        ssh_channel_send_eof(channel);
        ssh_channel_close(channel);
        ssh_channel_free(channel);
    });
}

@end

@interface SSHCoreLibSSHShellRuntime : NSObject

- (instancetype)initWithChannel:(ssh_channel)channel
                    workerQueue:(dispatch_queue_t)workerQueue
                    eventHandler:(SSHKitShellEventHandler)eventHandler
                        onClosed:(SSHCoreShellClosedBlock)onClosed;
- (void)start;
- (void)writeData:(NSData *)data completion:(SSHKitCompletion)completion;
- (void)resizeWithColumns:(uint16_t)columns rows:(uint16_t)rows completion:(SSHKitCompletion)completion;
- (void)closeWithCompletion:(SSHKitCompletion)completion;
- (void)invalidateOnWorkerQueue;

@end

@interface SSHCoreLibSSHShellRuntime ()

@property (nonatomic) ssh_channel channel;
@property (nonatomic) dispatch_queue_t workerQueue;
@property (nonatomic, copy) SSHKitShellEventHandler eventHandler;
@property (nonatomic, copy) SSHCoreShellClosedBlock onClosed;
@property (nonatomic) BOOL finished;

@end

@implementation SSHCoreLibSSHShellRuntime

- (instancetype)initWithChannel:(ssh_channel)channel
                    workerQueue:(dispatch_queue_t)workerQueue
                    eventHandler:(SSHKitShellEventHandler)eventHandler
                        onClosed:(SSHCoreShellClosedBlock)onClosed {
    NSParameterAssert(channel != NULL);
    NSParameterAssert(workerQueue != nil);

    self = [super init];
    if (self) {
        _channel = channel;
        _workerQueue = workerQueue;
        _eventHandler = [eventHandler copy];
        _onClosed = [onClosed copy];
    }
    return self;
}

- (void)start {
    dispatch_async(self.workerQueue, ^{
        [self readAvailableDataAndScheduleNextRead];
    });
}

- (void)writeData:(NSData *)data completion:(SSHKitCompletion)completion {
    dispatch_async(self.workerQueue, ^{
        if (self.finished || self.channel == NULL) {
            completion(SSHKitMakeError(SSHKitErrorCodeInvalidState, @"SSH shell is closed."));
            return;
        }

        const uint8_t *bytes = data.bytes;
        NSUInteger remaining = data.length;
        while (remaining > 0) {
            uint32_t chunkLength = remaining > UINT32_MAX ? UINT32_MAX : (uint32_t)remaining;
            int written = ssh_channel_write(self.channel, bytes, chunkLength);
            if (written == SSH_ERROR) {
                completion(SSHKitMakeError(SSHKitErrorCodeConnectionFailed, @"Unable to write to SSH shell."));
                return;
            }
            if (written <= 0) {
                completion(SSHKitMakeError(SSHKitErrorCodeConnectionFailed, @"SSH shell write made no progress."));
                return;
            }
            bytes += written;
            remaining -= (NSUInteger)written;
        }

        completion(nil);
    });
}

- (void)resizeWithColumns:(uint16_t)columns rows:(uint16_t)rows completion:(SSHKitCompletion)completion {
    dispatch_async(self.workerQueue, ^{
        if (self.finished || self.channel == NULL) {
            completion(SSHKitMakeError(SSHKitErrorCodeInvalidState, @"SSH shell is closed."));
            return;
        }

        if (ssh_channel_change_pty_size(self.channel, columns, rows) != SSH_OK) {
            completion(SSHKitMakeError(SSHKitErrorCodeConnectionFailed, @"Unable to resize SSH shell PTY."));
            return;
        }

        completion(nil);
    });
}

- (void)closeWithCompletion:(SSHKitCompletion)completion {
    dispatch_async(self.workerQueue, ^{
        if (self.finished) {
            completion(nil);
            return;
        }

        [self finishWithExitStatus:SSHCoreAbnormalExitStatus];
        completion(nil);
    });
}

- (void)readAvailableDataAndScheduleNextRead {
    if (self.finished || self.channel == NULL) {
        return;
    }

    if (![self drainStream:0 eventKind:SSHKitShellEventKindStandardOutput] ||
        ![self drainStream:1 eventKind:SSHKitShellEventKindStandardError]) {
        [self finishWithExitStatus:-1];
        return;
    }

    if (ssh_channel_is_eof(self.channel) || ssh_channel_is_closed(self.channel)) {
        [self finishWithExitStatus:[self exitStatus]];
        return;
    }

    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 50 * NSEC_PER_MSEC), self.workerQueue, ^{
        [self readAvailableDataAndScheduleNextRead];
    });
}

- (BOOL)drainStream:(int)isStderr eventKind:(SSHKitShellEventKind)eventKind {
    char buffer[32768];
    while (YES) {
        int byteCount = ssh_channel_read_nonblocking(self.channel, buffer, sizeof(buffer), isStderr);
        if (byteCount == SSH_ERROR) {
            return NO;
        }
        if (byteCount <= 0) {
            return YES;
        }

        NSData *data = [NSData dataWithBytes:buffer length:(NSUInteger)byteCount];
        SSHKitShellEvent *event = [[SSHKitShellEvent alloc] initWithKind:eventKind data:data exitStatus:0];
        self.eventHandler(event);
    }
}

- (int32_t)exitStatus {
    uint32_t exitCode = 0;
    if (self.channel == NULL) {
        return SSHCoreAbnormalExitStatus;
    }

    int exitState = ssh_channel_get_exit_state(self.channel, &exitCode, NULL, NULL);
    if (exitState != SSH_OK) {
        return SSHCoreAbnormalExitStatus;
    }

    return (int32_t)exitCode;
}

- (void)finishWithExitStatus:(int32_t)exitStatus {
    if (self.finished) {
        return;
    }

    self.finished = YES;
    ssh_channel channel = self.channel;
    self.channel = NULL;
    if (channel != NULL) {
        ssh_channel_send_eof(channel);
        ssh_channel_close(channel);
        ssh_channel_free(channel);
    }

    self.onClosed(exitStatus);
}

- (void)invalidateOnWorkerQueue {
    if (self.finished) {
        return;
    }

    self.finished = YES;
    ssh_channel channel = self.channel;
    self.channel = NULL;
    if (channel != NULL) {
        ssh_channel_send_eof(channel);
        ssh_channel_close(channel);
        ssh_channel_free(channel);
    }
}

- (void)dealloc {
    ssh_channel channel = self.channel;
    if (channel == NULL) {
        return;
    }
    dispatch_async(self.workerQueue, ^{
        ssh_channel_send_eof(channel);
        ssh_channel_close(channel);
        ssh_channel_free(channel);
    });
}

@end

@interface SSHCoreLibSSHLocalForwardRuntime : NSObject

- (instancetype)initWithSession:(ssh_session)session
                  listenerSocket:(int)listenerSocket
                       boundHost:(NSString *)boundHost
                       boundPort:(uint16_t)boundPort
                      targetHost:(nullable NSString *)targetHost
                      targetPort:(uint16_t)targetPort
                     socksUsername:(nullable NSString *)socksUsername
                     socksPassword:(nullable NSString *)socksPassword
                     workerQueue:(dispatch_queue_t)workerQueue
                    closeHandler:(SSHCoreTunnelCloseHandler)closeHandler
                          client:(SSHCoreOpenSSHClient *)client;
- (void)start;
- (void)closeWithCompletion:(SSHKitCompletion)completion;
- (void)invalidateOnWorkerQueue;

@end

@interface SSHCoreLibSSHLocalForwardRuntime ()

@property (nonatomic) ssh_session session;
@property (nonatomic) dispatch_queue_t workerQueue;
@property (nonatomic, copy) NSString *boundHost;
@property (nonatomic) uint16_t boundPort;
@property (nonatomic, copy, nullable) NSString *targetHost;
@property (nonatomic) uint16_t targetPort;
@property (nonatomic, copy, nullable) NSString *socksUsername;
@property (nonatomic, copy, nullable) NSString *socksPassword;
@property (nonatomic, copy) SSHCoreTunnelCloseHandler closeHandler;
@property (nonatomic, weak) SSHCoreOpenSSHClient *client;
@property (nonatomic) NSLock *lock;
@property (nonatomic) int listenerSocket;
@property (nonatomic) int activeSocket;
@property (nonatomic) BOOL closed;
@property (nonatomic) BOOL didCallCloseHandler;
@property (nonatomic) NSMutableArray<SSHKitCompletion> *closeCompletions;

@end

@interface SSHCoreLibSSHRemoteForwardRuntime : NSObject

- (instancetype)initWithSession:(ssh_session)session
                     remoteHost:(NSString *)remoteHost
                     remotePort:(uint16_t)remotePort
                      boundPort:(uint16_t)boundPort
                     targetHost:(NSString *)targetHost
                     targetPort:(uint16_t)targetPort
                    workerQueue:(dispatch_queue_t)workerQueue
                   closeHandler:(SSHCoreTunnelCloseHandler)closeHandler
                         client:(SSHCoreOpenSSHClient *)client;
- (void)start;
- (void)closeWithCompletion:(SSHKitCompletion)completion;
- (void)invalidateOnWorkerQueue;

@end

@interface SSHCoreLibSSHRemoteForwardRuntime ()

@property (nonatomic) ssh_session session;
@property (nonatomic, copy) NSString *remoteHost;
@property (nonatomic) uint16_t remotePort;
@property (nonatomic) uint16_t boundPort;
@property (nonatomic, copy) NSString *targetHost;
@property (nonatomic) uint16_t targetPort;
@property (nonatomic) dispatch_queue_t workerQueue;
@property (nonatomic, copy) SSHCoreTunnelCloseHandler closeHandler;
@property (nonatomic, weak) SSHCoreOpenSSHClient *client;
@property (nonatomic) NSLock *lock;
@property (nonatomic) int activeSocket;
@property (nonatomic) BOOL closed;
@property (nonatomic) BOOL didCancelRemoteForward;
@property (nonatomic) BOOL didCallCloseHandler;
@property (nonatomic) NSMutableArray<SSHKitCompletion> *closeCompletions;

@end

@class SSHCoreLibSSHSFTPFileRuntime;

@interface SSHCoreLibSSHSFTPRuntime : NSObject

- (instancetype)initWithSession:(sftp_session)sftp
                    workerQueue:(dispatch_queue_t)workerQueue
                    closeHandler:(SSHCoreSFTPCloseHandler)closeHandler
                          client:(SSHCoreOpenSSHClient *)client;
- (void)listDirectory:(NSString *)path completion:(SSHKitSFTPListCompletion)completion;
- (void)realpath:(NSString *)path completion:(SSHKitSFTPStringCompletion)completion;
- (void)statPath:(NSString *)path followSymlink:(BOOL)followSymlink completion:(SSHKitSFTPAttributesCompletion)completion;
- (void)setPermissions:(uint32_t)permissions atPath:(NSString *)path completion:(SSHKitCompletion)completion;
- (void)fileSystemAttributesAtPath:(NSString *)path completion:(SSHKitSFTPFileSystemAttributesCompletion)completion;
- (void)createDirectoryAtPath:(NSString *)path permissions:(uint32_t)permissions completion:(SSHKitCompletion)completion;
- (void)removeDirectoryAtPath:(NSString *)path completion:(SSHKitCompletion)completion;
- (void)removeFileAtPath:(NSString *)path completion:(SSHKitCompletion)completion;
- (void)renamePath:(NSString *)sourcePath toPath:(NSString *)destinationPath completion:(SSHKitCompletion)completion;
- (void)readLinkAtPath:(NSString *)path completion:(SSHKitSFTPStringCompletion)completion;
- (void)createSymbolicLinkAtPath:(NSString *)linkPath targetPath:(NSString *)targetPath completion:(SSHKitCompletion)completion;
- (void)openFileAtPath:(NSString *)path flags:(SSHKitSFTPFileOpenFlags)flags permissions:(uint32_t)permissions completion:(SSHKitSFTPFileHandleCompletion)completion;
- (void)readFileAtPath:(NSString *)path completion:(SSHKitSFTPDataCompletion)completion;
- (void)writeData:(NSData *)data toFileAtPath:(NSString *)path completion:(SSHKitCompletion)completion;
- (void)downloadFileAtPath:(NSString *)remotePath toLocalPath:(NSString *)localPath resume:(BOOL)resume progress:(SSHKitSFTPProgressHandler)progress completion:(SSHKitCompletion)completion;
- (void)uploadFileAtPath:(NSString *)localPath toRemotePath:(NSString *)remotePath resume:(BOOL)resume progress:(SSHKitSFTPProgressHandler)progress completion:(SSHKitCompletion)completion;
- (void)closeWithCompletion:(SSHKitCompletion)completion;
- (void)invalidateOnWorkerQueue;
- (void)registerFileRuntime:(SSHCoreLibSSHSFTPFileRuntime *)fileRuntime;
- (void)unregisterFileRuntime:(SSHCoreLibSSHSFTPFileRuntime *)fileRuntime;
- (BOOL)isOpenOnWorkerQueue;

@end

@interface SSHCoreLibSSHSFTPRuntime ()

@property (nonatomic) sftp_session sftp;
@property (nonatomic) dispatch_queue_t workerQueue;
@property (nonatomic, copy) SSHCoreSFTPCloseHandler closeHandler;
@property (nonatomic, weak) SSHCoreOpenSSHClient *client;
@property (nonatomic) BOOL closed;
@property (nonatomic) BOOL runningOperation;
@property (nonatomic) BOOL didCallCloseHandler;
@property (nonatomic) NSHashTable<SSHCoreLibSSHSFTPFileRuntime *> *fileRuntimes;

@end

@interface SSHCoreLibSSHSFTPFileRuntime : NSObject

- (instancetype)initWithFile:(sftp_file)file
                       owner:(SSHCoreLibSSHSFTPRuntime *)owner
                 workerQueue:(dispatch_queue_t)workerQueue
                       client:(SSHCoreOpenSSHClient *)client;
- (void)readDataWithMaximumLength:(NSUInteger)maximumLength completion:(SSHKitSFTPDataCompletion)completion;
- (void)writeData:(NSData *)data completion:(SSHKitCompletion)completion;
- (void)seekToOffset:(uint64_t)offset completion:(SSHKitCompletion)completion;
- (void)closeWithCompletion:(SSHKitCompletion)completion;
- (void)invalidateOnWorkerQueue;

@end

@interface SSHCoreLibSSHSFTPFileRuntime ()

@property (nonatomic) sftp_file file;
@property (nonatomic) SSHCoreLibSSHSFTPRuntime *owner;
@property (nonatomic) dispatch_queue_t workerQueue;
@property (nonatomic) SSHCoreOpenSSHClient *client;
@property (nonatomic) BOOL closed;

@end

@interface SSHCoreLibSSHTunnelRuntime : NSObject

- (instancetype)initWithChannel:(ssh_channel)channel
                    workerQueue:(dispatch_queue_t)workerQueue
                    isCancelled:(BOOL (^)(void))isCancelled
                    closeHandler:(SSHCoreTunnelCloseHandler)closeHandler;
- (void)readDataWithMaximumLength:(NSUInteger)maximumLength completion:(SSHKitTunnelReadCompletion)completion;
- (void)writeData:(NSData *)data completion:(SSHKitCompletion)completion;
- (void)closeWithCompletion:(SSHKitCompletion)completion;
- (BOOL)isTunnelCancelled;
- (NSError *)tunnelErrorWithCode:(SSHKitErrorCode)code fallback:(NSString *)fallback cancelled:(BOOL)cancelled;
- (void)closeAfterTerminalTunnelFailure;
- (void)invalidateOnWorkerQueue;

@end

@interface SSHCoreLibSSHTunnelRuntime ()

@property (nonatomic) ssh_channel channel;
@property (nonatomic) dispatch_queue_t workerQueue;
@property (nonatomic, copy) SSHCoreTunnelCloseHandler closeHandler;
@property (nonatomic, copy) BOOL (^isCancelled)(void);
@property (nonatomic) BOOL closed;
@property (nonatomic) BOOL didCallCloseHandler;

@end

@implementation SSHCoreLibSSHTunnelRuntime

- (instancetype)initWithChannel:(ssh_channel)channel
                    workerQueue:(dispatch_queue_t)workerQueue
                    isCancelled:(BOOL (^)(void))isCancelled
                    closeHandler:(SSHCoreTunnelCloseHandler)closeHandler {
    NSParameterAssert(channel != NULL);
    NSParameterAssert(workerQueue != nil);

    self = [super init];
    if (self) {
        _channel = channel;
        _workerQueue = workerQueue;
        _isCancelled = [isCancelled copy];
        _closeHandler = [closeHandler copy];
    }
    return self;
}

- (void)readDataWithMaximumLength:(NSUInteger)maximumLength completion:(SSHKitTunnelReadCompletion)completion {
    dispatch_async(self.workerQueue, ^{
        if (self.closed || self.channel == NULL) {
            completion(nil, SSHKitMakeError(SSHKitErrorCodeInvalidState, @"SSH tunnel channel is closed."));
            return;
        }

        uint32_t boundedLength = (uint32_t)MIN(maximumLength, (NSUInteger)32768);
        NSMutableData *data = [NSMutableData dataWithLength:(NSUInteger)boundedLength];
        int byteCount = ssh_channel_read_timeout(self.channel, data.mutableBytes, boundedLength, 0, 10000);
        if (byteCount == SSH_AGAIN) {
            BOOL cancelled = [self isTunnelCancelled];
            if (cancelled) {
                [self closeAfterTerminalTunnelFailure];
            }
            completion(nil, [self tunnelErrorWithCode:SSHKitErrorCodeConnectionFailed fallback:@"Timed out waiting for SSH tunnel channel data." cancelled:cancelled]);
            return;
        }
        if (byteCount == SSH_ERROR) {
            BOOL cancelled = [self isTunnelCancelled];
            [self closeAfterTerminalTunnelFailure];
            completion(nil, [self tunnelErrorWithCode:SSHKitErrorCodeConnectionFailed fallback:@"Unable to read SSH tunnel channel." cancelled:cancelled]);
            return;
        }
        if (byteCount == 0) {
            BOOL cancelled = [self isTunnelCancelled];
            [self closeAfterTerminalTunnelFailure];
            completion(nil, [self tunnelErrorWithCode:SSHKitErrorCodeConnectionFailed fallback:@"SSH tunnel channel reached EOF." cancelled:cancelled]);
            return;
        }

        data.length = (NSUInteger)byteCount;
        completion(data, nil);
    });
}

- (void)writeData:(NSData *)data completion:(SSHKitCompletion)completion {
    dispatch_async(self.workerQueue, ^{
        if (self.closed || self.channel == NULL) {
            completion(SSHKitMakeError(SSHKitErrorCodeInvalidState, @"SSH tunnel channel is closed."));
            return;
        }

        const uint8_t *bytes = data.bytes;
        NSUInteger remaining = data.length;
        while (remaining > 0) {
            uint32_t chunkLength = remaining > UINT32_MAX ? UINT32_MAX : (uint32_t)remaining;
            int written = ssh_channel_write(self.channel, bytes, chunkLength);
            if (written == SSH_ERROR) {
                BOOL cancelled = [self isTunnelCancelled];
                [self closeAfterTerminalTunnelFailure];
                completion([self tunnelErrorWithCode:SSHKitErrorCodeConnectionFailed fallback:@"Unable to write SSH tunnel channel." cancelled:cancelled]);
                return;
            }
            if (written <= 0) {
                BOOL cancelled = [self isTunnelCancelled];
                [self closeAfterTerminalTunnelFailure];
                completion([self tunnelErrorWithCode:SSHKitErrorCodeConnectionFailed fallback:@"SSH tunnel write made no progress." cancelled:cancelled]);
                return;
            }
            bytes += written;
            remaining -= (NSUInteger)written;
        }

        completion(nil);
    });
}

- (BOOL)isTunnelCancelled {
    return self.isCancelled ? self.isCancelled() : NO;
}

- (NSError *)tunnelErrorWithCode:(SSHKitErrorCode)code fallback:(NSString *)fallback cancelled:(BOOL)cancelled {
    return cancelled ? SSHKitMakeError(SSHKitErrorCodeCancelled, @"SSH tunnel channel was cancelled.") : SSHKitMakeError(code, fallback);
}

- (void)closeWithCompletion:(SSHKitCompletion)completion {
    dispatch_async(self.workerQueue, ^{
        [self invalidateOnWorkerQueue];
        [self callCloseHandlerIfNeeded];
        completion(nil);
    });
}

- (void)closeAfterTerminalTunnelFailure {
    [self invalidateOnWorkerQueue];
    [self callCloseHandlerIfNeeded];
}

- (void)invalidateOnWorkerQueue {
    if (self.closed) {
        return;
    }

    self.closed = YES;
    ssh_channel channel = self.channel;
    self.channel = NULL;
    if (channel != NULL) {
        ssh_channel_send_eof(channel);
        ssh_channel_close(channel);
        ssh_channel_free(channel);
    }
}

- (void)callCloseHandlerIfNeeded {
    if (self.didCallCloseHandler) {
        return;
    }
    self.didCallCloseHandler = YES;
    self.closeHandler();
}

- (void)dealloc {
    ssh_channel channel = self.channel;
    if (channel == NULL) {
        return;
    }
    dispatch_async(self.workerQueue, ^{
        ssh_channel_send_eof(channel);
        ssh_channel_close(channel);
        ssh_channel_free(channel);
    });
}

@end

@interface SSHCoreOpenSSHClient ()

- (NSError *)sftpErrorForOperation:(NSString *)operation sftp:(sftp_session)sftp;
- (NSError *)sftpErrorForOperation:(NSString *)operation status:(int)status;
- (void)emitLogLevel:(SSHKitLogLevel)level phase:(NSString *)phase message:(NSString *)message metadata:(NSDictionary<NSString *, NSString *> *)metadata;

@end

@implementation SSHCoreLibSSHLocalForwardRuntime

- (instancetype)initWithSession:(ssh_session)session
                  listenerSocket:(int)listenerSocket
                       boundHost:(NSString *)boundHost
                       boundPort:(uint16_t)boundPort
                      targetHost:(NSString *)targetHost
                      targetPort:(uint16_t)targetPort
                    socksUsername:(NSString *)socksUsername
                    socksPassword:(NSString *)socksPassword
                     workerQueue:(dispatch_queue_t)workerQueue
                    closeHandler:(SSHCoreTunnelCloseHandler)closeHandler
                          client:(SSHCoreOpenSSHClient *)client {
    NSParameterAssert(session != NULL);
    NSParameterAssert(listenerSocket >= 0);
    NSParameterAssert(workerQueue != nil);

    self = [super init];
    if (self) {
        _session = session;
        _listenerSocket = listenerSocket;
        _activeSocket = -1;
        _boundHost = [boundHost copy];
        _boundPort = boundPort;
        _targetHost = [targetHost copy];
        _targetPort = targetPort;
        _socksUsername = [socksUsername copy];
        _socksPassword = [socksPassword copy];
        _workerQueue = workerQueue;
        _closeHandler = [closeHandler copy];
        _client = client;
        _lock = [[NSLock alloc] init];
        _closeCompletions = [[NSMutableArray alloc] init];
    }
    return self;
}

- (void)start {
    [self acceptLoopOnWorkerQueue];
}

- (void)acceptLoopOnWorkerQueue {
    while (![self isClosed]) {
        fd_set readSet;
        FD_ZERO(&readSet);
        FD_SET(self.listenerSocket, &readSet);
        struct timeval timeout;
        timeout.tv_sec = 0;
        timeout.tv_usec = 10000;
        int selectResult = select(self.listenerSocket + 1, &readSet, NULL, NULL, &timeout);
        if (selectResult == 0 || (selectResult < 0 && errno == EINTR)) {
            continue;
        }
        if (selectResult < 0) {
            [self.client emitLogLevel:SSHKitLogLevelWarning
                                phase:@"tunnel"
                              message:@"SSH local forward listener failed."
                             metadata:@{@"error": [NSString stringWithUTF8String:strerror(errno)]}];
            break;
        }

        struct sockaddr_storage clientAddress;
        socklen_t clientAddressLength = sizeof(clientAddress);
        int clientSocket = accept(self.listenerSocket, (struct sockaddr *)&clientAddress, &clientAddressLength);
        if (clientSocket < 0) {
            if ([self isClosed] || errno == EBADF || errno == EINVAL) {
                break;
            }
            if (errno == EINTR) {
                continue;
            }
            if (errno == ECONNABORTED || errno == EMFILE || errno == ENFILE) {
                [self.client emitLogLevel:SSHKitLogLevelWarning
                                    phase:@"tunnel"
                                  message:@"SSH local forward accept failed."
                                 metadata:@{@"error": [NSString stringWithUTF8String:strerror(errno)]}];
                continue;
            }
            [self.client emitLogLevel:SSHKitLogLevelWarning
                                phase:@"tunnel"
                              message:@"SSH local forward stopped after accept failure."
                             metadata:@{@"error": [NSString stringWithUTF8String:strerror(errno)]}];
            break;
        }

        [self setActiveSocket:clientSocket];
        NSString *targetHost = self.targetHost;
        uint16_t targetPort = self.targetPort;
        BOOL isDynamicRequest = targetHost == nil;
        if (targetHost == nil) {
            if (![self readSOCKSTargetHost:&targetHost port:&targetPort fromClientSocket:clientSocket]) {
                SSHCoreCloseDescriptor(&clientSocket);
                [self setActiveSocket:-1];
                continue;
            }
        }
        ssh_channel channel = [self openForwardChannelForClientSocket:clientSocket targetHost:targetHost targetPort:targetPort];
        if (channel != NULL) {
            if (isDynamicRequest) {
                [self sendSOCKSReply:0x00 toSocket:clientSocket];
            }
            [self bridgeClientSocket:clientSocket channel:channel];
            ssh_channel_send_eof(channel);
            ssh_channel_close(channel);
            ssh_channel_free(channel);
        } else if (isDynamicRequest) {
            [self sendSOCKSReply:0x05 toSocket:clientSocket];
        }
        SSHCoreCloseDescriptor(&clientSocket);
        [self setActiveSocket:-1];
    }

    [self invalidateOnWorkerQueue];
    [self callCloseHandlerIfNeeded];
    [self completePendingCloseCompletions];
}

- (nullable ssh_channel)openForwardChannelForClientSocket:(int)clientSocket targetHost:(NSString *)targetHost targetPort:(uint16_t)targetPort {
    ssh_channel channel = ssh_channel_new(self.session);
    if (channel == NULL) {
        [self.client emitLogLevel:SSHKitLogLevelWarning phase:@"tunnel" message:@"SSH local forward could not allocate channel." metadata:@{}];
        return NULL;
    }

    int sourcePort = 0;
    NSString *sourceHost = [self peerHostForSocket:clientSocket port:&sourcePort];
    if (ssh_channel_open_forward(channel, targetHost.UTF8String, targetPort, sourceHost.UTF8String, sourcePort) != SSH_OK) {
        [self.client emitLogLevel:SSHKitLogLevelWarning
                            phase:@"tunnel"
                          message:@"SSH local forward channel open failed."
                         metadata:@{@"targetHost": targetHost,
                                    @"targetPort": [NSString stringWithFormat:@"%hu", targetPort],
                                    @"sourceHost": sourceHost,
                                    @"sourcePort": [NSString stringWithFormat:@"%d", sourcePort]}];
        ssh_channel_free(channel);
        return NULL;
    }
    return channel;
}

- (void)bridgeClientSocket:(int)clientSocket channel:(ssh_channel)channel {
    char buffer[32768];
    while (![self isClosed] && ssh_channel_is_open(channel)) {
        fd_set readSet;
        FD_ZERO(&readSet);
        FD_SET(clientSocket, &readSet);
        struct timeval timeout;
        timeout.tv_sec = 0;
        timeout.tv_usec = 10000;

        int selectResult = select(clientSocket + 1, &readSet, NULL, NULL, &timeout);
        if (selectResult > 0 && FD_ISSET(clientSocket, &readSet)) {
            ssize_t bytesRead = read(clientSocket, buffer, sizeof(buffer));
            if (bytesRead <= 0) {
                break;
            }
            if (![self writeBytes:buffer length:(size_t)bytesRead toChannel:channel]) {
                break;
            }
        } else if (selectResult < 0 && errno != EINTR) {
            break;
        }

        while (YES) {
            int bytesRead = ssh_channel_read_nonblocking(channel, buffer, sizeof(buffer), 0);
            if (bytesRead == SSH_ERROR) {
                return;
            }
            if (bytesRead <= 0) {
                break;
            }
            if (![self writeBytes:buffer length:(size_t)bytesRead toSocket:clientSocket]) {
                return;
            }
        }

        if (ssh_channel_is_eof(channel)) {
            break;
        }
    }
}

- (BOOL)readSOCKSTargetHost:(NSString **)targetHost port:(uint16_t *)targetPort fromClientSocket:(int)clientSocket {
    uint8_t header[2];
    if (![self readExactly:header length:sizeof(header) fromSocket:clientSocket] || header[0] != 0x05 || header[1] == 0) {
        return NO;
    }

    NSMutableData *methods = [NSMutableData dataWithLength:header[1]];
    if (![self readExactly:methods.mutableBytes length:methods.length fromSocket:clientSocket]) {
        return NO;
    }

    uint8_t selectedMethod = 0xFF;
    const uint8_t *methodBytes = methods.bytes;
    BOOL wantsPassword = self.socksUsername != nil || self.socksPassword != nil;
    for (NSUInteger index = 0; index < methods.length; index++) {
        if (!wantsPassword && methodBytes[index] == 0x00) {
            selectedMethod = 0x00;
            break;
        }
        if (wantsPassword && methodBytes[index] == 0x02) {
            selectedMethod = 0x02;
            break;
        }
    }

    uint8_t selection[2] = {0x05, selectedMethod};
    if (![self writeBytes:(const char *)selection length:sizeof(selection) toSocket:clientSocket] || selectedMethod == 0xFF) {
        return NO;
    }
    if (selectedMethod == 0x02 && ![self authenticateSOCKSUserPasswordOnSocket:clientSocket]) {
        return NO;
    }

    uint8_t requestHeader[4];
    if (![self readExactly:requestHeader length:sizeof(requestHeader) fromSocket:clientSocket] ||
        requestHeader[0] != 0x05 ||
        requestHeader[1] != 0x01 ||
        requestHeader[2] != 0x00) {
        [self sendSOCKSReply:0x07 toSocket:clientSocket];
        return NO;
    }

    NSString *host = nil;
    switch (requestHeader[3]) {
        case 0x01: {
            uint8_t address[4];
            if (![self readExactly:address length:sizeof(address) fromSocket:clientSocket]) {
                return NO;
            }
            char buffer[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, address, buffer, sizeof(buffer));
            host = [NSString stringWithUTF8String:buffer];
            break;
        }
        case 0x03: {
            uint8_t length = 0;
            if (![self readExactly:&length length:1 fromSocket:clientSocket] || length == 0) {
                return NO;
            }
            NSMutableData *domain = [NSMutableData dataWithLength:length];
            if (![self readExactly:domain.mutableBytes length:domain.length fromSocket:clientSocket]) {
                return NO;
            }
            host = [[NSString alloc] initWithData:domain encoding:NSUTF8StringEncoding];
            break;
        }
        case 0x04: {
            uint8_t address[16];
            if (![self readExactly:address length:sizeof(address) fromSocket:clientSocket]) {
                return NO;
            }
            char buffer[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, address, buffer, sizeof(buffer));
            host = [NSString stringWithUTF8String:buffer];
            break;
        }
        default:
            [self sendSOCKSReply:0x08 toSocket:clientSocket];
            return NO;
    }

    uint8_t portBytes[2];
    if (host.length == 0) {
        [self sendSOCKSReply:0x01 toSocket:clientSocket];
        return NO;
    }
    if (![self readExactly:portBytes length:sizeof(portBytes) fromSocket:clientSocket]) {
        return NO;
    }

    *targetHost = host;
    *targetPort = (uint16_t)((portBytes[0] << 8) | portBytes[1]);
    return YES;
}

- (BOOL)authenticateSOCKSUserPasswordOnSocket:(int)clientSocket {
    uint8_t header[2];
    if (![self readExactly:header length:sizeof(header) fromSocket:clientSocket] || header[0] != 0x01) {
        return NO;
    }
    NSMutableData *username = [NSMutableData dataWithLength:header[1]];
    if (![self readExactly:username.mutableBytes length:username.length fromSocket:clientSocket]) {
        return NO;
    }
    uint8_t passwordLength = 0;
    if (![self readExactly:&passwordLength length:1 fromSocket:clientSocket]) {
        return NO;
    }
    NSMutableData *password = [NSMutableData dataWithLength:passwordLength];
    if (![self readExactly:password.mutableBytes length:password.length fromSocket:clientSocket]) {
        return NO;
    }

    NSString *requestUsername = [[NSString alloc] initWithData:username encoding:NSUTF8StringEncoding] ?: @"";
    NSString *requestPassword = [[NSString alloc] initWithData:password encoding:NSUTF8StringEncoding] ?: @"";
    BOOL accepted = [requestUsername isEqualToString:self.socksUsername ?: @""] &&
        [requestPassword isEqualToString:self.socksPassword ?: @""];
    uint8_t response[2] = {0x01, accepted ? 0x00 : 0x01};
    [self writeBytes:(const char *)response length:sizeof(response) toSocket:clientSocket];
    return accepted;
}

- (void)sendSOCKSReply:(uint8_t)reply toSocket:(int)clientSocket {
    uint8_t response[10] = {0x05, reply, 0x00, 0x01, 0, 0, 0, 0, 0, 0};
    [self writeBytes:(const char *)response length:sizeof(response) toSocket:clientSocket];
}

- (BOOL)readExactly:(void *)buffer length:(NSUInteger)length fromSocket:(int)socket {
    uint8_t *cursor = buffer;
    NSUInteger remaining = length;
    while (remaining > 0) {
        ssize_t bytesRead = read(socket, cursor, remaining);
        if (bytesRead < 0 && errno == EINTR) {
            continue;
        }
        if (bytesRead <= 0) {
            return NO;
        }
        cursor += bytesRead;
        remaining -= (NSUInteger)bytesRead;
    }
    return YES;
}

- (BOOL)writeBytes:(const char *)bytes length:(size_t)length toChannel:(ssh_channel)channel {
    size_t offset = 0;
    while (offset < length) {
        int chunkLength = (int)MIN(length - offset, (size_t)UINT32_MAX);
        int written = ssh_channel_write(channel, bytes + offset, (uint32_t)chunkLength);
        if (written <= 0) {
            return NO;
        }
        offset += (size_t)written;
    }
    return YES;
}

- (BOOL)writeBytes:(const char *)bytes length:(size_t)length toSocket:(int)socket {
    size_t offset = 0;
    while (offset < length) {
        ssize_t written = write(socket, bytes + offset, length - offset);
        if (written < 0 && errno == EINTR) {
            continue;
        }
        if (written <= 0) {
            return NO;
        }
        offset += (size_t)written;
    }
    return YES;
}

- (NSString *)peerHostForSocket:(int)socket port:(int *)port {
    struct sockaddr_storage address;
    socklen_t addressLength = sizeof(address);
    if (getpeername(socket, (struct sockaddr *)&address, &addressLength) != 0) {
        *port = 0;
        return self.boundHost;
    }
    char hostBuffer[NI_MAXHOST];
    if (address.ss_family == AF_INET) {
        *port = ntohs(((struct sockaddr_in *)&address)->sin_port);
    } else if (address.ss_family == AF_INET6) {
        *port = ntohs(((struct sockaddr_in6 *)&address)->sin6_port);
    } else {
        *port = 0;
        return self.boundHost;
    }
    int result = getnameinfo((struct sockaddr *)&address, addressLength, hostBuffer, sizeof(hostBuffer), NULL, 0, NI_NUMERICHOST);
    if (result != 0) {
        return self.boundHost;
    }
    return [NSString stringWithUTF8String:hostBuffer];
}

- (void)setActiveSocket:(int)activeSocket {
    [self.lock lock];
    _activeSocket = activeSocket;
    [self.lock unlock];
}

- (BOOL)isClosed {
    [self.lock lock];
    BOOL closed = self.closed;
    [self.lock unlock];
    return closed;
}

- (void)closeWithCompletion:(SSHKitCompletion)completion {
    [self.lock lock];
    if (self.didCallCloseHandler) {
        [self.lock unlock];
        completion(nil);
        return;
    }
    self.closed = YES;
    int activeSocket = self.activeSocket;
    [self.closeCompletions addObject:[completion copy]];
    [self.lock unlock];

    SSHCoreShutdownDescriptor(activeSocket);
}

- (void)invalidateOnWorkerQueue {
    [self.lock lock];
    self.closed = YES;
    int listenerSocket = self.listenerSocket;
    self.listenerSocket = -1;
    int activeSocket = self.activeSocket;
    self.activeSocket = -1;
    [self.lock unlock];

    SSHCoreCloseDescriptor(&listenerSocket);
    SSHCoreCloseDescriptor(&activeSocket);
}

- (void)callCloseHandlerIfNeeded {
    [self.lock lock];
    if (self.didCallCloseHandler) {
        [self.lock unlock];
        return;
    }
    self.didCallCloseHandler = YES;
    [self.lock unlock];
    self.closeHandler();
}

- (void)completePendingCloseCompletions {
    [self.lock lock];
    NSArray<SSHKitCompletion> *completions = [self.closeCompletions copy];
    [self.closeCompletions removeAllObjects];
    [self.lock unlock];

    for (SSHKitCompletion completion in completions) {
        completion(nil);
    }
}

- (void)dealloc {
    [self invalidateOnWorkerQueue];
}

@end

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"

@implementation SSHCoreLibSSHRemoteForwardRuntime

- (instancetype)initWithSession:(ssh_session)session
                     remoteHost:(NSString *)remoteHost
                     remotePort:(uint16_t)remotePort
                      boundPort:(uint16_t)boundPort
                     targetHost:(NSString *)targetHost
                     targetPort:(uint16_t)targetPort
                    workerQueue:(dispatch_queue_t)workerQueue
                   closeHandler:(SSHCoreTunnelCloseHandler)closeHandler
                         client:(SSHCoreOpenSSHClient *)client {
    self = [super init];
    if (self) {
        _session = session;
        _remoteHost = [remoteHost copy];
        _remotePort = remotePort;
        _boundPort = boundPort;
        _targetHost = [targetHost copy];
        _targetPort = targetPort;
        _workerQueue = workerQueue;
        _closeHandler = [closeHandler copy];
        _client = client;
        _lock = [[NSLock alloc] init];
        _activeSocket = -1;
        _closeCompletions = [[NSMutableArray alloc] init];
    }
    return self;
}

- (void)start {
    while (![self isClosed]) {
        int destinationPort = 0;
        ssh_channel channel = ssh_channel_accept_forward(self.session, 100, &destinationPort);
        if (channel == NULL) {
            continue;
        }

        int localSocket = [self openTargetSocket];
        if (localSocket >= 0) {
            [self setActiveSocket:localSocket];
            [self bridgeLocalSocket:localSocket channel:channel];
            SSHCoreCloseDescriptor(&localSocket);
            [self setActiveSocket:-1];
        } else {
            [self.client emitLogLevel:SSHKitLogLevelWarning
                                phase:@"tunnel"
                              message:@"SSH remote forward local target connect failed."
                             metadata:@{@"targetHost": self.targetHost,
                                        @"targetPort": [NSString stringWithFormat:@"%hu", self.targetPort]}];
        }
        ssh_channel_send_eof(channel);
        ssh_channel_close(channel);
        ssh_channel_free(channel);
    }

    [self invalidateOnWorkerQueue];
    [self callCloseHandlerIfNeeded];
    [self completePendingCloseCompletions];
}

- (int)openTargetSocket {
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    NSString *port = [NSString stringWithFormat:@"%hu", self.targetPort];
    struct addrinfo *addresses = NULL;
    if (getaddrinfo(self.targetHost.UTF8String, port.UTF8String, &hints, &addresses) != 0) {
        return -1;
    }
    for (struct addrinfo *address = addresses; address != NULL; address = address->ai_next) {
        int fileDescriptor = socket(address->ai_family, address->ai_socktype, address->ai_protocol);
        if (fileDescriptor < 0) {
            continue;
        }
        if (connect(fileDescriptor, address->ai_addr, address->ai_addrlen) == 0) {
            freeaddrinfo(addresses);
            return fileDescriptor;
        }
        close(fileDescriptor);
    }
    freeaddrinfo(addresses);
    return -1;
}

- (void)bridgeLocalSocket:(int)localSocket channel:(ssh_channel)channel {
    char buffer[32768];
    while (![self isClosed] && ssh_channel_is_open(channel)) {
        fd_set readSet;
        FD_ZERO(&readSet);
        FD_SET(localSocket, &readSet);
        struct timeval timeout;
        timeout.tv_sec = 0;
        timeout.tv_usec = 10000;
        int selectResult = select(localSocket + 1, &readSet, NULL, NULL, &timeout);
        if (selectResult > 0 && FD_ISSET(localSocket, &readSet)) {
            ssize_t bytesRead = read(localSocket, buffer, sizeof(buffer));
            if (bytesRead <= 0 || ![self writeBytes:buffer length:(size_t)bytesRead toChannel:channel]) {
                break;
            }
        } else if (selectResult < 0 && errno != EINTR) {
            break;
        }

        while (YES) {
            int bytesRead = ssh_channel_read_nonblocking(channel, buffer, sizeof(buffer), 0);
            if (bytesRead == SSH_ERROR) {
                return;
            }
            if (bytesRead <= 0) {
                break;
            }
            if (![self writeBytes:buffer length:(size_t)bytesRead toSocket:localSocket]) {
                return;
            }
        }
        if (ssh_channel_is_eof(channel)) {
            break;
        }
    }
}

- (BOOL)writeBytes:(const char *)bytes length:(size_t)length toChannel:(ssh_channel)channel {
    size_t offset = 0;
    while (offset < length) {
        int written = ssh_channel_write(channel, bytes + offset, (uint32_t)MIN(length - offset, (size_t)UINT32_MAX));
        if (written <= 0) {
            return NO;
        }
        offset += (size_t)written;
    }
    return YES;
}

- (BOOL)writeBytes:(const char *)bytes length:(size_t)length toSocket:(int)socket {
    size_t offset = 0;
    while (offset < length) {
        ssize_t written = write(socket, bytes + offset, length - offset);
        if (written < 0 && errno == EINTR) {
            continue;
        }
        if (written <= 0) {
            return NO;
        }
        offset += (size_t)written;
    }
    return YES;
}

- (void)setActiveSocket:(int)activeSocket {
    [self.lock lock];
    _activeSocket = activeSocket;
    [self.lock unlock];
}

- (BOOL)isClosed {
    [self.lock lock];
    BOOL closed = self.closed;
    [self.lock unlock];
    return closed;
}

- (void)closeWithCompletion:(SSHKitCompletion)completion {
    [self.lock lock];
    if (self.didCallCloseHandler) {
        [self.lock unlock];
        completion(nil);
        return;
    }
    self.closed = YES;
    int activeSocket = self.activeSocket;
    [self.closeCompletions addObject:[completion copy]];
    [self.lock unlock];

    SSHCoreShutdownDescriptor(activeSocket);
}

- (void)invalidateOnWorkerQueue {
    [self.lock lock];
    self.closed = YES;
    int activeSocket = self.activeSocket;
    self.activeSocket = -1;
    BOOL shouldCancelRemoteForward = !self.didCancelRemoteForward;
    self.didCancelRemoteForward = YES;
    [self.lock unlock];

    SSHCoreCloseDescriptor(&activeSocket);
    if (shouldCancelRemoteForward) {
        ssh_forward_cancel(self.session, self.remoteHost.UTF8String, self.boundPort);
    }
}

- (void)callCloseHandlerIfNeeded {
    [self.lock lock];
    if (self.didCallCloseHandler) {
        [self.lock unlock];
        return;
    }
    self.didCallCloseHandler = YES;
    [self.lock unlock];
    self.closeHandler();
}

- (void)completePendingCloseCompletions {
    [self.lock lock];
    NSArray<SSHKitCompletion> *completions = [self.closeCompletions copy];
    [self.closeCompletions removeAllObjects];
    [self.lock unlock];

    for (SSHKitCompletion completion in completions) {
        completion(nil);
    }
}

@end

#pragma clang diagnostic pop

@implementation SSHCoreLibSSHSFTPFileRuntime

- (instancetype)initWithFile:(sftp_file)file
                       owner:(SSHCoreLibSSHSFTPRuntime *)owner
                 workerQueue:(dispatch_queue_t)workerQueue
                       client:(SSHCoreOpenSSHClient *)client {
    NSParameterAssert(file != NULL);
    NSParameterAssert(owner != nil);
    NSParameterAssert(workerQueue != nil);

    self = [super init];
    if (self) {
        _file = file;
        _owner = owner;
        _workerQueue = workerQueue;
        _client = client;
    }
    return self;
}

- (void)readDataWithMaximumLength:(NSUInteger)maximumLength completion:(SSHKitSFTPDataCompletion)completion {
    dispatch_async(self.workerQueue, ^{
        NSError *stateError = nil;
        if (![self ensureOpenWithError:&stateError]) {
            completion(nil, stateError);
            return;
        }

        uint32_t boundedLength = (uint32_t)MIN(maximumLength, (NSUInteger)32768);
        NSMutableData *data = [NSMutableData dataWithLength:(NSUInteger)boundedLength];
        ssize_t bytesRead = sftp_read(self.file, data.mutableBytes, boundedLength);
        if (bytesRead < 0) {
            completion(nil, [self.client sftpErrorForOperation:@"SFTP file read" status:sftp_get_error(self.file->sftp)]);
            return;
        }

        data.length = (NSUInteger)bytesRead;
        completion(data, nil);
    });
}

- (void)writeData:(NSData *)data completion:(SSHKitCompletion)completion {
    dispatch_async(self.workerQueue, ^{
        NSError *stateError = nil;
        if (![self ensureOpenWithError:&stateError]) {
            completion(stateError);
            return;
        }

        const uint8_t *bytes = data.bytes;
        NSUInteger remaining = data.length;
        while (remaining > 0) {
            ssize_t bytesWritten = sftp_write(self.file, bytes, remaining);
            if (bytesWritten < 0) {
                completion([self.client sftpErrorForOperation:@"SFTP file write" status:sftp_get_error(self.file->sftp)]);
                return;
            }
            if (bytesWritten == 0) {
                completion(SSHKitMakeError(SSHKitErrorCodeConnectionFailed, @"SFTP file write made no progress."));
                return;
            }
            bytes += bytesWritten;
            remaining -= (NSUInteger)bytesWritten;
        }
        completion(nil);
    });
}

- (void)seekToOffset:(uint64_t)offset completion:(SSHKitCompletion)completion {
    dispatch_async(self.workerQueue, ^{
        NSError *stateError = nil;
        if (![self ensureOpenWithError:&stateError]) {
            completion(stateError);
            return;
        }

        int result = sftp_seek64(self.file, offset);
        completion(result == SSH_OK ? nil : [self.client sftpErrorForOperation:@"SFTP file seek" status:sftp_get_error(self.file->sftp)]);
    });
}

- (void)closeWithCompletion:(SSHKitCompletion)completion {
    dispatch_async(self.workerQueue, ^{
        if (self.closed || self.file == NULL) {
            completion(nil);
            return;
        }

        sftp_file file = self.file;
        self.file = NULL;
        self.closed = YES;
        int result = sftp_close(file);
        [self.owner unregisterFileRuntime:self];
        completion(result == SSH_OK ? nil : SSHKitMakeError(SSHKitErrorCodeSFTPFailure, @"SFTP file close failed."));
    });
}

- (BOOL)ensureOpenWithError:(NSError **)error {
    if (!self.closed && self.file != NULL && [self.owner isOpenOnWorkerQueue]) {
        return YES;
    }

    NSAssert(NO, @"SFTP file handle is closed.");
    if (error) {
        *error = SSHKitMakeError(SSHKitErrorCodeInvalidState, @"SFTP file handle is closed.");
    }
    return NO;
}

- (void)invalidateOnWorkerQueue {
    if (self.closed) {
        return;
    }

    self.closed = YES;
    sftp_file file = self.file;
    self.file = NULL;
    if (file != NULL) {
        sftp_close(file);
    }
    [self.owner unregisterFileRuntime:self];
}

- (void)dealloc {
    sftp_file file = self.file;
    if (file == NULL) {
        return;
    }
    SSHCoreLibSSHSFTPRuntime *owner = self.owner;
    dispatch_async(self.workerQueue, ^{
        sftp_close(file);
        (void)owner;
    });
}

@end

@implementation SSHCoreLibSSHSFTPRuntime

- (instancetype)initWithSession:(sftp_session)sftp
                    workerQueue:(dispatch_queue_t)workerQueue
                    closeHandler:(SSHCoreSFTPCloseHandler)closeHandler
                          client:(SSHCoreOpenSSHClient *)client {
    NSParameterAssert(sftp != NULL);
    NSParameterAssert(workerQueue != nil);

    self = [super init];
    if (self) {
        _sftp = sftp;
        _workerQueue = workerQueue;
        _closeHandler = [closeHandler copy];
        _client = client;
        _fileRuntimes = [NSHashTable weakObjectsHashTable];
    }
    return self;
}

- (SSHKitSFTPAttributes *)attributesFromSFTPAttributes:(sftp_attributes)attributes {
    NSDate *accessedAt = attributes->atime64 > 0 ? [NSDate dateWithTimeIntervalSince1970:(NSTimeInterval)attributes->atime64] : nil;
    NSDate *modifiedAt = attributes->mtime64 > 0 ? [NSDate dateWithTimeIntervalSince1970:(NSTimeInterval)attributes->mtime64] : nil;
    return [[SSHKitSFTPAttributes alloc] initWithSize:attributes->size
                                         permissions:attributes->permissions
                                                 uid:attributes->uid
                                                 gid:attributes->gid
                                                type:attributes->type
                                          accessedAt:accessedAt
                                          modifiedAt:modifiedAt];
}

- (void)listDirectory:(NSString *)path completion:(SSHKitSFTPListCompletion)completion {
    dispatch_async(self.workerQueue, ^{
        NSError *startError = nil;
        if (![self beginOperationWithError:&startError]) {
            completion(nil, startError);
            return;
        }

        NSMutableArray<SSHKitSFTPEntry *> *entries = [[NSMutableArray alloc] init];
        sftp_dir directory = sftp_opendir(self.sftp, path.UTF8String);
        if (directory == NULL) {
            NSError *error = [self.client sftpErrorForOperation:@"SFTP list" sftp:self.sftp];
            [self endOperation];
            completion(nil, error);
            return;
        }

        while (YES) {
            sftp_attributes attributes = sftp_readdir(self.sftp, directory);
            if (attributes == NULL) {
                break;
            }

            if (attributes->name != NULL) {
                NSString *filename = [NSString stringWithUTF8String:attributes->name];
                if (![filename isEqualToString:@"."] && ![filename isEqualToString:@".."]) {
                    [entries addObject:[[SSHKitSFTPEntry alloc] initWithFilename:filename attributes:[self attributesFromSFTPAttributes:attributes]]];
                }
            }
            sftp_attributes_free(attributes);
        }

        BOOL reachedEOF = sftp_dir_eof(directory) != 0;
        int readdirStatus = reachedEOF ? SSH_FX_OK : sftp_get_error(self.sftp);
        sftp_closedir(directory);
        [self endOperation];
        if (!reachedEOF) {
            completion(nil, [self.client sftpErrorForOperation:@"SFTP list" status:readdirStatus]);
            return;
        }

        completion(entries, nil);
    });
}

- (void)realpath:(NSString *)path completion:(SSHKitSFTPStringCompletion)completion {
    dispatch_async(self.workerQueue, ^{
        NSError *startError = nil;
        if (![self beginOperationWithError:&startError]) {
            completion(nil, startError);
            return;
        }

        char *canonicalPath = sftp_canonicalize_path(self.sftp, path.UTF8String);
        [self endOperation];
        if (canonicalPath == NULL) {
            completion(nil, [self.client sftpErrorForOperation:@"SFTP realpath" sftp:self.sftp]);
            return;
        }

        NSString *value = [NSString stringWithUTF8String:canonicalPath];
        free(canonicalPath);
        completion(value, nil);
    });
}

- (void)statPath:(NSString *)path followSymlink:(BOOL)followSymlink completion:(SSHKitSFTPAttributesCompletion)completion {
    dispatch_async(self.workerQueue, ^{
        NSError *startError = nil;
        if (![self beginOperationWithError:&startError]) {
            completion(nil, startError);
            return;
        }

        sftp_attributes attributes = followSymlink ? sftp_stat(self.sftp, path.UTF8String) : sftp_lstat(self.sftp, path.UTF8String);
        [self endOperation];
        if (attributes == NULL) {
            completion(nil, [self.client sftpErrorForOperation:followSymlink ? @"SFTP stat" : @"SFTP lstat" sftp:self.sftp]);
            return;
        }

        SSHKitSFTPAttributes *result = [self attributesFromSFTPAttributes:attributes];
        sftp_attributes_free(attributes);
        completion(result, nil);
    });
}

- (void)setPermissions:(uint32_t)permissions atPath:(NSString *)path completion:(SSHKitCompletion)completion {
    dispatch_async(self.workerQueue, ^{
        NSError *startError = nil;
        if (![self beginOperationWithError:&startError]) {
            completion(startError);
            return;
        }

        int result = sftp_chmod(self.sftp, path.UTF8String, (mode_t)permissions);
        [self endOperation];
        completion(result == SSH_OK ? nil : [self.client sftpErrorForOperation:@"SFTP chmod" sftp:self.sftp]);
    });
}

- (void)fileSystemAttributesAtPath:(NSString *)path completion:(SSHKitSFTPFileSystemAttributesCompletion)completion {
    dispatch_async(self.workerQueue, ^{
        NSError *startError = nil;
        if (![self beginOperationWithError:&startError]) {
            completion(nil, startError);
            return;
        }

        sftp_statvfs_t statvfs = sftp_statvfs(self.sftp, path.UTF8String);
        [self endOperation];
        if (statvfs == NULL) {
            completion(nil, [self.client sftpErrorForOperation:@"SFTP statvfs" sftp:self.sftp]);
            return;
        }

        NSDictionary<NSString *, NSNumber *> *attributes = @{
            @"blockSize": @(statvfs->f_bsize),
            @"fundamentalBlockSize": @(statvfs->f_frsize),
            @"blocks": @(statvfs->f_blocks),
            @"freeBlocks": @(statvfs->f_bfree),
            @"availableBlocks": @(statvfs->f_bavail),
            @"files": @(statvfs->f_files),
            @"freeFiles": @(statvfs->f_ffree),
        };
        sftp_statvfs_free(statvfs);
        completion(attributes, nil);
    });
}

- (void)createDirectoryAtPath:(NSString *)path permissions:(uint32_t)permissions completion:(SSHKitCompletion)completion {
    dispatch_async(self.workerQueue, ^{
        NSError *startError = nil;
        if (![self beginOperationWithError:&startError]) {
            completion(startError);
            return;
        }

        int result = sftp_mkdir(self.sftp, path.UTF8String, (mode_t)permissions);
        [self endOperation];
        completion(result == SSH_OK ? nil : [self.client sftpErrorForOperation:@"SFTP mkdir" sftp:self.sftp]);
    });
}

- (void)removeDirectoryAtPath:(NSString *)path completion:(SSHKitCompletion)completion {
    dispatch_async(self.workerQueue, ^{
        NSError *startError = nil;
        if (![self beginOperationWithError:&startError]) {
            completion(startError);
            return;
        }

        int result = sftp_rmdir(self.sftp, path.UTF8String);
        [self endOperation];
        completion(result == SSH_OK ? nil : [self.client sftpErrorForOperation:@"SFTP rmdir" sftp:self.sftp]);
    });
}

- (void)removeFileAtPath:(NSString *)path completion:(SSHKitCompletion)completion {
    dispatch_async(self.workerQueue, ^{
        NSError *startError = nil;
        if (![self beginOperationWithError:&startError]) {
            completion(startError);
            return;
        }

        int result = sftp_unlink(self.sftp, path.UTF8String);
        [self endOperation];
        completion(result == SSH_OK ? nil : [self.client sftpErrorForOperation:@"SFTP unlink" sftp:self.sftp]);
    });
}

- (void)renamePath:(NSString *)sourcePath toPath:(NSString *)destinationPath completion:(SSHKitCompletion)completion {
    dispatch_async(self.workerQueue, ^{
        NSError *startError = nil;
        if (![self beginOperationWithError:&startError]) {
            completion(startError);
            return;
        }

        int result = sftp_rename(self.sftp, sourcePath.UTF8String, destinationPath.UTF8String);
        [self endOperation];
        completion(result == SSH_OK ? nil : [self.client sftpErrorForOperation:@"SFTP rename" sftp:self.sftp]);
    });
}

- (void)readLinkAtPath:(NSString *)path completion:(SSHKitSFTPStringCompletion)completion {
    dispatch_async(self.workerQueue, ^{
        NSError *startError = nil;
        if (![self beginOperationWithError:&startError]) {
            completion(nil, startError);
            return;
        }

        char *target = sftp_readlink(self.sftp, path.UTF8String);
        [self endOperation];
        if (target == NULL) {
            completion(nil, [self.client sftpErrorForOperation:@"SFTP readlink" sftp:self.sftp]);
            return;
        }

        NSString *value = [NSString stringWithUTF8String:target];
        free(target);
        completion(value, nil);
    });
}

- (void)createSymbolicLinkAtPath:(NSString *)linkPath targetPath:(NSString *)targetPath completion:(SSHKitCompletion)completion {
    dispatch_async(self.workerQueue, ^{
        NSError *startError = nil;
        if (![self beginOperationWithError:&startError]) {
            completion(startError);
            return;
        }

        int result = sftp_symlink(self.sftp, targetPath.UTF8String, linkPath.UTF8String);
        [self endOperation];
        completion(result == SSH_OK ? nil : [self.client sftpErrorForOperation:@"SFTP symlink" sftp:self.sftp]);
    });
}

- (void)openFileAtPath:(NSString *)path flags:(SSHKitSFTPFileOpenFlags)flags permissions:(uint32_t)permissions completion:(SSHKitSFTPFileHandleCompletion)completion {
    dispatch_async(self.workerQueue, ^{
        NSError *startError = nil;
        if (![self beginOperationWithError:&startError]) {
            completion(nil, startError);
            return;
        }

        sftp_file file = sftp_open(self.sftp, path.UTF8String, SSHCoreSFTPFileOpenFlagsToPOSIX(flags), permissions);
        if (file == NULL) {
            NSError *error = [self.client sftpErrorForOperation:@"SFTP file open" sftp:self.sftp];
            [self endOperation];
            completion(nil, error);
            return;
        }

        SSHCoreLibSSHSFTPFileRuntime *fileRuntime = [[SSHCoreLibSSHSFTPFileRuntime alloc] initWithFile:file
                                                                                                 owner:self
                                                                                           workerQueue:self.workerQueue
                                                                                                 client:self.client];
        [self registerFileRuntime:fileRuntime];
        SSHKitSFTPFileHandle *handle = [[SSHKitSFTPFileHandle alloc] initWithReadBlock:^(NSUInteger maximumLength, SSHKitSFTPDataCompletion readCompletion) {
            [fileRuntime readDataWithMaximumLength:maximumLength completion:readCompletion];
        } writeBlock:^(NSData *data, SSHKitCompletion writeCompletion) {
            [fileRuntime writeData:data completion:writeCompletion];
        } seekBlock:^(uint64_t offset, SSHKitCompletion seekCompletion) {
            [fileRuntime seekToOffset:offset completion:seekCompletion];
        } closeBlock:^(SSHKitCompletion closeCompletion) {
            [fileRuntime closeWithCompletion:closeCompletion];
        }];
        [self endOperation];
        completion(handle, nil);
    });
}

- (void)readFileAtPath:(NSString *)path completion:(SSHKitSFTPDataCompletion)completion {
    dispatch_async(self.workerQueue, ^{
        NSError *startError = nil;
        if (![self beginOperationWithError:&startError]) {
            completion(nil, startError);
            return;
        }

        NSMutableData *data = [[NSMutableData alloc] init];
        NSError *error = [self readRemotePath:path intoData:data progress:nil];
        [self endOperation];
        completion(error == nil ? data : nil, error);
    });
}

- (void)writeData:(NSData *)data toFileAtPath:(NSString *)path completion:(SSHKitCompletion)completion {
    dispatch_async(self.workerQueue, ^{
        NSError *startError = nil;
        if (![self beginOperationWithError:&startError]) {
            completion(startError);
            return;
        }

        NSError *error = [self writeData:data toRemotePath:path progress:nil];
        [self endOperation];
        completion(error);
    });
}

- (void)downloadFileAtPath:(NSString *)remotePath toLocalPath:(NSString *)localPath resume:(BOOL)resume progress:(SSHKitSFTPProgressHandler)progress completion:(SSHKitCompletion)completion {
    dispatch_async(self.workerQueue, ^{
        NSError *startError = nil;
        if (![self beginOperationWithError:&startError]) {
            completion(startError);
            return;
        }

        NSError *error = [self downloadRemotePath:remotePath toLocalPath:localPath resume:resume progress:progress];
        [self endOperation];
        completion(error);
    });
}

- (void)uploadFileAtPath:(NSString *)localPath toRemotePath:(NSString *)remotePath resume:(BOOL)resume progress:(SSHKitSFTPProgressHandler)progress completion:(SSHKitCompletion)completion {
    dispatch_async(self.workerQueue, ^{
        NSError *startError = nil;
        if (![self beginOperationWithError:&startError]) {
            completion(startError);
            return;
        }

        NSError *error = [self uploadLocalPath:localPath toRemotePath:remotePath resume:resume progress:progress];
        [self endOperation];
        completion(error);
    });
}

- (void)closeWithCompletion:(SSHKitCompletion)completion {
    dispatch_async(self.workerQueue, ^{
        if (self.closed) {
            completion(nil);
            return;
        }

        self.closed = YES;
        for (SSHCoreLibSSHSFTPFileRuntime *fileRuntime in self.fileRuntimes.allObjects) {
            [fileRuntime invalidateOnWorkerQueue];
        }
        [self.fileRuntimes removeAllObjects];
        sftp_session sftp = self.sftp;
        self.sftp = NULL;
        if (sftp != NULL) {
            sftp_free(sftp);
        }
        [self callCloseHandlerIfNeeded];
        completion(nil);
    });
}

- (BOOL)beginOperationWithError:(NSError **)error {
    if (self.closed || self.sftp == NULL) {
        if (error) {
            *error = SSHKitMakeError(SSHKitErrorCodeInvalidState, @"SFTP client is closed.");
        }
        return NO;
    }
    NSAssert(!self.runningOperation, @"SFTP client operation reentered the serial worker queue.");

    self.runningOperation = YES;
    return YES;
}

- (void)endOperation {
    self.runningOperation = NO;
}

- (NSError *)readRemotePath:(NSString *)remotePath intoData:(NSMutableData *)data progress:(SSHKitSFTPProgressHandler)progress {
    sftp_file remoteFile = sftp_open(self.sftp, remotePath.UTF8String, O_RDONLY, 0);
    if (remoteFile == NULL) {
        return [self.client sftpErrorForOperation:@"SFTP read open" sftp:self.sftp];
    }

    uint64_t totalBytes = 0;
    sftp_attributes attributes = sftp_stat(self.sftp, remotePath.UTF8String);
    if (attributes != NULL) {
        totalBytes = attributes->size;
        sftp_attributes_free(attributes);
    } else {
        sftp_close(remoteFile);
        return [self.client sftpErrorForOperation:@"SFTP read stat" sftp:self.sftp];
    }
    if (totalBytes > SSHCoreSFTPMaximumReadFileSize) {
        sftp_close(remoteFile);
        return SSHKitMakeError(SSHKitErrorCodeSFTPFailure, @"SFTP read exceeds the maximum in-memory read size.");
    }
    uint64_t completedBytes = 0;
    char buffer[32768];
    while (YES) {
        ssize_t bytesRead = sftp_read(remoteFile, buffer, sizeof(buffer));
        if (bytesRead < 0) {
            sftp_close(remoteFile);
            return [self.client sftpErrorForOperation:@"SFTP read" sftp:self.sftp];
        }
        if (bytesRead == 0) {
            break;
        }

        if (data.length + (NSUInteger)bytesRead > SSHCoreSFTPMaximumReadFileSize) {
            sftp_close(remoteFile);
            return SSHKitMakeError(SSHKitErrorCodeSFTPFailure, @"SFTP read exceeds the maximum in-memory read size.");
        }
        [data appendBytes:buffer length:(NSUInteger)bytesRead];
        completedBytes += (uint64_t)bytesRead;
        if (progress != nil) {
            progress(completedBytes, totalBytes);
        }
    }

    if (sftp_close(remoteFile) != SSH_OK) {
        return [self.client sftpErrorForOperation:@"SFTP read close" sftp:self.sftp];
    }
    return nil;
}

- (NSError *)writeData:(NSData *)data toRemotePath:(NSString *)remotePath progress:(SSHKitSFTPProgressHandler)progress {
    sftp_file remoteFile = sftp_open(self.sftp, remotePath.UTF8String, O_CREAT | O_TRUNC | O_WRONLY, 0600);
    if (remoteFile == NULL) {
        return [self.client sftpErrorForOperation:@"SFTP write open" sftp:self.sftp];
    }

    const uint8_t *bytes = data.bytes;
    NSUInteger remaining = data.length;
    uint64_t completedBytes = 0;
    uint64_t totalBytes = (uint64_t)data.length;
    while (remaining > 0) {
        size_t chunkLength = MIN(remaining, (NSUInteger)32768);
        ssize_t bytesWritten = sftp_write(remoteFile, bytes, chunkLength);
        if (bytesWritten < 0) {
            sftp_close(remoteFile);
            return [self.client sftpErrorForOperation:@"SFTP write" sftp:self.sftp];
        }
        if (bytesWritten == 0) {
            sftp_close(remoteFile);
            return SSHKitMakeError(SSHKitErrorCodeConnectionFailed, @"SFTP write made no progress.");
        }
        bytes += bytesWritten;
        remaining -= (NSUInteger)bytesWritten;
        completedBytes += (uint64_t)bytesWritten;
        if (progress != nil) {
            progress(completedBytes, totalBytes);
        }
    }

    if (sftp_close(remoteFile) != SSH_OK) {
        return [self.client sftpErrorForOperation:@"SFTP write close" sftp:self.sftp];
    }
    return nil;
}

- (NSError *)downloadRemotePath:(NSString *)remotePath toLocalPath:(NSString *)localPath resume:(BOOL)resume progress:(SSHKitSFTPProgressHandler)progress {
    sftp_file remoteFile = sftp_open(self.sftp, remotePath.UTF8String, O_RDONLY, 0);
    if (remoteFile == NULL) {
        return [self.client sftpErrorForOperation:@"SFTP download open" sftp:self.sftp];
    }

    sftp_attributes attributes = sftp_stat(self.sftp, remotePath.UTF8String);
    if (attributes == NULL) {
        sftp_close(remoteFile);
        return [self.client sftpErrorForOperation:@"SFTP download stat" sftp:self.sftp];
    }
    uint64_t totalBytes = attributes->size;
    sftp_attributes_free(attributes);

    int openFlags = O_CREAT | O_WRONLY | (resume ? O_APPEND : O_TRUNC);
    int localFileDescriptor = open(localPath.fileSystemRepresentation, openFlags, 0600);
    if (localFileDescriptor < 0) {
        sftp_close(remoteFile);
        return SSHKitMakeError(SSHKitErrorCodeUnavailable, [NSString stringWithFormat:@"Unable to open local download file: %s", strerror(errno)]);
    }

    uint64_t completedBytes = 0;
    if (resume) {
        off_t localOffset = lseek(localFileDescriptor, 0, SEEK_END);
        if (localOffset < 0) {
            close(localFileDescriptor);
            sftp_close(remoteFile);
            return SSHKitMakeError(SSHKitErrorCodeUnavailable, [NSString stringWithFormat:@"Unable to seek local download file: %s", strerror(errno)]);
        }
        completedBytes = (uint64_t)localOffset;
        if (completedBytes > totalBytes) {
            close(localFileDescriptor);
            sftp_close(remoteFile);
            return SSHKitMakeError(SSHKitErrorCodeUnavailable, @"Local partial download is larger than the remote file.");
        }
        if (sftp_seek64(remoteFile, completedBytes) != SSH_OK) {
            close(localFileDescriptor);
            sftp_close(remoteFile);
            return [self.client sftpErrorForOperation:@"SFTP download seek" sftp:self.sftp];
        }
    }

    char buffer[32768];
    while (YES) {
        ssize_t bytesRead = sftp_read(remoteFile, buffer, sizeof(buffer));
        if (bytesRead < 0) {
            close(localFileDescriptor);
            sftp_close(remoteFile);
            return [self.client sftpErrorForOperation:@"SFTP download read" sftp:self.sftp];
        }
        if (bytesRead == 0) {
            break;
        }

        ssize_t bytesWritten = write(localFileDescriptor, buffer, (size_t)bytesRead);
        if (bytesWritten != bytesRead) {
            close(localFileDescriptor);
            sftp_close(remoteFile);
            return SSHKitMakeError(SSHKitErrorCodeUnavailable, [NSString stringWithFormat:@"Unable to write local download file: %s", strerror(errno)]);
        }
        completedBytes += (uint64_t)bytesRead;
        if (progress != nil) {
            progress(completedBytes, totalBytes);
        }
    }

    if (close(localFileDescriptor) != 0) {
        sftp_close(remoteFile);
        return SSHKitMakeError(SSHKitErrorCodeUnavailable, [NSString stringWithFormat:@"Unable to close local download file: %s", strerror(errno)]);
    }
    if (sftp_close(remoteFile) != SSH_OK) {
        return [self.client sftpErrorForOperation:@"SFTP download close" sftp:self.sftp];
    }
    return nil;
}

- (NSError *)uploadLocalPath:(NSString *)localPath toRemotePath:(NSString *)remotePath resume:(BOOL)resume progress:(SSHKitSFTPProgressHandler)progress {
    int localFileDescriptor = open(localPath.fileSystemRepresentation, O_RDONLY);
    if (localFileDescriptor < 0) {
        return SSHKitMakeError(SSHKitErrorCodeUnavailable, [NSString stringWithFormat:@"Unable to open local upload file: %s", strerror(errno)]);
    }

    struct stat localStat;
    if (fstat(localFileDescriptor, &localStat) != 0) {
        close(localFileDescriptor);
        return SSHKitMakeError(SSHKitErrorCodeUnavailable, [NSString stringWithFormat:@"Unable to stat local upload file: %s", strerror(errno)]);
    }
    uint64_t totalBytes = (uint64_t)localStat.st_size;
    uint64_t completedBytes = 0;
    if (resume) {
        sftp_attributes remoteAttributes = sftp_stat(self.sftp, remotePath.UTF8String);
        if (remoteAttributes == NULL) {
            close(localFileDescriptor);
            return [self.client sftpErrorForOperation:@"SFTP resume upload stat" sftp:self.sftp];
        }
        completedBytes = remoteAttributes->size;
        sftp_attributes_free(remoteAttributes);
    }
    int remoteFlags = O_CREAT | O_WRONLY | (resume ? 0 : O_TRUNC);
    sftp_file remoteFile = sftp_open(self.sftp, remotePath.UTF8String, remoteFlags, 0600);
    if (remoteFile == NULL) {
        close(localFileDescriptor);
        return [self.client sftpErrorForOperation:@"SFTP upload open" sftp:self.sftp];
    }

    if (resume) {
        if (completedBytes > totalBytes) {
            close(localFileDescriptor);
            sftp_close(remoteFile);
            return SSHKitMakeError(SSHKitErrorCodeUnavailable, @"Remote partial upload is larger than the local file.");
        }
        if (lseek(localFileDescriptor, (off_t)completedBytes, SEEK_SET) < 0 ||
            sftp_seek64(remoteFile, completedBytes) != SSH_OK) {
            close(localFileDescriptor);
            sftp_close(remoteFile);
            return SSHKitMakeError(SSHKitErrorCodeUnavailable, @"Unable to seek resumable upload offsets.");
        }
    }

    char buffer[32768];
    while (YES) {
        ssize_t bytesRead = read(localFileDescriptor, buffer, sizeof(buffer));
        if (bytesRead < 0) {
            close(localFileDescriptor);
            sftp_close(remoteFile);
            return SSHKitMakeError(SSHKitErrorCodeUnavailable, [NSString stringWithFormat:@"Unable to read local upload file: %s", strerror(errno)]);
        }
        if (bytesRead == 0) {
            break;
        }

        ssize_t writtenTotal = 0;
        while (writtenTotal < bytesRead) {
            ssize_t bytesWritten = sftp_write(remoteFile, buffer + writtenTotal, (size_t)(bytesRead - writtenTotal));
            if (bytesWritten < 0) {
                close(localFileDescriptor);
                sftp_close(remoteFile);
                return [self.client sftpErrorForOperation:@"SFTP upload write" sftp:self.sftp];
            }
            if (bytesWritten == 0) {
                close(localFileDescriptor);
                sftp_close(remoteFile);
                return SSHKitMakeError(SSHKitErrorCodeConnectionFailed, @"SFTP upload write made no progress.");
            }
            writtenTotal += bytesWritten;
            completedBytes += (uint64_t)bytesWritten;
            if (progress != nil) {
                progress(completedBytes, totalBytes);
            }
        }
    }

    if (close(localFileDescriptor) != 0) {
        sftp_close(remoteFile);
        return SSHKitMakeError(SSHKitErrorCodeUnavailable, [NSString stringWithFormat:@"Unable to close local upload file: %s", strerror(errno)]);
    }
    if (sftp_close(remoteFile) != SSH_OK) {
        return [self.client sftpErrorForOperation:@"SFTP upload close" sftp:self.sftp];
    }
    return nil;
}

- (void)callCloseHandlerIfNeeded {
    if (self.didCallCloseHandler) {
        return;
    }
    self.didCallCloseHandler = YES;
    self.closeHandler();
}

- (void)invalidateOnWorkerQueue {
    self.closed = YES;
    for (SSHCoreLibSSHSFTPFileRuntime *fileRuntime in self.fileRuntimes.allObjects) {
        [fileRuntime invalidateOnWorkerQueue];
    }
    [self.fileRuntimes removeAllObjects];
    sftp_session sftp = self.sftp;
    self.sftp = NULL;
    if (sftp != NULL) {
        sftp_free(sftp);
    }
    [self callCloseHandlerIfNeeded];
}

- (void)registerFileRuntime:(SSHCoreLibSSHSFTPFileRuntime *)fileRuntime {
    [self.fileRuntimes addObject:fileRuntime];
}

- (void)unregisterFileRuntime:(SSHCoreLibSSHSFTPFileRuntime *)fileRuntime {
    [self.fileRuntimes removeObject:fileRuntime];
}

- (BOOL)isOpenOnWorkerQueue {
    return !self.closed && self.sftp != NULL;
}

- (void)dealloc {
    sftp_session sftp = self.sftp;
    if (sftp == NULL) {
        return;
    }
    SSHCoreSFTPCloseHandler closeHandler = self.closeHandler;
    NSArray<SSHCoreLibSSHSFTPFileRuntime *> *fileRuntimes = self.fileRuntimes.allObjects;
    dispatch_async(self.workerQueue, ^{
        for (SSHCoreLibSSHSFTPFileRuntime *fileRuntime in fileRuntimes) {
            [fileRuntime invalidateOnWorkerQueue];
        }
        sftp_free(sftp);
        closeHandler();
    });
}

@end

@interface SSHCoreOpenSSHClient ()

@property (nonatomic, copy) SSHKitConfiguration *configuration;
@property (nonatomic) SSHCoreSessionWorker *worker;
@property (nonatomic) NSLock *taskLock;
@property (nonatomic, nullable) id currentTask;
@property (nonatomic) BOOL taskCancelled;
@property (nonatomic) ssh_session session;
@property (nonatomic) NSMutableArray<NSValue *> *proxyJumpCallbackPointers;
@property (nonatomic, copy) NSArray<SSHKitConfiguration *> *proxyJumpCallbackConfigurations;
@property (nonatomic, copy, readwrite, nullable) NSString *hostKeySHA256Fingerprint;

@end

@implementation SSHCoreOpenSSHClient

- (instancetype)initWithConfiguration:(SSHKitConfiguration *)configuration worker:(SSHCoreSessionWorker *)worker {
    NSParameterAssert(worker != nil);

    self = [super init];
    if (self) {
        _configuration = [configuration copy];
        _worker = worker;
        _taskLock = [[NSLock alloc] init];
        _proxyJumpCallbackPointers = [[NSMutableArray alloc] init];
        _proxyJumpCallbackConfigurations = @[];
    }
    return self;
}

- (BOOL)verifyConnectionWithError:(NSError **)error {
    return [self connectLibSSHSessionWithError:error];
}

- (NSDictionary<NSString *, NSString *> *)baseLogMetadata {
    return @{
        @"host": self.configuration.host,
        @"port": [NSString stringWithFormat:@"%hu", self.configuration.port],
        @"username": self.configuration.username,
        @"authentication": SSHCoreAuthenticationName(self.configuration.authenticationKind),
        @"hostKeyPolicy": SSHCoreHostKeyPolicyName(self.configuration.hostKeyPolicyKind),
    };
}

- (void)emitLogLevel:(SSHKitLogLevel)level
               phase:(NSString *)phase
             message:(NSString *)message
            metadata:(NSDictionary<NSString *, NSString *> *)metadata {
    SSHKitLogHandler handler = self.configuration.logHandler;
    if (handler == nil) {
        return;
    }

    NSMutableDictionary<NSString *, NSString *> *mergedMetadata = [[self baseLogMetadata] mutableCopy];
    [metadata enumerateKeysAndObjectsUsingBlock:^(NSString *key, NSString *value, BOOL *stop) {
        (void)stop;
        mergedMetadata[key] = value;
    }];
    SSHKitLogEvent *event = [[SSHKitLogEvent alloc] initWithLevel:level
                                                            phase:phase
                                                          message:message
                                                         metadata:mergedMetadata];
    handler(event);
}

- (nullable SSHKitAuthenticationDiscoveryResult *)discoverAuthenticationMethodsWithError:(NSError **)error {
    [self emitLogLevel:SSHKitLogLevelInfo phase:@"authDiscovery" message:@"SSH authentication discovery started." metadata:@{}];
    if (![self connectLibSSHSessionWithoutAuthenticationWithError:error]) {
        return nil;
    }

    [self.taskLock lock];
    ssh_session session = self.session;
    [self.taskLock unlock];

    int noneStatus = ssh_userauth_none(session, NULL);
    int methodMask = noneStatus == SSH_AUTH_SUCCESS ? SSH_AUTH_METHOD_NONE : ssh_userauth_list(session, NULL);
    if (methodMask == SSH_AUTH_METHOD_UNKNOWN && noneStatus != SSH_AUTH_SUCCESS) {
        if (error) {
            *error = [self libSSHErrorWithSession:session code:SSHKitErrorCodeAuthenticationFailed fallback:@"Unable to discover SSH authentication methods."];
        }
        [self emitLogLevel:SSHKitLogLevelError phase:@"authDiscovery" message:@"SSH authentication discovery failed." metadata:@{}];
        return nil;
    }

    char *issueBanner = ssh_get_issue_banner(session);
    NSString *issueBannerString = issueBanner != NULL ? [NSString stringWithUTF8String:issueBanner] : nil;
    free(issueBanner);

    const char *serverBanner = ssh_get_serverbanner(session);
    NSArray<NSNumber *> *methods = SSHCoreAuthenticationMethodsFromMask(methodMask);
    [self emitLogLevel:SSHKitLogLevelInfo
                 phase:@"authDiscovery"
               message:@"SSH authentication discovery succeeded."
              metadata:@{@"methodCount": [NSString stringWithFormat:@"%lu", (unsigned long)methods.count]}];
    return [[SSHKitAuthenticationDiscoveryResult alloc] initWithMethods:methods
                                                            issueBanner:issueBannerString
                                                           serverBanner:SSHCoreNullableStringFromCString(serverBanner)];
}

- (nullable SSHKitCommandResult *)executeCommand:(NSString *)command error:(NSError **)error {
    return [self executeLibSSHCommand:command requestPTY:NO error:error];
}

- (nullable SSHKitCommandResult *)executePTYCommand:(NSString *)command error:(NSError **)error {
    return [self executeLibSSHCommand:command requestPTY:YES error:error];
}

- (nullable SSHKitCommand *)openCommand:(NSString *)command
                           eventHandler:(SSHKitCommandEventHandler)eventHandler
                               onClosed:(SSHCoreCommandClosedBlock)onClosed
                                  error:(NSError **)error {
    [self emitLogLevel:SSHKitLogLevelInfo phase:@"command" message:@"SSH streaming command open started." metadata:@{}];
    ssh_channel channel = [self openSessionChannelWithError:error];
    if (channel == NULL) {
        return nil;
    }

    if (ssh_channel_request_exec(channel, command.UTF8String) != SSH_OK) {
        if (error) {
            *error = [self libSSHErrorWithCode:SSHKitErrorCodeCommandFailed fallback:@"Unable to execute SSH command."];
        }
        ssh_channel_close(channel);
        ssh_channel_free(channel);
        return nil;
    }

    __weak SSHCoreOpenSSHClient *weakSelf = self;
    SSHCoreLibSSHCommandRuntime *runtime = [[SSHCoreLibSSHCommandRuntime alloc] initWithChannel:channel
                                                                                   workerQueue:self.worker.queue
                                                                                   eventHandler:eventHandler
                                                                                       onClosed:^(int32_t exitStatus, NSString *exitSignal) {
        [weakSelf clearCurrentTask];
        onClosed(exitStatus, exitSignal);
    }];
    [self.taskLock lock];
    self.currentTask = runtime;
    BOOL wasCancelled = self.taskCancelled;
    [self.taskLock unlock];
    if (wasCancelled) {
        [runtime closeWithCompletion:^(NSError *closeError) {
            (void)closeError;
        }];
        if (error) {
            *error = SSHKitMakeError(SSHKitErrorCodeCancelled, @"SSH command was cancelled before start.");
        }
        return nil;
    }

    [self emitLogLevel:SSHKitLogLevelInfo phase:@"command" message:@"SSH streaming command opened." metadata:@{}];
    return [[SSHKitCommand alloc] initWithWriteBlock:^(NSData *data, SSHKitCompletion completion) {
        [runtime writeData:data completion:completion];
    } eofBlock:^(SSHKitCompletion completion) {
        [runtime sendEOFWithCompletion:completion];
    } closeBlock:^(SSHKitCompletion completion) {
        [runtime closeWithCompletion:completion];
    } startBlock:^{
        [runtime start];
    }];
}

- (nullable SSHKitShell *)openShellWithTerminalType:(NSString *)terminalType
                                            columns:(uint16_t)columns
                                               rows:(uint16_t)rows
                                       eventHandler:(SSHKitShellEventHandler)eventHandler
                                           onClosed:(SSHCoreShellClosedBlock)onClosed
                                              error:(NSError **)error {
    [self emitLogLevel:SSHKitLogLevelInfo
                 phase:@"shell"
               message:@"SSH shell open started."
              metadata:@{@"terminalType": terminalType,
                         @"columns": [NSString stringWithFormat:@"%hu", columns],
                         @"rows": [NSString stringWithFormat:@"%hu", rows]}];
    ssh_channel channel = [self openSessionChannelWithError:error];
    if (channel == NULL) {
        return nil;
    }

    if (ssh_channel_request_pty_size(channel, terminalType.UTF8String, columns, rows) != SSH_OK) {
        if (error) {
            *error = [self libSSHErrorWithCode:SSHKitErrorCodeConnectionFailed fallback:@"Unable to request SSH shell PTY."];
        }
        ssh_channel_close(channel);
        ssh_channel_free(channel);
        return nil;
    }

    if (ssh_channel_request_shell(channel) != SSH_OK) {
        if (error) {
            *error = [self libSSHErrorWithCode:SSHKitErrorCodeConnectionFailed fallback:@"Unable to request SSH shell."];
        }
        ssh_channel_close(channel);
        ssh_channel_free(channel);
        return nil;
    }

    __weak SSHCoreOpenSSHClient *weakSelf = self;
    SSHCoreLibSSHShellRuntime *runtime = [[SSHCoreLibSSHShellRuntime alloc] initWithChannel:channel
                                                                                workerQueue:self.worker.queue
                                                                                eventHandler:eventHandler
                                                                                    onClosed:^(int32_t exitStatus) {
        [weakSelf clearCurrentTask];
        onClosed(exitStatus);
    }];
    [self.taskLock lock];
    self.currentTask = runtime;
    BOOL wasCancelled = self.taskCancelled;
    [self.taskLock unlock];
    if (wasCancelled) {
        [runtime closeWithCompletion:^(NSError *closeError) {
            (void)closeError;
        }];
        if (error) {
            *error = SSHKitMakeError(SSHKitErrorCodeCancelled, @"SSH shell was cancelled before start.");
        }
        return nil;
    }

    [self emitLogLevel:SSHKitLogLevelInfo phase:@"shell" message:@"SSH shell opened." metadata:@{}];
    return [[SSHKitShell alloc] initWithWriteBlock:^(NSData *data, SSHKitCompletion completion) {
        [runtime writeData:data completion:completion];
    } resizeBlock:^(uint16_t resizeColumns, uint16_t resizeRows, SSHKitCompletion completion) {
        [runtime resizeWithColumns:resizeColumns rows:resizeRows completion:completion];
    } closeBlock:^(SSHKitCompletion completion) {
        [runtime closeWithCompletion:completion];
    } startBlock:^{
        [runtime start];
    }];
}

- (nullable SSHKitSFTPClient *)openSFTPWithCloseHandler:(SSHCoreSFTPCloseHandler)closeHandler error:(NSError **)error {
    [self emitLogLevel:SSHKitLogLevelInfo phase:@"sftp" message:@"SSH SFTP open started." metadata:@{}];
    if (self.session == NULL) {
        if (error) {
            *error = SSHKitMakeError(SSHKitErrorCodeInvalidState, @"SSH session is not connected.");
        }
        return nil;
    }

    sftp_session sftp = sftp_new(self.session);
    if (sftp == NULL) {
        if (error) {
            *error = [self libSSHErrorWithCode:SSHKitErrorCodeConnectionFailed fallback:@"Unable to allocate SFTP session."];
        }
        return nil;
    }

    if (sftp_init(sftp) != SSH_OK) {
        if (error) {
            *error = [self sftpErrorForOperation:@"SFTP init" sftp:sftp];
        }
        sftp_free(sftp);
        return nil;
    }

    __weak SSHCoreOpenSSHClient *weakSelf = self;
    SSHCoreLibSSHSFTPRuntime *runtime = [[SSHCoreLibSSHSFTPRuntime alloc] initWithSession:sftp
                                                                              workerQueue:self.worker.queue
                                                                             closeHandler:^{
        [weakSelf clearCurrentTask];
        closeHandler();
    }
                                                                                   client:self];
    [self.taskLock lock];
    self.currentTask = runtime;
    [self.taskLock unlock];
    [self emitLogLevel:SSHKitLogLevelInfo phase:@"sftp" message:@"SSH SFTP opened." metadata:@{}];
    return [[SSHKitSFTPClient alloc] initWithListBlock:^(NSString *path, SSHKitSFTPListCompletion completion) {
        [runtime listDirectory:path completion:completion];
    } realpathBlock:^(NSString *path, SSHKitSFTPStringCompletion completion) {
        [runtime realpath:path completion:completion];
    } statBlock:^(NSString *path, SSHKitSFTPAttributesCompletion completion) {
        [runtime statPath:path followSymlink:YES completion:completion];
    } lstatBlock:^(NSString *path, SSHKitSFTPAttributesCompletion completion) {
        [runtime statPath:path followSymlink:NO completion:completion];
    } setPermissionsBlock:^(NSString *path, uint32_t permissions, SSHKitCompletion completion) {
        [runtime setPermissions:permissions atPath:path completion:completion];
    } fileSystemAttributesBlock:^(NSString *path, SSHKitSFTPFileSystemAttributesCompletion completion) {
        [runtime fileSystemAttributesAtPath:path completion:completion];
    } createDirectoryBlock:^(NSString *path, uint32_t permissions, SSHKitCompletion completion) {
        [runtime createDirectoryAtPath:path permissions:permissions completion:completion];
    } removeDirectoryBlock:^(NSString *path, SSHKitCompletion completion) {
        [runtime removeDirectoryAtPath:path completion:completion];
    } removeFileBlock:^(NSString *path, SSHKitCompletion completion) {
        [runtime removeFileAtPath:path completion:completion];
    } renameBlock:^(NSString *sourcePath, NSString *destinationPath, SSHKitCompletion completion) {
        [runtime renamePath:sourcePath toPath:destinationPath completion:completion];
    } readLinkBlock:^(NSString *path, SSHKitSFTPStringCompletion completion) {
        [runtime readLinkAtPath:path completion:completion];
    } createSymbolicLinkBlock:^(NSString *targetPath, NSString *linkPath, SSHKitCompletion completion) {
        [runtime createSymbolicLinkAtPath:linkPath targetPath:targetPath completion:completion];
    } openFileBlock:^(NSString *path, SSHKitSFTPFileOpenFlags flags, uint32_t permissions, SSHKitSFTPFileHandleCompletion completion) {
        [runtime openFileAtPath:path flags:flags permissions:permissions completion:completion];
    } readFileBlock:^(NSString *path, SSHKitSFTPDataCompletion completion) {
        [runtime readFileAtPath:path completion:completion];
    } writeDataBlock:^(NSString *path, NSData *data, SSHKitCompletion completion) {
        [runtime writeData:data toFileAtPath:path completion:completion];
    } downloadBlock:^(NSString *remotePath, NSString *localPath, BOOL resume, SSHKitSFTPProgressHandler progress, SSHKitCompletion completion) {
        [runtime downloadFileAtPath:remotePath toLocalPath:localPath resume:resume progress:progress completion:completion];
    } uploadBlock:^(NSString *localPath, NSString *remotePath, BOOL resume, SSHKitSFTPProgressHandler progress, SSHKitCompletion completion) {
        [runtime uploadFileAtPath:localPath toRemotePath:remotePath resume:resume progress:progress completion:completion];
    } closeBlock:^(SSHKitCompletion completion) {
        [runtime closeWithCompletion:completion];
    }];
}

- (nullable SSHKitTunnelChannel *)openDirectTCPChannelToHost:(NSString *)host
                                                        port:(uint16_t)port
                                                closeHandler:(SSHCoreTunnelCloseHandler)closeHandler
                                                       error:(NSError **)error {
    [self emitLogLevel:SSHKitLogLevelInfo
                 phase:@"tunnel"
               message:@"SSH direct TCP channel open started."
              metadata:@{@"targetHost": host,
                         @"targetPort": [NSString stringWithFormat:@"%hu", port]}];
    if (self.session == NULL) {
        if (error) {
            *error = SSHKitMakeError(SSHKitErrorCodeInvalidState, @"SSH session is not connected.");
        }
        return nil;
    }

    ssh_channel channel = ssh_channel_new(self.session);
    if (channel == NULL) {
        if (error) {
            *error = [self libSSHErrorWithCode:SSHKitErrorCodeConnectionFailed fallback:@"Unable to allocate SSH tunnel channel."];
        }
        return nil;
    }

    if (ssh_channel_open_forward(channel, host.UTF8String, port, self.configuration.host.UTF8String, 0) != SSH_OK) {
        if (error) {
            *error = [self libSSHErrorWithCode:SSHKitErrorCodeConnectionFailed fallback:@"Unable to open SSH direct TCP channel."];
        }
        ssh_channel_free(channel);
        return nil;
    }

    __weak SSHCoreOpenSSHClient *weakSelf = self;
    SSHCoreLibSSHTunnelRuntime *runtime = [[SSHCoreLibSSHTunnelRuntime alloc] initWithChannel:channel
                                                                                  workerQueue:self.worker.queue
                                                                                  isCancelled:^BOOL{
        SSHCoreOpenSSHClient *strongSelf = weakSelf;
        return strongSelf ? [strongSelf isTaskCancelled] : NO;
    }
                                                                                 closeHandler:^{
        [weakSelf clearCurrentTask];
        closeHandler();
    }];
    [self.taskLock lock];
    self.currentTask = runtime;
    [self.taskLock unlock];

    [self emitLogLevel:SSHKitLogLevelInfo
                 phase:@"tunnel"
               message:@"SSH direct TCP channel opened."
              metadata:@{@"targetHost": host,
                         @"targetPort": [NSString stringWithFormat:@"%hu", port]}];
    return [[SSHKitTunnelChannel alloc] initWithReadBlock:^(NSUInteger maximumLength, SSHKitTunnelReadCompletion completion) {
        [runtime readDataWithMaximumLength:maximumLength completion:completion];
    } writeBlock:^(NSData *data, SSHKitCompletion completion) {
        [runtime writeData:data completion:completion];
    } closeBlock:^(SSHKitCompletion completion) {
        [runtime closeWithCompletion:completion];
    }];
}

- (nullable SSHKitPortForward *)startLocalForwardFromHost:(NSString *)localHost
                                                     port:(uint16_t)localPort
                                                   toHost:(NSString *)remoteHost
                                               targetPort:(uint16_t)remotePort
                                             closeHandler:(SSHCoreTunnelCloseHandler)closeHandler
                                                    error:(NSError **)error {
    [self emitLogLevel:SSHKitLogLevelInfo
                 phase:@"tunnel"
               message:@"SSH local forward start requested."
              metadata:@{@"localHost": localHost,
                         @"localPort": [NSString stringWithFormat:@"%hu", localPort],
                         @"targetHost": remoteHost,
                         @"targetPort": [NSString stringWithFormat:@"%hu", remotePort]}];
    if (self.session == NULL) {
        if (error) {
            *error = SSHKitMakeError(SSHKitErrorCodeInvalidState, @"SSH session is not connected.");
        }
        return nil;
    }

    uint16_t boundPort = 0;
    int listenerSocket = [self openLocalForwardListenerAtHost:localHost port:localPort boundPort:&boundPort error:error];
    if (listenerSocket < 0) {
        return nil;
    }

    __weak SSHCoreOpenSSHClient *weakSelf = self;
    SSHCoreLibSSHLocalForwardRuntime *runtime = [[SSHCoreLibSSHLocalForwardRuntime alloc] initWithSession:self.session
                                                                                           listenerSocket:listenerSocket
                                                                                                boundHost:localHost
                                                                                                boundPort:boundPort
                                                                                               targetHost:remoteHost
                                                                                               targetPort:remotePort
                                                                                            socksUsername:nil
                                                                                            socksPassword:nil
                                                                                              workerQueue:self.worker.queue
                                                                                             closeHandler:^{
        [weakSelf clearCurrentTask];
        closeHandler();
    }
                                                                                                   client:self];
    [self.taskLock lock];
    self.currentTask = runtime;
    [self.taskLock unlock];

    dispatch_async(self.worker.queue, ^{
        [runtime start];
    });

    [self emitLogLevel:SSHKitLogLevelInfo
                 phase:@"tunnel"
               message:@"SSH local forward started."
              metadata:@{@"localHost": localHost,
                         @"boundPort": [NSString stringWithFormat:@"%hu", boundPort],
                         @"targetHost": remoteHost,
                         @"targetPort": [NSString stringWithFormat:@"%hu", remotePort]}];
    return [[SSHKitPortForward alloc] initWithBoundHost:localHost boundPort:boundPort closeBlock:^(SSHKitCompletion completion) {
        [runtime closeWithCompletion:completion];
    }];
}

- (nullable SSHKitPortForward *)startDynamicForwardFromHost:(NSString *)localHost
                                                       port:(uint16_t)localPort
                                                   username:(NSString *)username
                                                   password:(NSString *)password
                                               closeHandler:(SSHCoreTunnelCloseHandler)closeHandler
                                                      error:(NSError **)error {
    [self emitLogLevel:SSHKitLogLevelInfo
                 phase:@"tunnel"
               message:@"SSH dynamic SOCKS forward start requested."
              metadata:@{@"localHost": localHost,
                         @"localPort": [NSString stringWithFormat:@"%hu", localPort]}];
    if (self.session == NULL) {
        if (error) {
            *error = SSHKitMakeError(SSHKitErrorCodeInvalidState, @"SSH session is not connected.");
        }
        return nil;
    }

    uint16_t boundPort = 0;
    int listenerSocket = [self openLocalForwardListenerAtHost:localHost port:localPort boundPort:&boundPort error:error];
    if (listenerSocket < 0) {
        return nil;
    }

    __weak SSHCoreOpenSSHClient *weakSelf = self;
    SSHCoreLibSSHLocalForwardRuntime *runtime = [[SSHCoreLibSSHLocalForwardRuntime alloc] initWithSession:self.session
                                                                                           listenerSocket:listenerSocket
                                                                                                boundHost:localHost
                                                                                                boundPort:boundPort
                                                                                               targetHost:nil
                                                                                               targetPort:0
                                                                                            socksUsername:username
                                                                                            socksPassword:password
                                                                                              workerQueue:self.worker.queue
                                                                                             closeHandler:^{
        [weakSelf clearCurrentTask];
        closeHandler();
    }
                                                                                                   client:self];
    [self.taskLock lock];
    self.currentTask = runtime;
    [self.taskLock unlock];

    dispatch_async(self.worker.queue, ^{
        [runtime start];
    });

    [self emitLogLevel:SSHKitLogLevelInfo
                 phase:@"tunnel"
               message:@"SSH dynamic SOCKS forward started."
              metadata:@{@"localHost": localHost,
                         @"boundPort": [NSString stringWithFormat:@"%hu", boundPort]}];
    return [[SSHKitPortForward alloc] initWithBoundHost:localHost boundPort:boundPort closeBlock:^(SSHKitCompletion completion) {
        [runtime closeWithCompletion:completion];
    }];
}

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"

- (nullable SSHKitPortForward *)startRemoteForwardFromHost:(NSString *)remoteHost
                                                      port:(uint16_t)remotePort
                                                    toHost:(NSString *)localHost
                                                targetPort:(uint16_t)localPort
                                              closeHandler:(SSHCoreTunnelCloseHandler)closeHandler
                                                     error:(NSError **)error {
    [self emitLogLevel:SSHKitLogLevelInfo
                 phase:@"tunnel"
               message:@"SSH remote forward start requested."
              metadata:@{@"remoteHost": remoteHost,
                         @"remotePort": [NSString stringWithFormat:@"%hu", remotePort],
                         @"targetHost": localHost,
                         @"targetPort": [NSString stringWithFormat:@"%hu", localPort]}];
    if (self.session == NULL) {
        if (error) {
            *error = SSHKitMakeError(SSHKitErrorCodeInvalidState, @"SSH session is not connected.");
        }
        return nil;
    }

    int boundPort = 0;
    if (ssh_forward_listen(self.session, remoteHost.UTF8String, remotePort, &boundPort) != SSH_OK) {
        if (error) {
            *error = SSHKitMakeError(SSHKitErrorCodeConnectionFailed, @"SSH remote forward listen failed.");
        }
        return nil;
    }

    __weak SSHCoreOpenSSHClient *weakSelf = self;
    SSHCoreLibSSHRemoteForwardRuntime *runtime = [[SSHCoreLibSSHRemoteForwardRuntime alloc] initWithSession:self.session
                                                                                                remoteHost:remoteHost
                                                                                                remotePort:remotePort
                                                                                                 boundPort:(uint16_t)boundPort
                                                                                                targetHost:localHost
                                                                                                targetPort:localPort
                                                                                               workerQueue:self.worker.queue
                                                                                              closeHandler:^{
        [weakSelf clearCurrentTask];
        closeHandler();
    }
                                                                                                    client:self];
    [self.taskLock lock];
    self.currentTask = runtime;
    [self.taskLock unlock];

    dispatch_async(self.worker.queue, ^{
        [runtime start];
    });

    [self emitLogLevel:SSHKitLogLevelInfo
                 phase:@"tunnel"
               message:@"SSH remote forward started."
              metadata:@{@"remoteHost": remoteHost,
                         @"boundPort": [NSString stringWithFormat:@"%d", boundPort]}];
    return [[SSHKitPortForward alloc] initWithBoundHost:remoteHost boundPort:(uint16_t)boundPort closeBlock:^(SSHKitCompletion completion) {
        [runtime closeWithCompletion:completion];
    }];
}

#pragma clang diagnostic pop

- (void)cancelCurrentTask {
    SSHCoreSessionState workerState = self.worker.state;
    [self.taskLock lock];
    id taskObject = self.currentTask;
    ssh_session session = self.session;
    BOOL shouldShutdownSocket = taskObject != nil || [self.worker isActiveJobState:workerState];
    if (taskObject || session != NULL) {
        self.taskCancelled = YES;
    }
    [self.taskLock unlock];

    if ([taskObject respondsToSelector:@selector(closeWithCompletion:)]) {
        void (*closeMessage)(id, SEL, SSHKitCompletion) = (void *)objc_msgSend;
        closeMessage(taskObject, @selector(closeWithCompletion:), ^(NSError *error) {
            (void)error;
        });
    }
    if (shouldShutdownSocket) {
        [self.worker.socketHandle shutdownNow];
    }
}

- (void)cancelCurrentTaskAndWaitUntilExit {
    [self cancelCurrentTask];
}

- (void)closeSession {
    [self emitLogLevel:SSHKitLogLevelInfo phase:@"close" message:@"SSH session close started." metadata:@{}];
    [self.taskLock lock];
    ssh_session session = self.session;
    self.session = NULL;
    self.currentTask = nil;
    self.taskCancelled = NO;
    [self.taskLock unlock];

    if (session != NULL) {
        ssh_disconnect(session);
        ssh_free(session);
    }
    [self closeWorkerSocketHandle];
    [self emitLogLevel:SSHKitLogLevelInfo phase:@"close" message:@"SSH session close finished." metadata:@{}];
}

- (BOOL)connectLibSSHSessionWithError:(NSError **)error {
    if (![self connectLibSSHSessionWithoutAuthenticationWithError:error]) {
        return NO;
    }

    [self.taskLock lock];
    ssh_session session = self.session;
    [self.taskLock unlock];
    [self emitLogLevel:SSHKitLogLevelInfo phase:@"auth" message:@"SSH authentication started." metadata:@{}];
    if (![self authenticateLibSSHSession:session error:error]) {
        [self emitLogLevel:SSHKitLogLevelError phase:@"auth" message:@"SSH authentication failed." metadata:@{}];
        [self clearLibSSHSession:session];
        return NO;
    }

    [self emitLogLevel:SSHKitLogLevelInfo phase:@"auth" message:@"SSH authentication succeeded." metadata:@{}];
    return YES;
}

- (BOOL)connectLibSSHSessionWithoutAuthenticationWithError:(NSError **)error {
    [self emitLogLevel:SSHKitLogLevelInfo phase:@"connect" message:@"SSH connect started." metadata:@{}];
    if ([self isTaskCancelled]) {
        if (error) {
            *error = SSHKitMakeError(SSHKitErrorCodeCancelled, @"SSH connection was cancelled before connect.");
        }
        [self emitLogLevel:SSHKitLogLevelWarning phase:@"connect" message:@"SSH connect cancelled before socket open." metadata:@{}];
        return NO;
    }

    ssh_session session = ssh_new();
    if (session == NULL) {
        if (error) {
            *error = SSHKitMakeError(SSHKitErrorCodeUnavailable, @"Unable to allocate libssh session.");
        }
        return NO;
    }

    if (![self configureLibSSHSession:session error:error]) {
        ssh_free(session);
        return NO;
    }

    if (self.configuration.proxyRouteKind != SSHKitProxyRouteKindProxyJump) {
        int fileDescriptor = [self openSocketWithError:error];
        if (fileDescriptor < 0) {
            ssh_free(session);
            return NO;
        }

        socket_t sshFileDescriptor = fileDescriptor;
        if (ssh_options_set(session, SSH_OPTIONS_FD, &sshFileDescriptor) != SSH_OK) {
            if (error) {
                *error = [self libSSHErrorWithSession:session code:SSHKitErrorCodeConnectionFailed fallback:@"Unable to attach socket to libssh session."];
            }
            ssh_free(session);
            [self closeWorkerSocketHandle];
            return NO;
        }
    }

    [self.taskLock lock];
    self.session = session;
    BOOL wasCancelledBeforeConnect = self.taskCancelled;
    [self.taskLock unlock];
    if (wasCancelledBeforeConnect) {
        [self clearLibSSHSession:session];
        if (error) {
            *error = SSHKitMakeError(SSHKitErrorCodeCancelled, @"SSH connection was cancelled before connect.");
        }
        return NO;
    }

    if (ssh_connect(session) != SSH_OK) {
        if (error) {
            if ([self isTaskCancelled]) {
                *error = SSHKitMakeError(SSHKitErrorCodeCancelled, @"SSH connection was cancelled.");
            } else {
                *error = [self libSSHErrorWithSession:session code:SSHKitErrorCodeConnectionFailed fallback:[self connectFailureFallbackMessage]];
            }
        }
        [self emitLogLevel:SSHKitLogLevelError phase:@"connect" message:@"SSH transport connect failed." metadata:@{}];
        [self clearLibSSHSession:session];
        return NO;
    }

    if (![self verifyLibSSHHostKeyForSession:session error:error]) {
        [self clearLibSSHSession:session];
        return NO;
    }

    [self emitLogLevel:SSHKitLogLevelInfo phase:@"connect" message:@"SSH transport connect succeeded." metadata:@{}];
    return YES;
}

- (NSString *)connectFailureFallbackMessage {
    if (self.configuration.proxyRouteKind == SSHKitProxyRouteKindProxyJump) {
        SSHKitConfiguration *jump = self.configuration.proxyJumpConfiguration;
        return [NSString stringWithFormat:@"ProxyJump route failed at %@:%hu while connecting to %@:%hu.", jump.host ?: @"<missing-hop>", jump.port, self.configuration.host, self.configuration.port];
    }
    if (self.configuration.proxyRouteKind == SSHKitProxyRouteKindSOCKS5 ||
        self.configuration.proxyRouteKind == SSHKitProxyRouteKindHTTPConnect) {
        return [NSString stringWithFormat:@"Proxy route failed at %@:%hu while connecting to %@:%hu.", self.configuration.proxyHost ?: @"<missing-proxy>", self.configuration.proxyPort, self.configuration.host, self.configuration.port];
    }
    return @"SSH connect failed.";
}

- (BOOL)configureLibSSHSession:(ssh_session)session error:(NSError **)error {
    int port = self.configuration.port;
    long timeout = (long)ceil(self.configuration.timeout);
    const char *host = self.configuration.host.UTF8String;
    const char *username = self.configuration.username.UTF8String;

    if (ssh_options_set(session, SSH_OPTIONS_HOST, host) != SSH_OK ||
        ssh_options_set(session, SSH_OPTIONS_PORT, &port) != SSH_OK ||
        ssh_options_set(session, SSH_OPTIONS_USER, username) != SSH_OK ||
        ssh_options_set(session, SSH_OPTIONS_TIMEOUT, &timeout) != SSH_OK) {
        if (error) {
            *error = [self libSSHErrorWithSession:session code:SSHKitErrorCodeConnectionFailed fallback:@"Unable to configure libssh session."];
        }
        return NO;
    }

    NSString *failedAlgorithmField = nil;
    if (!SSHCoreApplyAlgorithmProfile(session, self.configuration, &failedAlgorithmField)) {
        if (error) {
            NSString *fallback = failedAlgorithmField.length > 0
                                     ? [NSString stringWithFormat:@"Unsupported SSH algorithm profile value for %@.", failedAlgorithmField]
                                     : @"Unable to configure SSH algorithm profile.";
            *error = [self libSSHErrorWithSession:session code:SSHKitErrorCodeConnectionFailed fallback:fallback];
        }
        return NO;
    }

    if (self.configuration.hostKeyPolicyKind == SSHKitHostKeyPolicyKindKnownHostsFile) {
        if (self.configuration.knownHostsPath.length == 0) {
            if (error) {
                *error = SSHKitMakeError(SSHKitErrorCodeHostKeyVerificationFailed, @"Known hosts policy requires a known hosts file path.");
            }
            return NO;
        }

        const char *knownHostsPath = self.configuration.knownHostsPath.UTF8String;
        if (ssh_options_set(session, SSH_OPTIONS_KNOWNHOSTS, knownHostsPath) != SSH_OK) {
            if (error) {
                *error = [self libSSHErrorWithSession:session code:SSHKitErrorCodeHostKeyVerificationFailed fallback:@"Unable to configure known hosts file."];
            }
            return NO;
        }
    }

    if (self.configuration.authenticationKind == SSHKitAuthenticationKindAgent && self.configuration.identityAgentPath.length > 0) {
        if (ssh_options_set(session, SSH_OPTIONS_IDENTITY_AGENT, self.configuration.identityAgentPath.UTF8String) != SSH_OK) {
            if (error) {
                *error = [self libSSHErrorWithSession:session code:SSHKitErrorCodeAuthenticationFailed fallback:@"Unable to configure SSH agent socket."];
            }
            return NO;
        }
    }

    if (self.configuration.proxyRouteKind == SSHKitProxyRouteKindProxyJump) {
        if (![self configureProxyJumpForSession:session error:error]) {
            return NO;
        }
    }

    return YES;
}

- (BOOL)configureProxyJumpForSession:(ssh_session)session error:(NSError **)error {
    SSHKitConfiguration *jumpConfiguration = self.configuration.proxyJumpConfiguration;
    if (jumpConfiguration == nil) {
        if (error) {
            *error = SSHKitMakeError(SSHKitErrorCodeConnectionFailed, @"ProxyJump route requires a jump host configuration.");
        }
        return NO;
    }
    if (jumpConfiguration.authenticationKind == SSHKitAuthenticationKindKeyboardInteractive) {
        if (error) {
            *error = SSHKitMakeError(SSHKitErrorCodeAuthenticationFailed, [NSString stringWithFormat:@"ProxyJump route does not support keyboard-interactive authentication for jump host %@:%hu.", jumpConfiguration.host, jumpConfiguration.port]);
        }
        return NO;
    }

    NSString *jumpRoute = [NSString stringWithFormat:@"%@@%@:%hu", jumpConfiguration.username, jumpConfiguration.host, jumpConfiguration.port];
    if (ssh_options_set(session, SSH_OPTIONS_PROXYJUMP, jumpRoute.UTF8String) != SSH_OK) {
        if (error) {
            *error = [self libSSHErrorWithSession:session code:SSHKitErrorCodeConnectionFailed fallback:@"Unable to configure ProxyJump route."];
        }
        return NO;
    }

    struct ssh_jump_callbacks_struct *callbacks = calloc(1, sizeof(struct ssh_jump_callbacks_struct));
    if (callbacks == NULL) {
        if (error) {
            *error = SSHKitMakeError(SSHKitErrorCodeUnavailable, @"Unable to allocate ProxyJump callbacks.");
        }
        return NO;
    }

    callbacks->userdata = (__bridge void *)jumpConfiguration;
    callbacks->before_connection = SSHCoreProxyJumpBeforeConnection;
    callbacks->verify_knownhost = SSHCoreProxyJumpVerifyKnownHost;
    callbacks->authenticate = SSHCoreProxyJumpAuthenticate;

    if (ssh_options_set(session, SSH_OPTIONS_PROXYJUMP_CB_LIST_APPEND, callbacks) != SSH_OK) {
        free(callbacks);
        if (error) {
            *error = [self libSSHErrorWithSession:session code:SSHKitErrorCodeConnectionFailed fallback:@"Unable to configure ProxyJump callbacks."];
        }
        return NO;
    }

    [self.proxyJumpCallbackPointers addObject:[NSValue valueWithPointer:callbacks]];
    self.proxyJumpCallbackConfigurations = @[jumpConfiguration];
    return YES;
}

- (int)openLocalForwardListenerAtHost:(NSString *)host port:(uint16_t)port boundPort:(uint16_t *)boundPort error:(NSError **)error {
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_flags = AI_PASSIVE;

    NSString *portString = [NSString stringWithFormat:@"%hu", port];
    struct addrinfo *addresses = NULL;
    int result = getaddrinfo(host.UTF8String, portString.UTF8String, &hints, &addresses);
    if (result != 0) {
        if (error) {
            *error = SSHKitMakeError(SSHKitErrorCodeConnectionFailed, [NSString stringWithFormat:@"Unable to resolve local forward bind host: %s", gai_strerror(result)]);
        }
        return -1;
    }

    NSError *lastError = nil;
    for (struct addrinfo *address = addresses; address != NULL; address = address->ai_next) {
        int fileDescriptor = socket(address->ai_family, address->ai_socktype, address->ai_protocol);
        if (fileDescriptor < 0) {
            lastError = SSHKitMakeError(SSHKitErrorCodeConnectionFailed, [NSString stringWithFormat:@"Unable to create local forward listener: %s", strerror(errno)]);
            continue;
        }

        int reuse = 1;
        setsockopt(fileDescriptor, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
        if (bind(fileDescriptor, address->ai_addr, address->ai_addrlen) != 0) {
            lastError = SSHKitMakeError(SSHKitErrorCodeConnectionFailed, [NSString stringWithFormat:@"Unable to bind local forward listener: %s", strerror(errno)]);
            close(fileDescriptor);
            continue;
        }
        if (listen(fileDescriptor, 16) != 0) {
            lastError = SSHKitMakeError(SSHKitErrorCodeConnectionFailed, [NSString stringWithFormat:@"Unable to listen for local forward: %s", strerror(errno)]);
            close(fileDescriptor);
            continue;
        }

        *boundPort = [self boundPortForSocket:fileDescriptor fallback:port];
        freeaddrinfo(addresses);
        return fileDescriptor;
    }

    freeaddrinfo(addresses);
    if (error) {
        *error = lastError ?: SSHKitMakeError(SSHKitErrorCodeConnectionFailed, @"Unable to start local forward listener.");
    }
    return -1;
}

- (uint16_t)boundPortForSocket:(int)socket fallback:(uint16_t)fallback {
    struct sockaddr_storage address;
    socklen_t addressLength = sizeof(address);
    if (getsockname(socket, (struct sockaddr *)&address, &addressLength) != 0) {
        return fallback;
    }
    if (address.ss_family == AF_INET) {
        return ntohs(((struct sockaddr_in *)&address)->sin_port);
    }
    if (address.ss_family == AF_INET6) {
        return ntohs(((struct sockaddr_in6 *)&address)->sin6_port);
    }
    return fallback;
}

- (int)openSocketWithError:(NSError **)error {
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    NSString *socketHost = self.configuration.host;
    uint16_t socketPort = self.configuration.port;
    if (self.configuration.proxyRouteKind == SSHKitProxyRouteKindSOCKS5 ||
        self.configuration.proxyRouteKind == SSHKitProxyRouteKindHTTPConnect) {
        if (self.configuration.proxyHost.length == 0 || self.configuration.proxyPort == 0) {
            if (error) {
                *error = SSHKitMakeError(SSHKitErrorCodeConnectionFailed, @"Proxy route requires a proxy host and port.");
            }
            return -1;
        }
        socketHost = self.configuration.proxyHost;
        socketPort = self.configuration.proxyPort;
    }

    NSString *port = [NSString stringWithFormat:@"%hu", socketPort];
    struct addrinfo *addresses = NULL;
    int result = getaddrinfo(socketHost.UTF8String, port.UTF8String, &hints, &addresses);
    if (result != 0) {
        if (error) {
            *error = SSHKitMakeError(SSHKitErrorCodeConnectionFailed, [NSString stringWithFormat:@"Unable to resolve SSH route host: %s", gai_strerror(result)]);
        }
        return -1;
    }

    NSError *lastError = nil;
    for (struct addrinfo *address = addresses; address != NULL; address = address->ai_next) {
        int fileDescriptor = socket(address->ai_family, address->ai_socktype, address->ai_protocol);
        if (fileDescriptor < 0) {
            lastError = SSHKitMakeError(SSHKitErrorCodeConnectionFailed, [NSString stringWithFormat:@"Unable to create SSH socket: %s", strerror(errno)]);
            continue;
        }

        self.worker.socketHandle = [[SSHCoreSocketHandle alloc] initWithFileDescriptor:fileDescriptor];
        if ([self connectSocket:fileDescriptor address:address error:&lastError] &&
            [self completeProxyRouteOnSocket:fileDescriptor error:&lastError]) {
            freeaddrinfo(addresses);
            return fileDescriptor;
        }

        [self closeWorkerSocketHandle];
    }

    freeaddrinfo(addresses);
    if (error) {
        *error = lastError ?: SSHKitMakeError(SSHKitErrorCodeConnectionFailed, @"Unable to connect SSH socket.");
    }
    return -1;
}

- (BOOL)completeProxyRouteOnSocket:(int)fileDescriptor error:(NSError **)error {
    switch (self.configuration.proxyRouteKind) {
        case SSHKitProxyRouteKindNone:
        case SSHKitProxyRouteKindProxyJump:
            return YES;
        case SSHKitProxyRouteKindSOCKS5:
            return [self completeSOCKS5ProxyRouteOnSocket:fileDescriptor error:error];
        case SSHKitProxyRouteKindHTTPConnect:
            return [self completeHTTPConnectProxyRouteOnSocket:fileDescriptor error:error];
    }
}

- (BOOL)connectSocket:(int)fileDescriptor address:(struct addrinfo *)address error:(NSError **)error {
    int originalFlags = fcntl(fileDescriptor, F_GETFL, 0);
    if (originalFlags < 0 || fcntl(fileDescriptor, F_SETFL, originalFlags | O_NONBLOCK) != 0) {
        if (error) {
            *error = SSHKitMakeError(SSHKitErrorCodeConnectionFailed, [NSString stringWithFormat:@"Unable to configure SSH socket: %s", strerror(errno)]);
        }
        return NO;
    }

    int connectResult = connect(fileDescriptor, address->ai_addr, address->ai_addrlen);
    if (connectResult == 0) {
        fcntl(fileDescriptor, F_SETFL, originalFlags);
        return YES;
    }

    if (errno != EINPROGRESS) {
        if (error) {
            *error = SSHKitMakeError(SSHKitErrorCodeConnectionFailed, [NSString stringWithFormat:@"SSH socket connect failed: %s", strerror(errno)]);
        }
        return NO;
    }

    fd_set writeSet;
    FD_ZERO(&writeSet);
    FD_SET(fileDescriptor, &writeSet);

    NSTimeInterval timeoutInterval = self.configuration.timeout;
    struct timeval timeout;
    timeout.tv_sec = (long)timeoutInterval;
    timeout.tv_usec = (int)((timeoutInterval - floor(timeoutInterval)) * 1000000);

    int selectResult = select(fileDescriptor + 1, NULL, &writeSet, NULL, &timeout);
    if (selectResult <= 0) {
        if (error) {
            *error = [self isTaskCancelled]
                ? SSHKitMakeError(SSHKitErrorCodeCancelled, @"SSH socket connect was cancelled.")
                : SSHKitMakeError(SSHKitErrorCodeConnectionFailed, @"SSH socket connect timed out.");
        }
        return NO;
    }

    int socketError = 0;
    socklen_t socketErrorLength = sizeof(socketError);
    if (getsockopt(fileDescriptor, SOL_SOCKET, SO_ERROR, &socketError, &socketErrorLength) != 0 || socketError != 0) {
        if (error) {
            int reportedError = socketError != 0 ? socketError : errno;
            *error = SSHKitMakeError(SSHKitErrorCodeConnectionFailed, [NSString stringWithFormat:@"SSH socket connect failed: %s", strerror(reportedError)]);
        }
        return NO;
    }

    fcntl(fileDescriptor, F_SETFL, originalFlags);
    return YES;
}

- (BOOL)completeSOCKS5ProxyRouteOnSocket:(int)fileDescriptor error:(NSError **)error {
    BOOL wantsPassword = self.configuration.proxyUsername.length > 0 || self.configuration.proxyPassword.length > 0;
    uint8_t greeting[4] = {0x05, wantsPassword ? 0x02 : 0x01, 0x00, 0x02};
    if (![self writeBytes:(const char *)greeting length:(wantsPassword ? 4 : 3) toProxySocket:fileDescriptor error:error]) {
        return NO;
    }

    uint8_t selection[2];
    if (![self readBytes:selection length:sizeof(selection) fromProxySocket:fileDescriptor error:error] || selection[0] != 0x05) {
        if (error) {
            *error = SSHKitMakeError(SSHKitErrorCodeConnectionFailed, @"SOCKS5 proxy route failed during method negotiation.");
        }
        return NO;
    }
    if (wantsPassword && selection[1] == 0x02) {
        if (![self authenticateSOCKS5ProxyRouteOnSocket:fileDescriptor error:error]) {
            return NO;
        }
    } else if ((!wantsPassword && selection[1] != 0x00) || (wantsPassword && selection[1] != 0x02)) {
        if (error) {
            *error = SSHKitMakeError(SSHKitErrorCodeConnectionFailed, [NSString stringWithFormat:@"SOCKS5 proxy route rejected authentication method at %@:%hu.", self.configuration.proxyHost, self.configuration.proxyPort]);
        }
        return NO;
    }

    NSData *hostData = [self.configuration.host dataUsingEncoding:NSUTF8StringEncoding];
    if (hostData.length == 0 || hostData.length > UINT8_MAX) {
        if (error) {
            *error = SSHKitMakeError(SSHKitErrorCodeConnectionFailed, @"SOCKS5 proxy route target host must be 1...255 UTF-8 bytes.");
        }
        return NO;
    }

    NSMutableData *request = [[NSMutableData alloc] initWithCapacity:7 + hostData.length];
    uint8_t prefix[5] = {0x05, 0x01, 0x00, 0x03, (uint8_t)hostData.length};
    [request appendBytes:prefix length:sizeof(prefix)];
    [request appendData:hostData];
    uint8_t port[2] = {(uint8_t)(self.configuration.port >> 8), (uint8_t)(self.configuration.port & 0x00FF)};
    [request appendBytes:port length:sizeof(port)];
    if (![self writeBytes:request.bytes length:request.length toProxySocket:fileDescriptor error:error]) {
        return NO;
    }

    uint8_t replyHeader[4];
    if (![self readBytes:replyHeader length:sizeof(replyHeader) fromProxySocket:fileDescriptor error:error] || replyHeader[0] != 0x05) {
        if (error) {
            *error = SSHKitMakeError(SSHKitErrorCodeConnectionFailed, @"SOCKS5 proxy route failed while reading CONNECT reply.");
        }
        return NO;
    }
    if (replyHeader[1] != 0x00) {
        if (error) {
            *error = SSHKitMakeError(SSHKitErrorCodeConnectionFailed, [NSString stringWithFormat:@"SOCKS5 proxy route failed at %@:%hu with reply %hhu.", self.configuration.proxyHost, self.configuration.proxyPort, replyHeader[1]]);
        }
        return NO;
    }

    NSUInteger addressLength = 0;
    if (replyHeader[3] == 0x01) {
        addressLength = 4;
    } else if (replyHeader[3] == 0x04) {
        addressLength = 16;
    } else if (replyHeader[3] == 0x03) {
        uint8_t domainLength = 0;
        if (![self readBytes:&domainLength length:1 fromProxySocket:fileDescriptor error:error]) {
            return NO;
        }
        addressLength = domainLength;
    } else {
        if (error) {
            *error = SSHKitMakeError(SSHKitErrorCodeConnectionFailed, @"SOCKS5 proxy route returned an unsupported address type.");
        }
        return NO;
    }

    NSMutableData *ignored = [NSMutableData dataWithLength:addressLength + 2];
    return [self readBytes:ignored.mutableBytes length:ignored.length fromProxySocket:fileDescriptor error:error];
}

- (BOOL)authenticateSOCKS5ProxyRouteOnSocket:(int)fileDescriptor error:(NSError **)error {
    NSData *username = [(self.configuration.proxyUsername ?: @"") dataUsingEncoding:NSUTF8StringEncoding];
    NSData *password = [(self.configuration.proxyPassword ?: @"") dataUsingEncoding:NSUTF8StringEncoding];
    if (username.length > UINT8_MAX || password.length > UINT8_MAX) {
        if (error) {
            *error = SSHKitMakeError(SSHKitErrorCodeConnectionFailed, @"SOCKS5 proxy route credentials must be at most 255 UTF-8 bytes.");
        }
        return NO;
    }

    NSMutableData *request = [[NSMutableData alloc] initWithCapacity:3 + username.length + password.length];
    uint8_t version = 0x01;
    uint8_t usernameLength = (uint8_t)username.length;
    uint8_t passwordLength = (uint8_t)password.length;
    [request appendBytes:&version length:1];
    [request appendBytes:&usernameLength length:1];
    [request appendData:username];
    [request appendBytes:&passwordLength length:1];
    [request appendData:password];
    if (![self writeBytes:request.bytes length:request.length toProxySocket:fileDescriptor error:error]) {
        return NO;
    }

    uint8_t response[2];
    if (![self readBytes:response length:sizeof(response) fromProxySocket:fileDescriptor error:error] || response[0] != 0x01 || response[1] != 0x00) {
        if (error) {
            *error = SSHKitMakeError(SSHKitErrorCodeAuthenticationFailed, [NSString stringWithFormat:@"SOCKS5 proxy route authentication failed at %@:%hu.", self.configuration.proxyHost, self.configuration.proxyPort]);
        }
        return NO;
    }
    return YES;
}

- (BOOL)completeHTTPConnectProxyRouteOnSocket:(int)fileDescriptor error:(NSError **)error {
    NSString *authority = [NSString stringWithFormat:@"%@:%hu", self.configuration.host, self.configuration.port];
    NSMutableString *request = [NSMutableString stringWithFormat:@"CONNECT %@ HTTP/1.1\r\nHost: %@\r\nProxy-Connection: Keep-Alive\r\n", authority, authority];
    if (self.configuration.proxyUsername.length > 0 || self.configuration.proxyPassword.length > 0) {
        NSString *credentials = [NSString stringWithFormat:@"%@:%@", self.configuration.proxyUsername ?: @"", self.configuration.proxyPassword ?: @""];
        NSString *encodedCredentials = [[credentials dataUsingEncoding:NSUTF8StringEncoding] base64EncodedStringWithOptions:0];
        [request appendFormat:@"Proxy-Authorization: Basic %@\r\n", encodedCredentials];
    }
    [request appendString:@"\r\n"];

    NSData *requestData = [request dataUsingEncoding:NSUTF8StringEncoding];
    if (![self writeBytes:requestData.bytes length:requestData.length toProxySocket:fileDescriptor error:error]) {
        return NO;
    }

    NSMutableData *response = [[NSMutableData alloc] init];
    uint8_t byte = 0;
    while (response.length < 16 * 1024) {
        if (![self readBytes:&byte length:1 fromProxySocket:fileDescriptor error:error]) {
            return NO;
        }
        [response appendBytes:&byte length:1];
        if (response.length >= 4) {
            const uint8_t *bytes = response.bytes;
            NSUInteger length = response.length;
            if (bytes[length - 4] == '\r' && bytes[length - 3] == '\n' && bytes[length - 2] == '\r' && bytes[length - 1] == '\n') {
                NSString *header = [[NSString alloc] initWithData:response encoding:NSUTF8StringEncoding] ?: @"";
                NSArray<NSString *> *lines = [header componentsSeparatedByString:@"\r\n"];
                NSString *statusLine = lines.firstObject ?: @"";
                if ([statusLine containsString:@" 200 "]) {
                    return YES;
                }
                if (error) {
                    *error = SSHKitMakeError(SSHKitErrorCodeConnectionFailed, [NSString stringWithFormat:@"HTTP CONNECT proxy route failed at %@:%hu with status '%@'.", self.configuration.proxyHost, self.configuration.proxyPort, statusLine]);
                }
                return NO;
            }
        }
    }

    if (error) {
        *error = SSHKitMakeError(SSHKitErrorCodeConnectionFailed, @"HTTP CONNECT proxy route response header exceeded 16 KiB.");
    }
    return NO;
}

- (BOOL)readBytes:(void *)buffer length:(NSUInteger)length fromProxySocket:(int)socket error:(NSError **)error {
    uint8_t *cursor = buffer;
    NSUInteger remaining = length;
    while (remaining > 0) {
        ssize_t bytesRead = read(socket, cursor, remaining);
        if (bytesRead < 0 && errno == EINTR) {
            continue;
        }
        if (bytesRead <= 0) {
            if (error) {
                *error = SSHKitMakeError(SSHKitErrorCodeConnectionFailed, [NSString stringWithFormat:@"Proxy route socket read failed: %s", strerror(errno)]);
            }
            return NO;
        }
        cursor += bytesRead;
        remaining -= (NSUInteger)bytesRead;
    }
    return YES;
}

- (BOOL)writeBytes:(const char *)bytes length:(size_t)length toProxySocket:(int)socket error:(NSError **)error {
    size_t offset = 0;
    while (offset < length) {
        ssize_t written = write(socket, bytes + offset, length - offset);
        if (written < 0 && errno == EINTR) {
            continue;
        }
        if (written <= 0) {
            if (error) {
                *error = SSHKitMakeError(SSHKitErrorCodeConnectionFailed, [NSString stringWithFormat:@"Proxy route socket write failed: %s", strerror(errno)]);
            }
            return NO;
        }
        offset += (size_t)written;
    }
    return YES;
}

- (BOOL)verifyLibSSHHostKeyForSession:(ssh_session)session error:(NSError **)error {
    NSString *fingerprint = SSHCoreSHA256FingerprintForSession(session);
    self.hostKeySHA256Fingerprint = fingerprint;
    NSDictionary<NSString *, NSString *> *fingerprintMetadata = fingerprint.length > 0 ? @{@"fingerprint": fingerprint} : @{};
    [self emitLogLevel:SSHKitLogLevelInfo phase:@"trust" message:@"SSH host key verification started." metadata:fingerprintMetadata];
    if (self.configuration.hostKeyPolicyKind == SSHKitHostKeyPolicyKindInsecureAcceptAnyHostKey) {
        [self emitLogLevel:SSHKitLogLevelWarning
                     phase:@"trust"
                   message:@"SSH host key accepted by insecure policy."
                  metadata:fingerprint.length > 0
                               ? @{@"policy": @"insecureAcceptAnyHostKey", @"fingerprint": fingerprint}
                               : @{@"policy": @"insecureAcceptAnyHostKey"}];
        return YES;
    }

    if (self.configuration.hostKeyPolicyKind == SSHKitHostKeyPolicyKindPinnedFingerprint) {
        if (fingerprint.length == 0 || !SSHCoreFingerprintMatches(fingerprint, self.configuration.pinnedHostKeySHA256Fingerprint)) {
            if (error) {
                *error = SSHKitMakeError(SSHKitErrorCodeHostKeyVerificationFailed, @"Pinned host key fingerprint did not match the server host key.");
            }
            [self emitLogLevel:SSHKitLogLevelError
                         phase:@"trust"
                       message:@"SSH pinned host key verification failed."
                      metadata:fingerprint.length > 0 ? @{@"fingerprint": fingerprint} : @{}];
            return NO;
        }
        [self emitLogLevel:SSHKitLogLevelInfo
                     phase:@"trust"
                   message:@"SSH pinned host key verification succeeded."
                  metadata:@{@"fingerprint": fingerprint}];
        return YES;
    }

    if (self.configuration.hostKeyPolicyKind == SSHKitHostKeyPolicyKindTrustedFingerprint) {
        if (self.configuration.hostKeyTrustStoreError.length > 0) {
            if (error) {
                *error = SSHKitMakeError(SSHKitErrorCodeHostKeyVerificationFailed, [NSString stringWithFormat:@"Host trust store failed to load trusted fingerprint: %@.", self.configuration.hostKeyTrustStoreError]);
            }
            return NO;
        }
        if (self.configuration.trustedHostKeySHA256Fingerprint.length == 0) {
            if (error) {
                *error = SSHKitMakeError(SSHKitErrorCodeHostKeyVerificationFailed, @"Host trust store has no trusted fingerprint for this host and port.");
            }
            return NO;
        }
        if (fingerprint.length == 0 || !SSHCoreFingerprintMatches(fingerprint, self.configuration.trustedHostKeySHA256Fingerprint)) {
            if (error) {
                *error = SSHKitMakeError(SSHKitErrorCodeHostKeyVerificationFailed, @"Trusted host key fingerprint did not match the server host key.");
            }
            [self emitLogLevel:SSHKitLogLevelError
                         phase:@"trust"
                       message:@"SSH trust-store host key verification failed."
                      metadata:fingerprint.length > 0 ? @{@"fingerprint": fingerprint} : @{}];
            return NO;
        }
        [self emitLogLevel:SSHKitLogLevelInfo
                     phase:@"trust"
                   message:@"SSH trust-store host key verification succeeded."
                  metadata:@{@"fingerprint": fingerprint}];
        return YES;
    }

    enum ssh_known_hosts_e state = ssh_session_is_known_server(session);
    if (state == SSH_KNOWN_HOSTS_OK) {
        [self emitLogLevel:SSHKitLogLevelInfo
                     phase:@"trust"
                   message:@"SSH host key verification succeeded."
                  metadata:fingerprint.length > 0
                               ? @{@"knownHostsState": [NSString stringWithFormat:@"%d", state], @"fingerprint": fingerprint}
                               : @{@"knownHostsState": [NSString stringWithFormat:@"%d", state]}];
        return YES;
    }

    if (error) {
        NSString *message = [NSString stringWithFormat:@"Host key verification failed with libssh known-hosts state %d.", state];
        *error = SSHKitMakeError(SSHKitErrorCodeHostKeyVerificationFailed, message);
    }
    [self emitLogLevel:SSHKitLogLevelError
                 phase:@"trust"
               message:@"SSH host key verification failed."
              metadata:@{@"knownHostsState": [NSString stringWithFormat:@"%d", state]}];
    return NO;
}

- (BOOL)authenticateLibSSHSession:(ssh_session)session error:(NSError **)error {
    [self emitLogLevel:SSHKitLogLevelDebug
                 phase:@"auth"
               message:@"SSH authentication method selected."
              metadata:@{@"method": SSHCoreAuthenticationName(self.configuration.authenticationKind)}];
    int rc = SSH_AUTH_DENIED;
    switch (self.configuration.authenticationKind) {
        case SSHKitAuthenticationKindPassword:
            if (self.configuration.password.length == 0) {
                if (error) {
                    *error = SSHKitMakeError(SSHKitErrorCodeAuthenticationFailed, @"Password authentication requires a password.");
                }
                return NO;
            }
            rc = ssh_userauth_password(session, NULL, self.configuration.password.UTF8String);
            break;
        case SSHKitAuthenticationKindPrivateKeyFile: {
            if (self.configuration.privateKeyPath.length == 0) {
                if (error) {
                    *error = SSHKitMakeError(SSHKitErrorCodeAuthenticationFailed, @"Private key authentication requires a key file path.");
                }
                return NO;
            }
            ssh_key privateKey = NULL;
            const char *passphrase = self.configuration.privateKeyPassphrase.length > 0 ? self.configuration.privateKeyPassphrase.UTF8String : NULL;
            if (ssh_pki_import_privkey_file(self.configuration.privateKeyPath.UTF8String, passphrase, NULL, NULL, &privateKey) != SSH_OK) {
                if (error) {
                    *error = [self libSSHErrorWithSession:session code:SSHKitErrorCodeAuthenticationFailed fallback:@"Unable to import private key."];
                }
                return NO;
            }
            rc = ssh_userauth_publickey(session, NULL, privateKey);
            ssh_key_free(privateKey);
            break;
        }
        case SSHKitAuthenticationKindKeyboardInteractive:
            return [self authenticateKeyboardInteractiveSession:session error:error];
        case SSHKitAuthenticationKindAgent:
            rc = ssh_userauth_agent(session, NULL);
            break;
    }

    if (rc == SSH_AUTH_SUCCESS) {
        return YES;
    }

    if (error) {
        *error = [self libSSHErrorWithSession:session code:SSHKitErrorCodeAuthenticationFailed fallback:@"SSH authentication failed."];
    }
    return NO;
}

- (BOOL)authenticateKeyboardInteractiveSession:(ssh_session)session error:(NSError **)error {
    SSHKitKeyboardInteractiveResponder responder = self.configuration.keyboardInteractiveResponder;
    if (responder == nil) {
        if (error) {
            *error = SSHKitMakeError(SSHKitErrorCodeAuthenticationFailed, @"Keyboard-interactive authentication requires a response provider.");
        }
        return NO;
    }

    int rc = ssh_userauth_kbdint(session, NULL, NULL);
    while (rc == SSH_AUTH_INFO) {
        NSString *name = SSHCoreStringFromCString(ssh_userauth_kbdint_getname(session));
        NSString *instruction = SSHCoreStringFromCString(ssh_userauth_kbdint_getinstruction(session));
        int promptCount = ssh_userauth_kbdint_getnprompts(session);
        if (promptCount < 0) {
            if (error) {
                *error = [self libSSHErrorWithSession:session code:SSHKitErrorCodeAuthenticationFailed fallback:@"Unable to read keyboard-interactive prompts."];
            }
            return NO;
        }

        NSMutableArray<SSHKitKeyboardInteractivePrompt *> *prompts = [[NSMutableArray alloc] initWithCapacity:(NSUInteger)promptCount];
        for (int index = 0; index < promptCount; index++) {
            char echo = 0;
            const char *prompt = ssh_userauth_kbdint_getprompt(session, (unsigned int)index, &echo);
            [prompts addObject:[[SSHKitKeyboardInteractivePrompt alloc] initWithPrompt:SSHCoreStringFromCString(prompt) echo:echo != 0]];
        }

        NSArray<NSString *> *answers = responder(name, instruction, prompts);
        if (answers.count != prompts.count) {
            if (error) {
                *error = SSHKitMakeError(SSHKitErrorCodeAuthenticationFailed, @"Keyboard-interactive response count does not match prompt count.");
            }
            return NO;
        }

        for (NSUInteger index = 0; index < answers.count; index++) {
            if (ssh_userauth_kbdint_setanswer(session, (unsigned int)index, answers[index].UTF8String) != SSH_OK) {
                if (error) {
                    *error = [self libSSHErrorWithSession:session code:SSHKitErrorCodeAuthenticationFailed fallback:@"Unable to send keyboard-interactive answer."];
                }
                return NO;
            }
        }

        rc = ssh_userauth_kbdint(session, NULL, NULL);
    }

    if (rc == SSH_AUTH_SUCCESS) {
        return YES;
    }

    if (error) {
        NSString *fallback = rc == SSH_AUTH_PARTIAL ? @"Keyboard-interactive authentication requires additional methods." : @"Keyboard-interactive authentication failed.";
        *error = [self libSSHErrorWithSession:session code:SSHKitErrorCodeAuthenticationFailed fallback:fallback];
    }
    return NO;
}

- (nullable SSHKitCommandResult *)executeLibSSHCommand:(NSString *)command requestPTY:(BOOL)requestPTY error:(NSError **)error {
    [self emitLogLevel:SSHKitLogLevelInfo
                 phase:requestPTY ? @"shell" : @"command"
               message:requestPTY ? @"SSH PTY command started." : @"SSH command started."
              metadata:@{}];
    ssh_channel channel = [self openSessionChannelWithError:error];
    if (channel == NULL) {
        return nil;
    }

    if (requestPTY && ssh_channel_request_pty(channel) != SSH_OK) {
        if (error) {
            *error = [self libSSHErrorWithCode:SSHKitErrorCodeConnectionFailed fallback:@"Unable to request PTY."];
        }
        ssh_channel_close(channel);
        ssh_channel_free(channel);
        return nil;
    }

    if (ssh_channel_request_exec(channel, command.UTF8String) != SSH_OK) {
        if (error) {
            *error = [self libSSHErrorWithCode:SSHKitErrorCodeCommandFailed fallback:@"Unable to execute SSH command."];
        }
        ssh_channel_close(channel);
        ssh_channel_free(channel);
        return nil;
    }

    NSMutableData *standardOutput = [[NSMutableData alloc] init];
    NSMutableData *standardError = [[NSMutableData alloc] init];
    if (![self readLibSSHChannel:channel standardOutput:standardOutput standardError:standardError error:error]) {
        ssh_channel_close(channel);
        ssh_channel_free(channel);
        return nil;
    }

    uint32_t exitStatus = 0;
    char *rawExitSignal = NULL;
    int exitState = ssh_channel_get_exit_state(channel, &exitStatus, &rawExitSignal, NULL);
    if (exitState != SSH_OK) {
        free(rawExitSignal);
        if (error) {
            *error = SSHKitMakeError(SSHKitErrorCodeCommandFailed, @"SSH command finished without an exit status.");
        }
        ssh_channel_send_eof(channel);
        ssh_channel_close(channel);
        ssh_channel_free(channel);
        return nil;
    }
    NSString *exitSignal = rawExitSignal != NULL ? [NSString stringWithUTF8String:rawExitSignal] : nil;
    free(rawExitSignal);

    ssh_channel_send_eof(channel);
    ssh_channel_close(channel);
    ssh_channel_free(channel);
    NSMutableDictionary<NSString *, NSString *> *metadata = [@{@"exitStatus": [NSString stringWithFormat:@"%d", (int32_t)exitStatus]} mutableCopy];
    if (exitSignal.length > 0) {
        metadata[@"exitSignal"] = exitSignal;
    }
    [self emitLogLevel:SSHKitLogLevelInfo
                 phase:requestPTY ? @"shell" : @"command"
               message:requestPTY ? @"SSH PTY command finished." : @"SSH command finished."
              metadata:metadata];
    return [[SSHKitCommandResult alloc] initWithStandardOutput:standardOutput
                                                standardError:standardError
                                                   exitStatus:(int32_t)exitStatus
                                                   exitSignal:exitSignal];
}

- (nullable ssh_channel)openSessionChannelWithError:(NSError **)error {
    if (self.session == NULL) {
        if (error) {
            *error = SSHKitMakeError(SSHKitErrorCodeInvalidState, @"SSH session is not connected.");
        }
        return NULL;
    }

    ssh_channel channel = ssh_channel_new(self.session);
    if (channel == NULL) {
        if (error) {
            *error = [self libSSHErrorWithCode:SSHKitErrorCodeConnectionFailed fallback:@"Unable to allocate SSH channel."];
        }
        return NULL;
    }

    if (ssh_channel_open_session(channel) != SSH_OK) {
        if (error) {
            *error = [self libSSHErrorWithCode:SSHKitErrorCodeConnectionFailed fallback:@"Unable to open SSH channel."];
        }
        ssh_channel_free(channel);
        return NULL;
    }

    return channel;
}

- (BOOL)readLibSSHChannel:(ssh_channel)channel
           standardOutput:(NSMutableData *)standardOutput
            standardError:(NSMutableData *)standardError
                    error:(NSError **)error {
    char buffer[32768];
    while (ssh_channel_is_eof(channel) == 0) {
        int stdoutCount = ssh_channel_read_timeout(channel, buffer, sizeof(buffer), 0, 100);
        if (stdoutCount == SSH_ERROR) {
            if (error) {
                *error = [self isTaskCancelled] ? SSHKitMakeError(SSHKitErrorCodeCancelled, @"SSH command was cancelled.") : SSHKitMakeError(SSHKitErrorCodeCommandFailed, @"Failed reading SSH command stdout.");
            }
            return NO;
        }
        if (stdoutCount > 0) {
            [standardOutput appendBytes:buffer length:(NSUInteger)stdoutCount];
        }

        int stderrCount = ssh_channel_read_timeout(channel, buffer, sizeof(buffer), 1, 0);
        if (stderrCount == SSH_ERROR) {
            if (error) {
                *error = [self isTaskCancelled] ? SSHKitMakeError(SSHKitErrorCodeCancelled, @"SSH command was cancelled.") : SSHKitMakeError(SSHKitErrorCodeCommandFailed, @"Failed reading SSH command stderr.");
            }
            return NO;
        }
        if (stderrCount > 0) {
            [standardError appendBytes:buffer length:(NSUInteger)stderrCount];
        }
    }

    for (;;) {
        int stderrCount = ssh_channel_read_timeout(channel, buffer, sizeof(buffer), 1, 0);
        if (stderrCount == SSH_ERROR) {
            if (error) {
                *error = [self isTaskCancelled] ? SSHKitMakeError(SSHKitErrorCodeCancelled, @"SSH command was cancelled.") : SSHKitMakeError(SSHKitErrorCodeCommandFailed, @"Failed draining SSH command stderr.");
            }
            return NO;
        }
        if (stderrCount == 0) {
            return YES;
        }
        [standardError appendBytes:buffer length:(NSUInteger)stderrCount];
    }
}

- (NSError *)libSSHErrorWithCode:(SSHKitErrorCode)code fallback:(NSString *)fallback {
    [self.taskLock lock];
    const char *message = self.session != NULL ? ssh_get_error(self.session) : NULL;
    NSString *errorMessage = message != NULL && strlen(message) > 0 ? [NSString stringWithUTF8String:message] : nil;
    [self.taskLock unlock];

    if (errorMessage.length > 0) {
        return SSHKitMakeError(code, errorMessage);
    }
    return SSHKitMakeError(code, fallback);
}

- (NSError *)libSSHErrorWithSession:(ssh_session)session code:(SSHKitErrorCode)code fallback:(NSString *)fallback {
    const char *message = session != NULL ? ssh_get_error(session) : NULL;
    if (message != NULL && strlen(message) > 0) {
        return SSHKitMakeError(code, [NSString stringWithUTF8String:message]);
    }
    return SSHKitMakeError(code, fallback);
}

- (NSError *)sftpErrorForOperation:(NSString *)operation sftp:(sftp_session)sftp {
    int status = sftp != NULL ? sftp_get_error(sftp) : SSH_ERROR;
    return [self sftpErrorForOperation:operation status:status];
}

- (NSError *)sftpErrorForOperation:(NSString *)operation status:(int)status {
    SSHKitErrorCode code = SSHKitErrorCodeSFTPFailure;
    switch (status) {
        case SSH_FX_NO_SUCH_FILE:
            code = SSHKitErrorCodeSFTPFileNotFound;
            break;
        case SSH_FX_PERMISSION_DENIED:
            code = SSHKitErrorCodeSFTPPermissionDenied;
            break;
        default:
            break;
    }
    NSString *message = [NSString stringWithFormat:@"%@ failed with SFTP status %d.", operation, status];
    return SSHKitMakeError(code, message);
}

- (void)clearLibSSHSession:(ssh_session)session {
    [self.taskLock lock];
    if (self.session == session) {
        self.session = NULL;
    }
    [self.taskLock unlock];

    if (session != NULL) {
        ssh_disconnect(session);
        ssh_free(session);
    }
    [self freeProxyJumpCallbacks];
    [self closeWorkerSocketHandle];
}

- (void)freeProxyJumpCallbacks {
    for (NSValue *value in self.proxyJumpCallbackPointers) {
        free([value pointerValue]);
    }
    [self.proxyJumpCallbackPointers removeAllObjects];
    self.proxyJumpCallbackConfigurations = @[];
}

- (void)closeWorkerSocketHandle {
    SSHCoreSocketHandle *socketHandle = self.worker.socketHandle;
    int fileDescriptor = socketHandle ? [socketHandle takeFileDescriptorForClose] : -1;
    if (fileDescriptor >= 0) {
        close(fileDescriptor);
    }
    self.worker.socketHandle = nil;
}

- (BOOL)isTaskCancelled {
    [self.taskLock lock];
    BOOL cancelled = self.taskCancelled;
    [self.taskLock unlock];
    return cancelled;
}

- (void)clearCurrentTask {
    [self.taskLock lock];
    self.currentTask = nil;
    self.taskCancelled = NO;
    [self.taskLock unlock];
}

- (void)dealloc {
    [self.taskLock lock];
    ssh_session session = self.session;
    self.session = NULL;
    id taskObject = self.currentTask;
    self.currentTask = nil;
    SSHCoreSocketHandle *socketHandle = self.worker.socketHandle;
    self.worker.socketHandle = nil;
    dispatch_queue_t workerQueue = self.worker.queue;
    NSArray<NSValue *> *proxyJumpCallbackPointers = [self.proxyJumpCallbackPointers copy];
    [self.proxyJumpCallbackPointers removeAllObjects];
    self.proxyJumpCallbackConfigurations = @[];
    [self.taskLock unlock];

    if (session == NULL && socketHandle == nil && taskObject == nil && proxyJumpCallbackPointers.count == 0) {
        return;
    }

    dispatch_async(workerQueue, ^{
        if ([taskObject respondsToSelector:@selector(invalidateOnWorkerQueue)]) {
            void (*invalidateMessage)(id, SEL) = (void *)objc_msgSend;
            invalidateMessage(taskObject, @selector(invalidateOnWorkerQueue));
        }

        if (session != NULL) {
            ssh_disconnect(session);
            ssh_free(session);
        }
        for (NSValue *value in proxyJumpCallbackPointers) {
            free([value pointerValue]);
        }

        int fileDescriptor = socketHandle ? [socketHandle takeFileDescriptorForClose] : -1;
        if (fileDescriptor >= 0) {
            close(fileDescriptor);
        }
    });
}

@end
