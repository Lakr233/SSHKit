#import "SSHCoreLibSSHLocalForwardRuntime.h"

#import <CLibSSH/CLibSSH.h>

@class SSHCoreOpenSSHClient;

NS_ASSUME_NONNULL_BEGIN

@interface SSHCoreLibSSHLocalForwardRuntime ()

@property (nonatomic, nullable) ssh_session session;
@property (nonatomic) dispatch_queue_t workerQueue;
@property (nonatomic, copy) NSString *boundHost;
@property (nonatomic) uint16_t boundPort;
@property (nonatomic, copy, nullable) NSString *targetHost;
@property (nonatomic) uint16_t targetPort;
@property (nonatomic, copy, nullable) NSString *socksUsername;
@property (nonatomic, copy, nullable) NSString *socksPassword;
@property (nonatomic, copy, nullable) SSHCoreTunnelCloseHandler closeHandler;
@property (nonatomic, weak, nullable) SSHCoreOpenSSHClient *client;
@property (nonatomic) NSLock *lock;
@property (nonatomic) int listenerSocket;
@property (nonatomic) int activeSocket;
@property (nonatomic) BOOL closed;
@property (nonatomic) BOOL didCallCloseHandler;
@property (nonatomic) NSMutableArray<SSHKitCompletion> *closeCompletions;

// Shared between +Accept and +SOCKS.
- (BOOL)readExactly:(void *)buffer length:(NSUInteger)length fromSocket:(int)socket;
- (BOOL)writeBytes:(const char *)bytes length:(size_t)length toChannel:(ssh_channel)channel;
- (BOOL)writeBytes:(const char *)bytes length:(size_t)length toSocket:(int)socket;
- (NSString *)peerHostForSocket:(int)socket port:(int *)port;
- (void)setActiveSocket:(int)activeSocket;
- (BOOL)isClosed;
- (NSDictionary<NSString *, NSString *> *)diagnosticMetadata;
- (NSDictionary<NSString *, NSString *> *)diagnosticMetadataWithAdditional:(NSDictionary<NSString *, NSString *> *)additional;
- (void)callCloseHandlerIfNeeded;
- (void)completePendingCloseCompletions;

// +SOCKS surface consumed by +Accept's dynamic-forward bridging.
- (BOOL)readSOCKSTargetHost:(NSString *_Nullable *_Nullable)targetHost port:(uint16_t *)targetPort fromClientSocket:(int)clientSocket;
- (void)sendSOCKSReply:(uint8_t)reply toSocket:(int)clientSocket;

@end

NS_ASSUME_NONNULL_END
