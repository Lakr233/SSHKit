#import "SSHCoreOpenSSHClient.h"

#import <CLibSSH/CLibSSH.h>
#import <SSHKitObjC/SSHKitConfiguration.h>
#import <SSHKitObjC/SSHKitConnection.h>
#import <SSHKitObjC/SSHKitError.h>

#import "SSHCoreSessionWorker.h"

NS_ASSUME_NONNULL_BEGIN

@interface SSHCoreOpenSSHClient ()

@property (nonatomic, copy) SSHKitConfiguration *configuration;
@property (nonatomic) SSHCoreSessionWorker *worker;
@property (nonatomic) NSLock *taskLock;
@property (nonatomic, nullable) id currentTask;
@property (nonatomic) BOOL taskCancelled;
@property (nonatomic, nullable) ssh_session session;
@property (nonatomic) NSMutableArray<NSValue *> *proxyJumpCallbackPointers;
@property (nonatomic, copy) NSArray<SSHKitConfiguration *> *proxyJumpCallbackConfigurations;
@property (nonatomic, copy, readwrite, nullable) NSString *hostKeySHA256Fingerprint;

@end

@interface SSHCoreOpenSSHClient (Internal)

- (NSError *)sftpErrorForOperation:(NSString *)operation sftp:(sftp_session)sftp;
- (NSError *)sftpErrorForOperation:(NSString *)operation status:(int)status;
- (void)emitLogLevel:(SSHKitLogLevel)level
               phase:(NSString *)phase
             message:(NSString *)message
            metadata:(NSDictionary<NSString *, NSString *> *)metadata;

- (NSError *)libSSHErrorWithCode:(SSHKitErrorCode)code fallback:(NSString *)fallback;
- (NSError *)libSSHErrorWithSession:(ssh_session)session code:(SSHKitErrorCode)code fallback:(NSString *)fallback;

- (BOOL)isTaskCancelled;
- (void)clearCurrentTask;
- (void)clearLibSSHSession:(ssh_session)session;
- (void)closeWorkerSocketHandle;

@end

NS_ASSUME_NONNULL_END
