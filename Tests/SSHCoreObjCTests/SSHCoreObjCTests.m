#import <XCTest/XCTest.h>

#import <CLibSSH/CLibSSH.h>
#import <SSHKitObjC/SSHKitClient.h>
#import <SSHKitObjC/SSHKitConfiguration.h>
#import <SSHKitObjC/SSHKitError.h>

#import "SSHCoreCancellationToken.h"
#import "SSHCoreOpenSSHClient.h"
#import "SSHCoreSessionWorker.h"
#import "SSHCoreSocketHandle.h"
#import "SSHKitSFTPClient+Private.h"

#include <sys/socket.h>
#include <unistd.h>

@interface SSHCoreObjCTests : XCTestCase
@end

@interface SSHCoreOpenSSHClient (SSHCoreObjCTests)
- (NSError *)sftpErrorForOperation:(NSString *)operation status:(int)status;
@end

@implementation SSHCoreObjCTests

- (void)testCLibSSHLinksAndCreatesSession {
    XCTAssertGreaterThan(LIBSSH_VERSION_INT, 0);
    ssh_session session = ssh_new();
    XCTAssertNotEqual(session, NULL);
    ssh_free(session);
}

- (void)testObjectiveCAuthenticationFacadeAppliesConfigurationFields {
    SSHKitConfiguration *configuration = [[SSHKitConfiguration alloc] initWithHost:@"example.com" username:@"user"];
    configuration.authentication = [SSHKitAuthentication privateKeyFileAtPath:@"/tmp/key" passphrase:@"secret"];

    XCTAssertEqual(configuration.authenticationKind, SSHKitAuthenticationKindPrivateKeyFile);
    XCTAssertEqualObjects(configuration.privateKeyPath, @"/tmp/key");
    XCTAssertEqualObjects(configuration.privateKeyPassphrase, @"secret");
}

- (void)testObjectiveCHostTrustFacadeResolvesMemoryStoreForConnection {
    SSHKitMemoryTrustStore *store = [[SSHKitMemoryTrustStore alloc] initWithFingerprints:nil];
    NSError *error = nil;
    XCTAssertTrue([store saveFingerprint:@"abc123" host:@"example.com" port:2222 error:&error]);
    XCTAssertNil(error);

    SSHKitConfiguration *configuration = [[SSHKitConfiguration alloc] initWithHost:@"example.com" username:@"user"];
    configuration.port = 2222;
    configuration.hostKeyPolicy = [SSHKitHostKeyPolicy trustStore:store];

    SSHKitConnection *connection = [[SSHKitConnection alloc] initWithConfiguration:configuration];
    XCTAssertEqual(connection.configuration.hostKeyPolicyKind, SSHKitHostKeyPolicyKindTrustedFingerprint);
    XCTAssertEqualObjects(connection.configuration.trustedHostKeySHA256Fingerprint, @"SHA256:abc123");
}

- (void)testObjectiveCClientFacadeIsAvailable {
    XCTAssertNotNil([SSHKitClient class]);
}

- (void)testObjectiveCHostKeyDiscoveryResultExposesFields {
    SSHKitHostKeyDiscoveryResult *result = [[SSHKitHostKeyDiscoveryResult alloc] initWithHost:@"example.com"
                                                                                         port:2222
                                                                                  fingerprint:@"SHA256:abc123"];

    XCTAssertEqualObjects(result.host, @"example.com");
    XCTAssertEqual(result.port, 2222);
    XCTAssertEqualObjects(result.fingerprint, @"SHA256:abc123");
}

- (void)testObjectiveCLogRecorderBoundsEvents {
    SSHKitLogRecorder *recorder = [[SSHKitLogRecorder alloc] initWithCapacity:2];
    [recorder recordEvent:[[SSHKitLogEvent alloc] initWithLevel:SSHKitLogLevelInfo phase:@"connect" message:@"one" metadata:@{}]];
    [recorder recordEvent:[[SSHKitLogEvent alloc] initWithLevel:SSHKitLogLevelInfo phase:@"auth" message:@"two" metadata:@{}]];
    [recorder recordEvent:[[SSHKitLogEvent alloc] initWithLevel:SSHKitLogLevelWarning phase:@"trust" message:@"three" metadata:@{}]];

    XCTAssertEqual(recorder.events.count, 2);
    XCTAssertEqualObjects(recorder.events.firstObject.phase, @"auth");
    XCTAssertEqualObjects(recorder.events.lastObject.phase, @"trust");
}

- (void)testWorkerAllowsDocumentedCommandLifecycle {
    SSHCoreSessionWorker *worker = [[SSHCoreSessionWorker alloc] init];
    XCTestExpectation *expectation = [self expectationWithDescription:@"state transitions complete"];

    [worker async:^{
        [worker transitionToState:SSHCoreSessionStateConnecting];
        [worker transitionToState:SSHCoreSessionStateReady];
        [worker transitionToState:SSHCoreSessionStateRunningCommand];
        [worker transitionToState:SSHCoreSessionStateReady];
        [worker transitionToState:SSHCoreSessionStateClosing];
        [worker transitionToState:SSHCoreSessionStateClosed];
        [expectation fulfill];
    }];

    [self waitForExpectationsWithTimeout:2 handler:nil];
    XCTAssertEqual(worker.state, SSHCoreSessionStateClosed);
}

- (void)testWorkerAllowsDocumentedShellLifecycle {
    SSHCoreSessionWorker *worker = [[SSHCoreSessionWorker alloc] init];
    XCTestExpectation *expectation = [self expectationWithDescription:@"shell state transitions complete"];

    [worker async:^{
        [worker transitionToState:SSHCoreSessionStateConnecting];
        [worker transitionToState:SSHCoreSessionStateReady];
        [worker transitionToState:SSHCoreSessionStateRunningShell];
        [worker transitionToState:SSHCoreSessionStateReady];
        [worker transitionToState:SSHCoreSessionStateClosing];
        [worker transitionToState:SSHCoreSessionStateClosed];
        [expectation fulfill];
    }];

    [self waitForExpectationsWithTimeout:2 handler:nil];
    XCTAssertEqual(worker.state, SSHCoreSessionStateClosed);
}

- (void)testWorkerRejectsConcurrentJobs {
    SSHCoreSessionWorker *worker = [[SSHCoreSessionWorker alloc] init];
    XCTestExpectation *expectation = [self expectationWithDescription:@"invalid state raises"];

    [worker async:^{
        [worker transitionToState:SSHCoreSessionStateConnecting];
        [worker transitionToState:SSHCoreSessionStateReady];
        [worker transitionToState:SSHCoreSessionStateRunningShell];
        XCTAssertThrowsSpecificNamed([worker transitionToState:SSHCoreSessionStateRunningCommand],
                                     NSException,
                                     NSInternalInconsistencyException);
        [expectation fulfill];
    }];

    [self waitForExpectationsWithTimeout:2 handler:nil];
}

- (void)testCancellationTokenIsSticky {
    SSHCoreCancellationToken *token = [[SSHCoreCancellationToken alloc] init];
    XCTAssertFalse(token.cancelled);
    [token cancel];
    XCTAssertTrue(token.cancelled);
    [token cancel];
    XCTAssertTrue(token.cancelled);
}

- (void)testSFTPStatusCodesMapToTypedErrors {
    SSHKitConfiguration *configuration = [[SSHKitConfiguration alloc] initWithHost:@"example.com" username:@"user"];
    SSHCoreSessionWorker *worker = [[SSHCoreSessionWorker alloc] init];
    SSHCoreOpenSSHClient *client = [[SSHCoreOpenSSHClient alloc] initWithConfiguration:configuration worker:worker];

    NSError *missingFile = [client sftpErrorForOperation:@"SFTP stat" status:SSH_FX_NO_SUCH_FILE];
    XCTAssertEqualObjects(missingFile.domain, SSHKitErrorDomain);
    XCTAssertEqual(missingFile.code, SSHKitErrorCodeSFTPFileNotFound);

    NSError *permissionDenied = [client sftpErrorForOperation:@"SFTP write" status:SSH_FX_PERMISSION_DENIED];
    XCTAssertEqualObjects(permissionDenied.domain, SSHKitErrorDomain);
    XCTAssertEqual(permissionDenied.code, SSHKitErrorCodeSFTPPermissionDenied);

    NSError *genericFailure = [client sftpErrorForOperation:@"SFTP read" status:SSH_FX_FAILURE];
    XCTAssertEqualObjects(genericFailure.domain, SSHKitErrorDomain);
    XCTAssertEqual(genericFailure.code, SSHKitErrorCodeSFTPFailure);
}

- (void)testSFTPFileHandleDelegatesReadWriteSeekAndClose {
    XCTestExpectation *readExpectation = [self expectationWithDescription:@"read block called"];
    XCTestExpectation *writeExpectation = [self expectationWithDescription:@"write block called"];
    XCTestExpectation *seekExpectation = [self expectationWithDescription:@"seek block called"];
    XCTestExpectation *closeExpectation = [self expectationWithDescription:@"close block called"];

    SSHKitSFTPFileHandle *handle = [[SSHKitSFTPFileHandle alloc] initWithReadBlock:^(NSUInteger maximumLength, SSHKitSFTPDataCompletion completion) {
        XCTAssertEqual(maximumLength, 16);
        completion([@"chunk" dataUsingEncoding:NSUTF8StringEncoding], nil);
        [readExpectation fulfill];
    } writeBlock:^(NSData *data, SSHKitCompletion completion) {
        XCTAssertEqualObjects(data, [@"payload" dataUsingEncoding:NSUTF8StringEncoding]);
        completion(nil);
        [writeExpectation fulfill];
    } seekBlock:^(uint64_t offset, SSHKitCompletion completion) {
        XCTAssertEqual(offset, 42);
        completion(nil);
        [seekExpectation fulfill];
    } closeBlock:^(SSHKitCompletion completion) {
        completion(nil);
        [closeExpectation fulfill];
    }];

    [handle readDataWithMaximumLength:16 completion:^(NSData *data, NSError *error) {
        XCTAssertNil(error);
        XCTAssertEqualObjects(data, [@"chunk" dataUsingEncoding:NSUTF8StringEncoding]);
    }];
    [handle writeData:[@"payload" dataUsingEncoding:NSUTF8StringEncoding] completion:^(NSError *error) {
        XCTAssertNil(error);
    }];
    [handle seekToOffset:42 completion:^(NSError *error) {
        XCTAssertNil(error);
    }];
    [handle closeWithCompletion:^(NSError *error) {
        XCTAssertNil(error);
    }];

    [self waitForExpectationsWithTimeout:2 handler:nil];
}

- (void)testRequestCloseFromIdleIsIdempotent {
    SSHCoreSessionWorker *worker = [[SSHCoreSessionWorker alloc] init];

    [worker requestClose];
    [worker requestClose];

    XCTestExpectation *expectation = [self expectationWithDescription:@"close requests drain"];
    [worker async:^{
        [expectation fulfill];
    }];

    [self waitForExpectationsWithTimeout:2 handler:nil];
    XCTAssertEqual(worker.state, SSHCoreSessionStateClosed);
    XCTAssertTrue(worker.cancellationToken.cancelled);
}

- (void)testRequestCloseClosesOwnedSocketOnce {
    int sockets[2];
    XCTAssertEqual(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets), 0);

    SSHCoreSessionWorker *worker = [[SSHCoreSessionWorker alloc] init];
    worker.socketHandle = [[SSHCoreSocketHandle alloc] initWithFileDescriptor:sockets[0]];

    XCTestExpectation *ready = [self expectationWithDescription:@"worker reaches ready"];
    [worker async:^{
        [worker transitionToState:SSHCoreSessionStateConnecting];
        [worker transitionToState:SSHCoreSessionStateReady];
        [ready fulfill];
    }];
    [self waitForExpectationsWithTimeout:2 handler:nil];

    [worker requestClose];
    [worker requestClose];

    XCTestExpectation *closed = [self expectationWithDescription:@"worker closes socket"];
    [worker async:^{
        [closed fulfill];
    }];
    [self waitForExpectationsWithTimeout:2 handler:nil];

    XCTAssertEqual(worker.state, SSHCoreSessionStateClosed);
    XCTAssertNil(worker.socketHandle);
    close(sockets[1]);
}

- (void)testSocketHandleTransfersCloseOwnershipOnce {
    int sockets[2];
    XCTAssertEqual(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets), 0);

    SSHCoreSocketHandle *handle = [[SSHCoreSocketHandle alloc] initWithFileDescriptor:sockets[0]];
    XCTAssertEqual(handle.fileDescriptor, sockets[0]);
    [handle shutdownNow];

    int closeDescriptor = [handle takeFileDescriptorForClose];
    XCTAssertEqual(closeDescriptor, sockets[0]);
    XCTAssertEqual([handle takeFileDescriptorForClose], -1);

    close(closeDescriptor);
    close(sockets[1]);
}

- (void)testSocketHandleCoordinatesConcurrentShutdownAndCloseOwnership {
    for (NSUInteger iteration = 0; iteration < 100; iteration++) {
        int sockets[2];
        XCTAssertEqual(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets), 0);

        SSHCoreSocketHandle *handle = [[SSHCoreSocketHandle alloc] initWithFileDescriptor:sockets[0]];
        dispatch_group_t group = dispatch_group_create();
        __block int closeDescriptor = -1;

        dispatch_group_async(group, dispatch_get_global_queue(QOS_CLASS_DEFAULT, 0), ^{
            [handle shutdownNow];
        });
        dispatch_group_async(group, dispatch_get_global_queue(QOS_CLASS_DEFAULT, 0), ^{
            closeDescriptor = [handle takeFileDescriptorForClose];
        });

        XCTAssertEqual(dispatch_group_wait(group, dispatch_time(DISPATCH_TIME_NOW, 2 * NSEC_PER_SEC)), 0);
        XCTAssertEqual(closeDescriptor, sockets[0]);
        XCTAssertEqual([handle takeFileDescriptorForClose], -1);

        close(closeDescriptor);
        close(sockets[1]);
    }
}

@end
