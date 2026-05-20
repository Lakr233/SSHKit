#import <XCTest/XCTest.h>

#import <CLibSSH/CLibSSH.h>

#import "SSHCoreCancellationToken.h"
#import "SSHCoreSessionWorker.h"
#import "SSHCoreSocketHandle.h"

#include <sys/socket.h>
#include <unistd.h>

@interface SSHCoreObjCTests : XCTestCase
@end

@implementation SSHCoreObjCTests

- (void)testCLibSSHLinksAndCreatesSession {
    XCTAssertGreaterThan(LIBSSH_VERSION_INT, 0);
    ssh_session session = ssh_new();
    XCTAssertNotEqual(session, NULL);
    ssh_free(session);
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
