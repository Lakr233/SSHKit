import Darwin
import Foundation
import SSHKit
import XCTest

final class CancellationLiveTests: LiveSSHTestCase {
    func testConnectCancellationClosesFixtureConnectionAttemptThroughBlockingRoute() async throws {
        try requireLiveTestsEnabled()

        let fixture = try AlpineSSHFixture()
        let blockingRoute = try FixtureTCPServer(acceptedConnectionBehavior: .holdOpen)
        defer {
            blockingRoute.close()
        }

        let configuration = try privateKeyConfiguration(
            fixture: fixture,
            proxyRoute: .socks5(SSHProxyEndpoint(host: "127.0.0.1", port: blockingRoute.port)),
        )
        let connectTask = Task {
            _ = try await SSHClient.connect(configuration: configuration)
        }

        try await Task.sleep(nanoseconds: 200_000_000)
        connectTask.cancel()
        await assertTaskFailsWithCancellation(connectTask)
    }

    func testExecuteCancellationClosesFixtureConnection() async throws {
        try requireLiveTestsEnabled()

        let connection = try await connectWithPrivateKey()
        let commandTask = Task {
            _ = try await connection.execute("sleep 20 && printf done")
        }

        try await Task.sleep(nanoseconds: 200_000_000)
        commandTask.cancel()
        await assertTaskFailsWithCancellation(commandTask)
    }

    func testShellCancellationClosesFixtureConnection() async throws {
        try requireLiveTestsEnabled()

        let connection = try await connectWithPrivateKey()
        let shell = try await connection.openShell { _ in }
        try await shell.write("sleep 30\n")
        let payload = Data(repeating: 65, count: 32 * 1024 * 1024)
        let writeTask = Task {
            try await shell.write(payload)
        }

        try await Task.sleep(nanoseconds: 200_000_000)
        writeTask.cancel()
        await assertTaskFailsWithCancellation(writeTask)
    }

    func testSFTPDownloadCancellationClosesFixtureConnection() async throws {
        try requireLiveTestsEnabled()

        let connection = try await connectWithPrivateKey()
        let fixtureID = UUID().uuidString
        let remotePath = "/tmp/sshkit-cancel-\(fixtureID).bin"
        let localURL = try makeTemporaryDirectory().appendingPathComponent("cancelled-download.bin")

        do {
            _ = try await connection.execute("dd if=/dev/zero of=\(shellQuoted(remotePath)) bs=1048576 count=128")
            let sftp = try await connection.openSFTP()
            let downloadTask = Task {
                try await sftp.download(remotePath: remotePath, to: localURL)
            }
            try await Task.sleep(nanoseconds: 200_000_000)
            downloadTask.cancel()
            await assertTaskFailsWithCancellation(downloadTask)
        } catch {
            try? await removeRemoteFile(remotePath)
            try? await connection.close()
            throw error
        }
        try? await removeRemoteFile(remotePath)
    }

    func testForwardReadCancellationClosesFixtureConnection() async throws {
        try requireLiveTestsEnabled()

        let server = try FixtureTCPServer(acceptedConnectionBehavior: .holdOpen)
        defer {
            server.close()
        }

        let forwardingConnection = try await connectWithPrivateKey()
        let remoteForward = try await forwardingConnection.startRemoteForward(localHost: "127.0.0.1", localPort: server.port)

        let channelConnection = try await connectWithPrivateKey()
        let channel = try await channelConnection.openDirectTCPChannel(host: "127.0.0.1", port: remoteForward.boundPort)
        let readTask = Task {
            _ = try await channel.read(maximumLength: 512)
        }

        try await Task.sleep(nanoseconds: 200_000_000)
        readTask.cancel()
        await assertTaskFailsWithCancellation(readTask)

        await assertEventuallyRejectsCommandAfterCancellation(channelConnection)

        try? await remoteForward.close()
        try? await forwardingConnection.close()
    }

    func testForwardRemoteCloseReleasesFixtureConnection() async throws {
        try requireLiveTestsEnabled()

        let server = try FixtureTCPServer(acceptedConnectionBehavior: .closeImmediately)
        defer {
            server.close()
        }

        let forwardingConnection = try await connectWithPrivateKey()
        let remoteForward = try await forwardingConnection.startRemoteForward(localHost: "127.0.0.1", localPort: server.port)

        let channelConnection = try await connectWithPrivateKey()
        let channel = try await channelConnection.openDirectTCPChannel(host: "127.0.0.1", port: remoteForward.boundPort)

        do {
            _ = try await channel.read(maximumLength: 512)
            XCTFail("Forward read completed successfully after the target closed.")
        } catch let error as SSHKitError {
            XCTAssertEqual(error.code, SSHKitErrorCode.connectionFailed.rawValue)
        }

        let result = try await channelConnection.execute("printf after-forward-close")
        XCTAssertEqual(String(data: result.standardOutput, encoding: .utf8), "after-forward-close")

        try? await channelConnection.close()
        try? await remoteForward.close()
        try? await forwardingConnection.close()
    }

    private func connectWithPrivateKey() async throws -> SSHConnection {
        let fixture = try AlpineSSHFixture()
        return try await SSHClient.connect(configuration: privateKeyConfiguration(fixture: fixture))
    }

    private func assertEventuallyRejectsCommandAfterCancellation(
        _ connection: SSHConnection,
        file: StaticString = #filePath,
        line: UInt = #line,
    ) async {
        let deadline = Date().addingTimeInterval(5)
        var lastError: Error?

        while Date() < deadline {
            do {
                _ = try await connection.execute("printf after-forward-cancel")
                XCTFail("Connection accepted a command after forward read cancellation.", file: file, line: line)
                return
            } catch let error as SSHKitError where error.code == SSHKitErrorCode.invalidState.rawValue {
                return
            } catch {
                lastError = error
                try? await Task.sleep(nanoseconds: 100_000_000)
            }
        }

        XCTFail("Connection did not report invalidState after forward read cancellation. Last error: \(String(describing: lastError))", file: file, line: line)
    }

    private func privateKeyConfiguration(
        fixture: AlpineSSHFixture,
        proxyRoute: SSHProxyRoute? = nil,
    ) throws -> SSHClientConfiguration {
        try SSHClientConfiguration(
            host: fixture.host,
            port: fixture.port,
            username: fixture.username,
            authentication: .privateKeyFile(path: makePrivateKeyFile(fixture: fixture)),
            hostKeyPolicy: .knownHostsFile(makeKnownHostsFile(fixture: fixture)),
            timeout: 10,
            proxyRoute: proxyRoute,
        )
    }

    private func assertTaskFailsWithCancellation(
        _ task: Task<Void, Error>,
        file: StaticString = #filePath,
        line: UInt = #line,
    ) async {
        do {
            _ = try await task.value
            XCTFail("Cancelled fixture operation completed successfully.", file: file, line: line)
        } catch let error as SSHKitError {
            XCTAssertEqual(error.code, SSHKitErrorCode.cancelled.rawValue, file: file, line: line)
        } catch {
            XCTFail("Cancelled fixture operation returned unexpected error: \(error)", file: file, line: line)
        }
    }

    private func shellQuoted(_ value: String) -> String {
        "'\(value.replacingOccurrences(of: "'", with: "'\\''"))'"
    }

    private func removeRemoteFile(_ remotePath: String) async throws {
        let connection = try await connectWithPrivateKey()
        _ = try await connection.execute("rm -f \(shellQuoted(remotePath))")
        try await connection.close()
    }
}

private final class FixtureTCPServer: @unchecked Sendable {
    enum AcceptedConnectionBehavior {
        case holdOpen
        case closeImmediately
    }

    let port: UInt16

    private let acceptedConnectionBehavior: AcceptedConnectionBehavior
    private let queue = DispatchQueue(label: "SSHKitFixtureTCPServer")
    private let lock = NSLock()
    private var listener: Int32
    private var acceptedSockets: [Int32] = []

    init(acceptedConnectionBehavior: AcceptedConnectionBehavior) throws {
        let listenerSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)
        guard listenerSocket >= 0 else {
            throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
        }

        var reuse: Int32 = 1
        setsockopt(listenerSocket, SOL_SOCKET, SO_REUSEADDR, &reuse, socklen_t(MemoryLayout.size(ofValue: reuse)))

        var address = sockaddr_in()
        address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        address.sin_family = sa_family_t(AF_INET)
        address.sin_port = UInt16(0).bigEndian
        address.sin_addr = in_addr(s_addr: inet_addr("127.0.0.1"))

        let bindResult = withUnsafePointer(to: &address) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockaddrPointer in
                Darwin.bind(listenerSocket, sockaddrPointer, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        guard bindResult == 0 else {
            let bindErrno = errno
            Darwin.close(listenerSocket)
            throw POSIXError(POSIXErrorCode(rawValue: bindErrno) ?? .EIO)
        }

        guard listen(listenerSocket, 1) == 0 else {
            let listenErrno = errno
            Darwin.close(listenerSocket)
            throw POSIXError(POSIXErrorCode(rawValue: listenErrno) ?? .EIO)
        }

        var boundAddress = sockaddr_in()
        var boundLength = socklen_t(MemoryLayout<sockaddr_in>.size)
        let nameResult = withUnsafeMutablePointer(to: &boundAddress) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockaddrPointer in
                getsockname(listenerSocket, sockaddrPointer, &boundLength)
            }
        }
        guard nameResult == 0 else {
            let nameErrno = errno
            Darwin.close(listenerSocket)
            throw POSIXError(POSIXErrorCode(rawValue: nameErrno) ?? .EIO)
        }

        listener = listenerSocket
        port = UInt16(bigEndian: boundAddress.sin_port)
        self.acceptedConnectionBehavior = acceptedConnectionBehavior
        startAccepting()
    }

    deinit {
        close()
    }

    func close() {
        lock.lock()
        let listenerToClose = listener
        listener = -1
        let socketsToClose = acceptedSockets
        acceptedSockets.removeAll()
        lock.unlock()

        if listenerToClose >= 0 {
            Darwin.shutdown(listenerToClose, SHUT_RDWR)
            Darwin.close(listenerToClose)
        }

        for socket in socketsToClose {
            Darwin.shutdown(socket, SHUT_RDWR)
            Darwin.close(socket)
        }
    }

    private func startAccepting() {
        let listenerSocket = listener
        queue.async { [weak self] in
            while true {
                var address = sockaddr_in()
                var addressLength = socklen_t(MemoryLayout<sockaddr_in>.size)
                let client = withUnsafeMutablePointer(to: &address) { pointer in
                    pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockaddrPointer in
                        accept(listenerSocket, sockaddrPointer, &addressLength)
                    }
                }

                guard client >= 0 else {
                    return
                }

                self?.handleAcceptedSocket(client)
            }
        }
    }

    private func handleAcceptedSocket(_ socket: Int32) {
        guard acceptedConnectionBehavior == .holdOpen else {
            Darwin.shutdown(socket, SHUT_RDWR)
            Darwin.close(socket)
            return
        }

        lock.lock()
        let shouldStore = listener >= 0
        if shouldStore {
            acceptedSockets.append(socket)
        }
        lock.unlock()

        if shouldStore == false {
            Darwin.shutdown(socket, SHUT_RDWR)
            Darwin.close(socket)
        }
    }
}
