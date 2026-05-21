import Darwin
import Foundation
import SSHKit
import XCTest

final class CancellationLiveTests: LiveSSHTestCase {
    func testConnectCancellationClosesFixtureConnectionAttemptThroughBlockingRoute() async throws {
        try requireLiveTestsEnabled()

        let fixture = try AlpineSSHFixture()
        let blockingRoute = try BlockingTCPServer()
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
        let sftp = try await connection.openSFTP()
        let fixtureID = UUID().uuidString
        let remotePath = "/tmp/sshkit-cancel-\(fixtureID).bin"
        let localURL = try makeTemporaryDirectory().appendingPathComponent("cancelled-download.bin")

        do {
            _ = try await connection.execute("dd if=/dev/zero of=\(shellQuoted(remotePath)) bs=1048576 count=128")
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

    private func connectWithPrivateKey() async throws -> SSHConnection {
        let fixture = try AlpineSSHFixture()
        return try await SSHClient.connect(configuration: privateKeyConfiguration(fixture: fixture))
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

private final class BlockingTCPServer: @unchecked Sendable {
    let port: UInt16

    private let queue = DispatchQueue(label: "SSHKitBlockingTCPServer")
    private let lock = NSLock()
    private var listener: Int32
    private var acceptedSockets: [Int32] = []

    init() throws {
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

                self?.storeAcceptedSocket(client)
            }
        }
    }

    private func storeAcceptedSocket(_ socket: Int32) {
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
