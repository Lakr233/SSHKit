import Darwin
import Foundation
import SSHKit
import XCTest

final class ProxyRouteLiveTests: LiveSSHTestCase {
    func testPrivateKeyLoginConnectsThroughSOCKS5ProxyToFixture() throws {
        try requireLiveTestsEnabled()

        let fixture = try AlpineSSHFixture()
        let proxy = try LoopbackProxyServer(mode: .socks5)
        defer {
            proxy.close()
        }

        let connection = try connectThroughProxy(
            fixture: fixture,
            proxyRoute: .socks5(SSHProxyEndpoint(host: "127.0.0.1", port: proxy.port)),
            hostKeyPolicy: .knownHostsFile(makeKnownHostsFile(fixture: fixture)),
        )
        defer {
            try? close(connection)
        }

        try assertSmokeCommandResult(awaitSmokeCommand(on: connection))
    }

    func testPrivateKeyLoginConnectsThroughHTTPConnectProxyToFixture() throws {
        try requireLiveTestsEnabled()

        let fixture = try AlpineSSHFixture()
        let proxy = try LoopbackProxyServer(mode: .httpConnect)
        defer {
            proxy.close()
        }

        let connection = try connectThroughProxy(
            fixture: fixture,
            proxyRoute: .httpConnect(SSHProxyEndpoint(host: "127.0.0.1", port: proxy.port)),
            hostKeyPolicy: .knownHostsFile(makeKnownHostsFile(fixture: fixture)),
        )
        defer {
            try? close(connection)
        }

        try assertSmokeCommandResult(awaitSmokeCommand(on: connection))
    }

    func testPrivateKeyLoginConnectsThroughProxyJumpFixture() throws {
        try requireLiveTestsEnabled()

        let fixture = try AlpineSSHFixture()
        let privateKeyPath = try makePrivateKeyFile(fixture: fixture)
        let knownHostsPath = try makeKnownHostsFile(fixture: fixture)
        let jumpHost = SSHJumpHost(
            host: fixture.host,
            port: fixture.port,
            username: fixture.username,
            authentication: .privateKeyFile(path: privateKeyPath),
            hostKeyPolicy: .knownHostsFile(knownHostsPath),
        )
        let configuration = SSHClientConfiguration(
            host: "127.0.0.1",
            port: fixture.port,
            username: fixture.username,
            authentication: .privateKeyFile(path: privateKeyPath),
            hostKeyPolicy: .insecureAcceptAnyHostKey,
            timeout: 10,
            proxyRoute: .proxyJump(jumpHost),
        )

        let connection = try connect(configuration: configuration)
        defer {
            try? close(connection)
        }

        try assertSmokeCommandResult(awaitSmokeCommand(on: connection))
    }

    private func connectThroughProxy(
        fixture: AlpineSSHFixture,
        proxyRoute: SSHProxyRoute,
        hostKeyPolicy: SSHHostKeyPolicy,
    ) throws -> SSHConnection {
        let configuration = try SSHClientConfiguration(
            host: fixture.host,
            port: fixture.port,
            username: fixture.username,
            authentication: .privateKeyFile(path: makePrivateKeyFile(fixture: fixture)),
            hostKeyPolicy: hostKeyPolicy,
            timeout: 10,
            proxyRoute: proxyRoute,
        )
        return try connect(configuration: configuration)
    }

    private func connect(configuration: SSHClientConfiguration) throws -> SSHConnection {
        let expectation = expectation(description: "Connect through proxy route")
        var connectionResult: Result<SSHConnection, SSHKitError>?
        SSHClient.connect(configuration: configuration, callbackQueue: .main) { result in
            connectionResult = result
            expectation.fulfill()
        }
        wait(for: [expectation], timeout: 20)
        return try XCTUnwrap(connectionResult).get()
    }
}

final class LoopbackProxyServer: @unchecked Sendable {
    enum Mode {
        case socks5
        case httpConnect
    }

    let port: UInt16
    private var listener: Int32
    private let mode: Mode
    private let queue = DispatchQueue(label: "sshkit.live.proxy-server")
    private let lock = NSLock()
    private var activeSockets = [Int32]()

    init(mode: Mode) throws {
        self.mode = mode
        let listenerSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)
        guard listenerSocket >= 0 else {
            throw currentPOSIXError()
        }

        var reuse: Int32 = 1
        setsockopt(listenerSocket, SOL_SOCKET, SO_REUSEADDR, &reuse, socklen_t(MemoryLayout.size(ofValue: reuse)))

        var address = sockaddr_in()
        address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        address.sin_family = sa_family_t(AF_INET)
        address.sin_port = 0
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

        guard listen(listenerSocket, 4) == 0 else {
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
        start()
    }

    func close() {
        lock.lock()
        let listenerToClose = listener
        listener = -1
        let sockets = activeSockets
        activeSockets.removeAll()
        lock.unlock()

        if listenerToClose >= 0 {
            Darwin.shutdown(listenerToClose, SHUT_RDWR)
            Darwin.close(listenerToClose)
        }
        for socket in sockets where socket >= 0 {
            Darwin.shutdown(socket, SHUT_RDWR)
            Darwin.close(socket)
        }
    }

    private func start() {
        let listenerSocket = listener
        queue.async { [weak self] in
            guard let self else {
                return
            }
            var address = sockaddr_storage()
            var addressLength = socklen_t(MemoryLayout<sockaddr_storage>.size)
            let client = withUnsafeMutablePointer(to: &address) { pointer in
                pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockaddrPointer in
                    accept(listenerSocket, sockaddrPointer, &addressLength)
                }
            }
            guard client >= 0 else {
                return
            }
            addActiveSocket(client)
            do {
                let target = try readTarget(from: client)
                let remote = try openRemoteSocket(host: target.host, port: target.port)
                addActiveSocket(remote)
                try sendConnectedReply(to: client)
                bridge(client, remote)
            } catch {
                Darwin.close(client)
            }
        }
    }

    private func readTarget(from client: Int32) throws -> (host: String, port: UInt16) {
        switch mode {
        case .socks5:
            try readSOCKS5Target(from: client)
        case .httpConnect:
            try readHTTPConnectTarget(from: client)
        }
    }

    private func sendConnectedReply(to client: Int32) throws {
        switch mode {
        case .socks5:
            try writeAll([0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0], to: client)
        case .httpConnect:
            try writeAll(Array("HTTP/1.1 200 Connection Established\r\n\r\n".utf8), to: client)
        }
    }

    private func readSOCKS5Target(from client: Int32) throws -> (host: String, port: UInt16) {
        let greeting = try readExactly(2, from: client)
        guard greeting[0] == 0x05, greeting[1] > 0 else {
            throw POSIXError(.EPROTO)
        }
        _ = try readExactly(Int(greeting[1]), from: client)
        try writeAll([0x05, 0x00], to: client)

        let request = try readExactly(4, from: client)
        guard request[0] == 0x05, request[1] == 0x01 else {
            throw POSIXError(.EPROTO)
        }

        let host: String
        switch request[3] {
        case 0x01:
            let bytes = try readExactly(4, from: client)
            host = bytes.map(String.init).joined(separator: ".")
        case 0x03:
            let length = try Int(readExactly(1, from: client)[0])
            host = try String(decoding: readExactly(length, from: client), as: UTF8.self)
        default:
            throw POSIXError(.EPROTO)
        }
        let portBytes = try readExactly(2, from: client)
        let port = UInt16(portBytes[0]) << 8 | UInt16(portBytes[1])
        return (host, port)
    }

    private func readHTTPConnectTarget(from client: Int32) throws -> (host: String, port: UInt16) {
        let header = try readHeader(from: client)
        guard let requestLine = header.components(separatedBy: "\r\n").first else {
            throw POSIXError(.EPROTO)
        }
        let parts = requestLine.split(separator: " ")
        guard parts.count >= 2, parts[0] == "CONNECT" else {
            throw POSIXError(.EPROTO)
        }
        let authority = parts[1].split(separator: ":", maxSplits: 1).map(String.init)
        guard authority.count == 2, let port = UInt16(authority[1]) else {
            throw POSIXError(.EPROTO)
        }
        return (authority[0], port)
    }

    private func openRemoteSocket(host: String, port: UInt16) throws -> Int32 {
        var hints = addrinfo(
            ai_flags: 0,
            ai_family: AF_UNSPEC,
            ai_socktype: SOCK_STREAM,
            ai_protocol: IPPROTO_TCP,
            ai_addrlen: 0,
            ai_canonname: nil,
            ai_addr: nil,
            ai_next: nil,
        )
        var addresses: UnsafeMutablePointer<addrinfo>?
        guard getaddrinfo(host, String(port), &hints, &addresses) == 0 else {
            throw POSIXError(.ENOENT)
        }
        defer {
            freeaddrinfo(addresses)
        }

        var cursor = addresses
        while let address = cursor {
            let fileDescriptor = socket(address.pointee.ai_family, address.pointee.ai_socktype, address.pointee.ai_protocol)
            if fileDescriptor >= 0 {
                if Darwin.connect(fileDescriptor, address.pointee.ai_addr, address.pointee.ai_addrlen) == 0 {
                    return fileDescriptor
                }
                Darwin.close(fileDescriptor)
            }
            cursor = address.pointee.ai_next
        }
        throw currentPOSIXError()
    }

    private func bridge(_ left: Int32, _ right: Int32) {
        let group = DispatchGroup()
        group.enter()
        DispatchQueue.global().async {
            self.copyBytes(from: left, to: right)
            Darwin.shutdown(right, SHUT_WR)
            group.leave()
        }
        group.enter()
        DispatchQueue.global().async {
            self.copyBytes(from: right, to: left)
            Darwin.shutdown(left, SHUT_WR)
            group.leave()
        }
        group.wait()
        removeActiveSocket(left)
        removeActiveSocket(right)
        Darwin.close(left)
        Darwin.close(right)
    }

    private func copyBytes(from source: Int32, to destination: Int32) {
        var buffer = [UInt8](repeating: 0, count: 32768)
        let capacity = buffer.count
        while true {
            let count = buffer.withUnsafeMutableBytes { rawBuffer in
                Darwin.read(source, rawBuffer.baseAddress, capacity)
            }
            if count < 0, errno == EINTR {
                continue
            }
            if count <= 0 {
                return
            }
            do {
                try buffer.withUnsafeBytes { rawBuffer in
                    try writeAll(rawBuffer.bindMemory(to: UInt8.self).prefix(count).map(\.self), to: destination)
                }
            } catch {
                return
            }
        }
    }

    private func readHeader(from socket: Int32) throws -> String {
        var data = Data()
        while data.count < 16 * 1024 {
            let byte = try readExactly(1, from: socket)[0]
            data.append(byte)
            if data.count >= 4, data.suffix(4) == Data("\r\n\r\n".utf8) {
                return String(data: data, encoding: .utf8) ?? ""
            }
        }
        throw POSIXError(.EOVERFLOW)
    }

    private func readExactly(_ length: Int, from socket: Int32) throws -> [UInt8] {
        var buffer = [UInt8](repeating: 0, count: length)
        var offset = 0
        while offset < length {
            let count = buffer.withUnsafeMutableBytes { rawBuffer in
                Darwin.read(socket, rawBuffer.baseAddress!.advanced(by: offset), length - offset)
            }
            if count < 0, errno == EINTR {
                continue
            }
            if count <= 0 {
                throw currentPOSIXError()
            }
            offset += count
        }
        return buffer
    }

    private func writeAll(_ bytes: [UInt8], to socket: Int32) throws {
        try bytes.withUnsafeBytes { rawBuffer in
            var offset = 0
            while offset < rawBuffer.count {
                let written = Darwin.write(socket, rawBuffer.baseAddress!.advanced(by: offset), rawBuffer.count - offset)
                if written < 0, errno == EINTR {
                    continue
                }
                if written <= 0 {
                    throw currentPOSIXError()
                }
                offset += written
            }
        }
    }

    private func addActiveSocket(_ socket: Int32) {
        lock.lock()
        activeSockets.append(socket)
        lock.unlock()
    }

    private func removeActiveSocket(_ socket: Int32) {
        lock.lock()
        activeSockets.removeAll { $0 == socket }
        lock.unlock()
    }

    deinit {
        close()
    }
}

private func currentPOSIXError() -> POSIXError {
    POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
}
