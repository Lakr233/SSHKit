import Darwin
import Foundation
import SSHKit
import XCTest

final class AdvancedForwardLiveTests: LiveSSHTestCase {
    func testPrivateKeyLoginRunsDynamicSOCKSForwardToFixtureSSHD() throws {
        try requireLiveTestsEnabled()

        try withPrivateKeyConnection { connection in
            let fixture = try AlpineSSHFixture()
            let forward = try startDynamicForward(on: connection)
            defer {
                try? close(forward)
            }

            let banner = try readBannerThroughSOCKS(
                socksHost: forward.boundHost,
                socksPort: forward.boundPort,
                targetHost: "127.0.0.1",
                targetPort: fixture.remoteSSHDPort,
                username: nil,
                password: nil
            )
            XCTAssertTrue(banner.hasPrefix("SSH-2.0-"), "Expected SSH banner through SOCKS forward, received: \(banner)")
        }
    }

    func testPrivateKeyLoginRunsDynamicSOCKSForwardToHTTPServerThroughRemoteForward() throws {
        try requireLiveTestsEnabled()

        let body = "socks-http-ok\n"
        let response = "HTTP/1.1 200 OK\r\nContent-Length: \(body.utf8.count)\r\nConnection: close\r\n\r\n\(body)"
        let server = try OneShotTCPServer(payload: Data(response.utf8))
        defer {
            server.close()
        }

        try withPrivateKeyConnection { remoteForwardConnection in
            let remoteForward = try startRemoteForward(localHost: "127.0.0.1", localPort: server.port, on: remoteForwardConnection)
            defer {
                try? close(remoteForward)
            }

            try withPrivateKeyConnection { socksConnection in
                let socksForward = try startDynamicForward(on: socksConnection)
                defer {
                    try? close(socksForward)
                }

                let httpResponse = try readHTTPResponseThroughSOCKS(
                    socksHost: socksForward.boundHost,
                    socksPort: socksForward.boundPort,
                    targetHost: "127.0.0.1",
                    targetPort: remoteForward.boundPort
                )
                XCTAssertTrue(httpResponse.hasPrefix("HTTP/1.1 200 OK\r\n"))
                XCTAssertTrue(httpResponse.hasSuffix(body))
            }
        }
    }

    func testPrivateKeyLoginRunsAuthenticatedDynamicSOCKSForwardToFixtureSSHD() throws {
        try requireLiveTestsEnabled()

        try withPrivateKeyConnection { connection in
            let fixture = try AlpineSSHFixture()
            let forward = try startDynamicForward(username: "sshkit", password: "fixture-secret", on: connection)
            defer {
                try? close(forward)
            }

            let banner = try readBannerThroughSOCKS(
                socksHost: forward.boundHost,
                socksPort: forward.boundPort,
                targetHost: "127.0.0.1",
                targetPort: fixture.remoteSSHDPort,
                username: "sshkit",
                password: "fixture-secret"
            )
            XCTAssertTrue(banner.hasPrefix("SSH-2.0-"), "Expected SSH banner through authenticated SOCKS forward, received: \(banner)")
        }
    }

    func testPrivateKeyLoginRunsRemoteForwardToLocalTCPServer() throws {
        try requireLiveTestsEnabled()

        let payload = "remote-forward-ok\n"
        let server = try OneShotTCPServer(payload: Data(payload.utf8))
        defer {
            server.close()
        }

        try withPrivateKeyConnection { forwardingConnection in
            let forward = try startRemoteForward(localHost: "127.0.0.1", localPort: server.port, on: forwardingConnection)
            defer {
                try? close(forward)
            }

            try withPrivateKeyConnection { commandConnection in
                try requireRemoteNetcat(on: commandConnection)
                let result = try execute("nc -w 2 127.0.0.1 \(forward.boundPort)", on: commandConnection)
                XCTAssertEqual(result.exitStatus, 0)
                XCTAssertEqual(String(data: result.standardOutput, encoding: .utf8), payload)
                XCTAssertEqual(result.standardError, Data())
            }
        }
    }

    private func startDynamicForward(username: String? = nil, password: String? = nil, on connection: SSHConnection) throws -> SSHPortForward {
        let expectation = expectation(description: "Start dynamic SOCKS forward")
        var forwardResult: Result<SSHPortForward, SSHKitError>?
        LiveSSHLog.event("dynamic-forward start localHost=127.0.0.1 localPort=0 auth=\(username == nil ? "none" : "username-password")")
        connection.startDynamicForward(localHost: "127.0.0.1", localPort: 0, username: username, password: password, callbackQueue: .main) { result in
            LiveSSHLog.event("dynamic-forward \(result.liveDiagnosticStatus)")
            forwardResult = result
            expectation.fulfill()
        }
        wait(for: [expectation], timeout: 15)
        return try XCTUnwrap(forwardResult).get()
    }

    private func startRemoteForward(localHost: String, localPort: UInt16, on connection: SSHConnection) throws -> SSHPortForward {
        let expectation = expectation(description: "Start remote SSH forward")
        var forwardResult: Result<SSHPortForward, SSHKitError>?
        LiveSSHLog.event("remote-forward start remoteHost=127.0.0.1 remotePort=0 localHost=\(localHost) localPort=\(localPort)")
        connection.startRemoteForward(remoteHost: "127.0.0.1", remotePort: 0, localHost: localHost, localPort: localPort, callbackQueue: .main) { result in
            LiveSSHLog.event("remote-forward \(result.liveDiagnosticStatus)")
            forwardResult = result
            expectation.fulfill()
        }
        wait(for: [expectation], timeout: 15)
        return try XCTUnwrap(forwardResult).get()
    }

    private func close(_ forward: SSHPortForward) throws {
        let expectation = expectation(description: "Close SSH forward")
        var closeResult: Result<Void, SSHKitError>?
        LiveSSHLog.event("forward close start")
        forward.close(callbackQueue: .main) { result in
            LiveSSHLog.event("forward close \(result.liveDiagnosticStatus)")
            closeResult = result
            expectation.fulfill()
        }
        wait(for: [expectation], timeout: 15)
        try XCTUnwrap(closeResult).get()
    }

    private func execute(_ command: String, on connection: SSHConnection) throws -> SSHCommandResult {
        let expectation = expectation(description: "Execute live SSH command")
        var commandResult: Result<SSHCommandResult, SSHKitError>?
        LiveSSHLog.event("command start \(command)")
        connection.execute(command, callbackQueue: .main) { result in
            LiveSSHLog.event("command \(result.liveDiagnosticStatus)")
            commandResult = result
            expectation.fulfill()
        }
        wait(for: [expectation], timeout: 15)
        return try XCTUnwrap(commandResult).get()
    }

    private func requireRemoteNetcat(on connection: SSHConnection) throws {
        let result = try execute("command -v nc >/dev/null 2>&1 && nc -h 2>&1 | grep -q -- '-w'", on: connection)
        try requireLiveFixtureCapability(
            result.exitStatus == 0,
            "Remote forward live test requires netcat with -w timeout support on the fixture host."
        )
    }

    private func readBannerThroughSOCKS(
        socksHost: String,
        socksPort: UInt16,
        targetHost: String,
        targetPort: UInt16,
        username: String?,
        password: String?
    ) throws -> String {
        let fileDescriptor = try connectLocalTCP(host: socksHost, port: socksPort)
        defer {
            Darwin.close(fileDescriptor)
        }

        if let username, let password {
            try authenticateSOCKS(username: username, password: password, socket: fileDescriptor)
        } else {
            try negotiateSOCKSNoAuthentication(socket: fileDescriptor)
        }

        LiveSSHLog.event("socks connect start target=\(targetHost):\(targetPort)")
        try connectSOCKS(socket: fileDescriptor, host: targetHost, port: targetPort)
        var buffer = [UInt8](repeating: 0, count: 512)
        let byteCount = Darwin.read(fileDescriptor, &buffer, buffer.count)
        try requirePositiveRead(byteCount)
        return String(decoding: buffer.prefix(byteCount), as: UTF8.self)
    }

    private func readHTTPResponseThroughSOCKS(
        socksHost: String,
        socksPort: UInt16,
        targetHost: String,
        targetPort: UInt16
    ) throws -> String {
        let fileDescriptor = try connectLocalTCP(host: socksHost, port: socksPort)
        defer {
            Darwin.close(fileDescriptor)
        }

        try negotiateSOCKSNoAuthentication(socket: fileDescriptor)
        LiveSSHLog.event("socks connect start target=\(targetHost):\(targetPort)")
        try connectSOCKS(socket: fileDescriptor, host: targetHost, port: targetPort)
        try writeAll(Array("GET / HTTP/1.1\r\nHost: fixture\r\nConnection: close\r\n\r\n".utf8), to: fileDescriptor)
        return try readUntilEOF(from: fileDescriptor)
    }

    private func negotiateSOCKSNoAuthentication(socket: Int32) throws {
        try writeAll([0x05, 0x01, 0x00], to: socket)
        let selection = try readExactly(2, from: socket)
        guard selection == [0x05, 0x00] else {
            throw LiveSSHFixtureError.protocolFailure("SOCKS no-auth negotiation failed reply=\(selection)")
        }
    }

    private func authenticateSOCKS(username: String, password: String, socket: Int32) throws {
        try writeAll([0x05, 0x01, 0x02], to: socket)
        let selection = try readExactly(2, from: socket)
        guard selection == [0x05, 0x02] else {
            throw LiveSSHFixtureError.protocolFailure("SOCKS username-password negotiation failed reply=\(selection)")
        }

        let usernameBytes = Array(username.utf8)
        let passwordBytes = Array(password.utf8)
        XCTAssertLessThanOrEqual(usernameBytes.count, Int(UInt8.max))
        XCTAssertLessThanOrEqual(passwordBytes.count, Int(UInt8.max))

        var authRequest = [UInt8]()
        authRequest.append(0x01)
        authRequest.append(UInt8(usernameBytes.count))
        authRequest.append(contentsOf: usernameBytes)
        authRequest.append(UInt8(passwordBytes.count))
        authRequest.append(contentsOf: passwordBytes)
        try writeAll(authRequest, to: socket)

        let authResponse = try readExactly(2, from: socket)
        guard authResponse == [0x01, 0x00] else {
            throw LiveSSHFixtureError.protocolFailure("SOCKS authentication failed reply=\(authResponse)")
        }
    }

    private func connectSOCKS(socket: Int32, host: String, port: UInt16) throws {
        let hostBytes = Array(host.utf8)
        XCTAssertLessThanOrEqual(hostBytes.count, Int(UInt8.max))

        var request = [UInt8]()
        request.append(contentsOf: [0x05, 0x01, 0x00, 0x03, UInt8(hostBytes.count)])
        request.append(contentsOf: hostBytes)
        request.append(UInt8(port >> 8))
        request.append(UInt8(port & 0x00FF))
        try writeAll(request, to: socket)

        let header = try readExactly(4, from: socket)
        guard header[0] == 0x05 else {
            throw LiveSSHFixtureError.protocolFailure("SOCKS connect returned unsupported version=\(header[0])")
        }
        guard header[1] == 0x00 else {
            throw LiveSSHFixtureError.protocolFailure("SOCKS connect failed code=\(header[1]) target=\(host):\(port)")
        }
        try readSOCKSBoundAddress(type: header[3], from: socket)
        _ = try readExactly(2, from: socket)
        LiveSSHLog.event("socks connect success target=\(host):\(port)")
    }

    private func readSOCKSBoundAddress(type: UInt8, from socket: Int32) throws {
        switch type {
        case 0x01:
            _ = try readExactly(4, from: socket)
        case 0x03:
            let length = try readExactly(1, from: socket)[0]
            _ = try readExactly(Int(length), from: socket)
        case 0x04:
            _ = try readExactly(16, from: socket)
        default:
            throw LiveSSHFixtureError.protocolFailure("SOCKS connect returned unsupported address type=\(type)")
        }
    }

    private func connectLocalTCP(host: String, port: UInt16) throws -> Int32 {
        var hints = addrinfo(
            ai_flags: 0,
            ai_family: AF_UNSPEC,
            ai_socktype: SOCK_STREAM,
            ai_protocol: IPPROTO_TCP,
            ai_addrlen: 0,
            ai_canonname: nil,
            ai_addr: nil,
            ai_next: nil
        )
        var addresses: UnsafeMutablePointer<addrinfo>?
        XCTAssertEqual(getaddrinfo(host, String(port), &hints, &addresses), 0)
        defer {
            if let addresses {
                freeaddrinfo(addresses)
            }
        }

        var lastErrno: Int32 = 0
        var cursor = addresses
        while let address = cursor {
            let fileDescriptor = socket(address.pointee.ai_family, address.pointee.ai_socktype, address.pointee.ai_protocol)
            if fileDescriptor >= 0 {
                if Darwin.connect(fileDescriptor, address.pointee.ai_addr, address.pointee.ai_addrlen) == 0 {
                    setSocketTimeout(on: fileDescriptor)
                    return fileDescriptor
                }
                lastErrno = errno
                Darwin.close(fileDescriptor)
            }
            cursor = address.pointee.ai_next
        }

        throw NSError(domain: NSPOSIXErrorDomain, code: Int(lastErrno), userInfo: [NSLocalizedDescriptionKey: String(cString: strerror(lastErrno))])
    }

    private func setSocketTimeout(on socket: Int32) {
        var timeout = timeval(tv_sec: 5, tv_usec: 0)
        setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size))
        setsockopt(socket, SOL_SOCKET, SO_SNDTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size))
    }

    private func writeAll(_ bytes: [UInt8], to socket: Int32) throws {
        try bytes.withUnsafeBytes { buffer in
            var offset = 0
            while offset < buffer.count {
                let written = Darwin.write(socket, buffer.baseAddress!.advanced(by: offset), buffer.count - offset)
                if written < 0, errno == EINTR {
                    continue
                }
                if written <= 0 {
                    throw NSError(domain: NSPOSIXErrorDomain, code: Int(errno), userInfo: [NSLocalizedDescriptionKey: String(cString: strerror(errno))])
                }
                offset += written
            }
        }
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
                throw NSError(domain: NSPOSIXErrorDomain, code: Int(errno), userInfo: [NSLocalizedDescriptionKey: String(cString: strerror(errno))])
            }
            offset += count
        }
        return buffer
    }

    private func readUntilEOF(from socket: Int32) throws -> String {
        var data = Data()
        var buffer = [UInt8](repeating: 0, count: 4096)
        while true {
            let count = Darwin.read(socket, &buffer, buffer.count)
            if count < 0, errno == EINTR {
                continue
            }
            if count < 0 {
                throw NSError(domain: NSPOSIXErrorDomain, code: Int(errno), userInfo: [NSLocalizedDescriptionKey: String(cString: strerror(errno))])
            }
            if count == 0 {
                break
            }
            data.append(contentsOf: buffer.prefix(count))
        }
        return String(data: data, encoding: .utf8) ?? ""
    }

    private func requirePositiveRead(_ byteCount: Int) throws {
        if byteCount < 0 {
            throw NSError(domain: NSPOSIXErrorDomain, code: Int(errno), userInfo: [NSLocalizedDescriptionKey: String(cString: strerror(errno))])
        }
        if byteCount == 0 {
            throw NSError(domain: NSPOSIXErrorDomain, code: 0, userInfo: [NSLocalizedDescriptionKey: "Unexpected EOF while reading fixture banner."])
        }
    }
}

private final class OneShotTCPServer {
    let port: UInt16
    private var listener: Int32
    private let payload: Data
    private let queue = DispatchQueue(label: "sshkit.live.one-shot-tcp-server")
    private let lock = NSLock()

    init(payload: Data) throws {
        let listenerSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)
        guard listenerSocket >= 0 else {
            throw NSError(domain: NSPOSIXErrorDomain, code: Int(errno), userInfo: [NSLocalizedDescriptionKey: String(cString: strerror(errno))])
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
            throw NSError(domain: NSPOSIXErrorDomain, code: Int(bindErrno), userInfo: [NSLocalizedDescriptionKey: String(cString: strerror(bindErrno))])
        }

        guard listen(listenerSocket, 1) == 0 else {
            let listenErrno = errno
            Darwin.close(listenerSocket)
            throw NSError(domain: NSPOSIXErrorDomain, code: Int(listenErrno), userInfo: [NSLocalizedDescriptionKey: String(cString: strerror(listenErrno))])
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
            throw NSError(domain: NSPOSIXErrorDomain, code: Int(nameErrno), userInfo: [NSLocalizedDescriptionKey: String(cString: strerror(nameErrno))])
        }

        listener = listenerSocket
        port = UInt16(bigEndian: boundAddress.sin_port)
        self.payload = payload
        start()
    }

    func close() {
        lock.lock()
        let listenerToClose = listener
        listener = -1
        lock.unlock()

        if listenerToClose >= 0 {
            Darwin.shutdown(listenerToClose, SHUT_RDWR)
            Darwin.close(listenerToClose)
        }
    }

    private func start() {
        let listenerSocket = listener
        queue.async { [listenerSocket, payload] in
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
            defer {
                Darwin.close(client)
            }

            payload.withUnsafeBytes { buffer in
                var offset = 0
                while offset < buffer.count {
                    let written = Darwin.write(client, buffer.baseAddress!.advanced(by: offset), buffer.count - offset)
                    if written < 0, errno == EINTR {
                        continue
                    }
                    if written <= 0 {
                        return
                    }
                    offset += written
                }
            }
        }
    }

    deinit {
        close()
    }
}
