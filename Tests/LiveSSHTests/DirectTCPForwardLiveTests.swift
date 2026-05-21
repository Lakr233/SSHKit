import Darwin
import SSHKit
import XCTest

final class DirectTCPForwardLiveTests: LiveSSHTestCase {
    func testPrivateKeyLoginOpensDirectTCPChannelToFixtureSSHD() throws {
        try requireLiveTestsEnabled()

        try withPrivateKeyConnection { connection in
            let fixture = try AlpineSSHFixture()
            let channel = try openDirectTCPChannel(host: "127.0.0.1", port: fixture.remoteSSHDPort, on: connection)
            defer {
                try? close(channel)
            }

            let banner = try readBanner(from: channel)
            XCTAssertTrue(banner.hasPrefix("SSH-2.0-"), "Expected SSH banner from fixture sshd, received: \(banner)")
        }
    }

    func testPrivateKeyLoginRoundTripsDirectTCPChannelToFixtureSSHD() throws {
        try requireLiveTestsEnabled()

        try withPrivateKeyConnection { connection in
            let fixture = try AlpineSSHFixture()
            let channel = try openDirectTCPChannel(host: "127.0.0.1", port: fixture.remoteSSHDPort, on: connection)
            defer {
                try? close(channel)
            }

            let banner = try readBanner(from: channel)
            XCTAssertTrue(banner.hasPrefix("SSH-2.0-"), "Expected SSH banner from fixture sshd, received: \(banner)")

            try writeClientBanner(to: channel)
            let response = try readData(from: channel)
            XCTAssertFalse(response.isEmpty, "Expected fixture sshd to respond after client banner.")
        }
    }

    func testPrivateKeyLoginRunsLocalForwardToFixtureSSHD() throws {
        try requireLiveTestsEnabled()

        try withPrivateKeyConnection { connection in
            let fixture = try AlpineSSHFixture()
            let forward = try startLocalForward(remoteHost: "127.0.0.1", remotePort: fixture.remoteSSHDPort, on: connection)
            defer {
                try? close(forward)
            }

            let banner = try readBannerFromLocalForward(host: forward.boundHost, port: forward.boundPort)
            XCTAssertTrue(banner.hasPrefix("SSH-2.0-"), "Expected SSH banner through local forward, received: \(banner)")
        }
    }

    func testPrivateKeyLoginRoundTripsLocalForwardToFixtureSSHD() throws {
        try requireLiveTestsEnabled()

        try withPrivateKeyConnection { connection in
            let fixture = try AlpineSSHFixture()
            let forward = try startLocalForward(remoteHost: "127.0.0.1", remotePort: fixture.remoteSSHDPort, on: connection)
            defer {
                try? close(forward)
            }

            let response = try roundTripSSHHandshakeThroughLocalForward(host: forward.boundHost, port: forward.boundPort)
            XCTAssertFalse(response.isEmpty, "Expected fixture sshd to respond through local forward after client banner.")
        }
    }

    func testPrivateKeyLoginClosesLocalForwardBeforeNextCommand() throws {
        try requireLiveTestsEnabled()

        try withPrivateKeyConnection { connection in
            let fixture = try AlpineSSHFixture()
            let forward = try startLocalForward(remoteHost: "127.0.0.1", remotePort: fixture.remoteSSHDPort, on: connection)

            try close(forward)
            let result = try execute("printf forward-closed", on: connection)
            XCTAssertEqual(String(data: result.standardOutput, encoding: .utf8), "forward-closed")
        }
    }

    private func openDirectTCPChannel(host: String, port: UInt16, on connection: SSHConnection) throws -> SSHTunnelChannel {
        let expectation = expectation(description: "Open direct TCP channel")
        var openResult: Result<SSHTunnelChannel, SSHKitError>?
        LiveSSHLog.event("direct-tcp start host=\(host) port=\(port)")
        connection.openDirectTCPChannel(host: host, port: port, callbackQueue: .main) { result in
            LiveSSHLog.event("direct-tcp \(result.liveDiagnosticStatus)")
            openResult = result
            expectation.fulfill()
        }
        wait(for: [expectation], timeout: 15)
        return try XCTUnwrap(openResult).get()
    }

    private func readBanner(from channel: SSHTunnelChannel) throws -> String {
        let expectation = expectation(description: "Read fixture sshd banner through direct TCP channel")
        var readResult: Result<Data, SSHKitError>?
        channel.read(maximumLength: 512, callbackQueue: .main) { result in
            readResult = result
            expectation.fulfill()
        }
        wait(for: [expectation], timeout: 15)
        let data = try XCTUnwrap(readResult).get()
        return String(data: data, encoding: .utf8) ?? ""
    }

    private func readData(from channel: SSHTunnelChannel) throws -> Data {
        let expectation = expectation(description: "Read fixture sshd response through direct TCP channel")
        var readResult: Result<Data, SSHKitError>?
        channel.read(maximumLength: 512, callbackQueue: .main) { result in
            readResult = result
            expectation.fulfill()
        }
        wait(for: [expectation], timeout: 15)
        return try XCTUnwrap(readResult).get()
    }

    private func writeClientBanner(to channel: SSHTunnelChannel) throws {
        let expectation = expectation(description: "Write client SSH banner through direct TCP channel")
        var writeResult: Result<Void, SSHKitError>?
        channel.write(Data("SSH-2.0-SSHKitForwardRoundTrip_1.0\r\n".utf8), callbackQueue: .main) { result in
            writeResult = result
            expectation.fulfill()
        }
        wait(for: [expectation], timeout: 15)
        try XCTUnwrap(writeResult).get()
    }

    private func close(_ channel: SSHTunnelChannel) throws {
        let expectation = expectation(description: "Close direct TCP channel")
        var closeResult: Result<Void, SSHKitError>?
        LiveSSHLog.event("direct-tcp close start")
        channel.close(callbackQueue: .main) { result in
            LiveSSHLog.event("direct-tcp close \(result.liveDiagnosticStatus)")
            closeResult = result
            expectation.fulfill()
        }
        wait(for: [expectation], timeout: 15)
        try XCTUnwrap(closeResult).get()
    }

    private func startLocalForward(remoteHost: String, remotePort: UInt16, on connection: SSHConnection) throws -> SSHPortForward {
        let expectation = expectation(description: "Start local SSH forward")
        var forwardResult: Result<SSHPortForward, SSHKitError>?
        LiveSSHLog.event("local-forward start remoteHost=\(remoteHost) remotePort=\(remotePort)")
        connection.startLocalForward(localHost: "127.0.0.1", localPort: 0, remoteHost: remoteHost, remotePort: remotePort, callbackQueue: .main) { result in
            LiveSSHLog.event("local-forward \(result.liveDiagnosticStatus)")
            forwardResult = result
            expectation.fulfill()
        }
        wait(for: [expectation], timeout: 15)
        return try XCTUnwrap(forwardResult).get()
    }

    private func close(_ forward: SSHPortForward) throws {
        let expectation = expectation(description: "Close local SSH forward")
        var closeResult: Result<Void, SSHKitError>?
        LiveSSHLog.event("local-forward close start")
        forward.close(callbackQueue: .main) { result in
            LiveSSHLog.event("local-forward close \(result.liveDiagnosticStatus)")
            closeResult = result
            expectation.fulfill()
        }
        wait(for: [expectation], timeout: 15)
        try XCTUnwrap(closeResult).get()
    }

    private func execute(_ command: String, on connection: SSHConnection) throws -> SSHCommandResult {
        let expectation = expectation(description: "Execute command after local forward closes")
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

    private func readBannerFromLocalForward(host: String, port: UInt16) throws -> String {
        let fileDescriptor = try connectLocalTCP(host: host, port: port)
        defer {
            Darwin.close(fileDescriptor)
        }

        return try readString(from: fileDescriptor)
    }

    private func roundTripSSHHandshakeThroughLocalForward(host: String, port: UInt16) throws -> Data {
        let fileDescriptor = try connectLocalTCP(host: host, port: port)
        defer {
            Darwin.close(fileDescriptor)
        }

        let banner = try readString(from: fileDescriptor)
        XCTAssertTrue(banner.hasPrefix("SSH-2.0-"), "Expected SSH banner through local forward, received: \(banner)")

        try writeAll(Array("SSH-2.0-SSHKitForwardRoundTrip_1.0\r\n".utf8), to: fileDescriptor)
        return try readData(from: fileDescriptor)
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
            ai_next: nil,
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

    private func readString(from socket: Int32) throws -> String {
        let data = try readData(from: socket)
        return String(data: data, encoding: .utf8) ?? ""
    }

    private func readData(from socket: Int32) throws -> Data {
        var buffer = [UInt8](repeating: 0, count: 512)
        let byteCount = Darwin.read(socket, &buffer, buffer.count)
        try requirePositiveRead(byteCount)
        return Data(buffer.prefix(byteCount))
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

    private func requirePositiveRead(_ byteCount: Int) throws {
        if byteCount < 0 {
            throw NSError(domain: NSPOSIXErrorDomain, code: Int(errno), userInfo: [NSLocalizedDescriptionKey: String(cString: strerror(errno))])
        }
        if byteCount == 0 {
            throw NSError(domain: NSPOSIXErrorDomain, code: 0, userInfo: [NSLocalizedDescriptionKey: "Unexpected EOF while reading fixture banner."])
        }
    }
}
