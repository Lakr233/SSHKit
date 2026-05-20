import SSHKit
import XCTest

final class DirectTCPForwardLiveTests: LiveSSHTestCase {
    func testPrivateKeyLoginOpensDirectTCPChannelToFixtureSSHD() throws {
        try requireLiveTestsEnabled()

        try withPrivateKeyConnection { connection in
            let fixture = try AlpineSSHFixture()
            let channel = try openDirectTCPChannel(host: "127.0.0.1", port: fixture.port, on: connection)
            defer {
                try? close(channel)
            }

            let banner = try readBanner(from: channel)
            XCTAssertTrue(banner.hasPrefix("SSH-2.0-"), "Expected SSH banner from fixture sshd, received: \(banner)")
        }
    }

    private func openDirectTCPChannel(host: String, port: UInt16, on connection: SSHConnection) throws -> SSHTunnelChannel {
        let expectation = expectation(description: "Open direct TCP channel")
        var openResult: Result<SSHTunnelChannel, SSHKitError>?
        connection.openDirectTCPChannel(host: host, port: port, callbackQueue: .main) { result in
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

    private func close(_ channel: SSHTunnelChannel) throws {
        let expectation = expectation(description: "Close direct TCP channel")
        var closeResult: Result<Void, SSHKitError>?
        channel.close(callbackQueue: .main) { result in
            closeResult = result
            expectation.fulfill()
        }
        wait(for: [expectation], timeout: 15)
        try XCTUnwrap(closeResult).get()
    }
}
