import Foundation
import SSHKit
import XCTest

final class ScopedConnectionLiveTests: LiveSSHTestCase {
    func testWithConnectionClosesFixtureConnectionAfterSuccess() async throws {
        try requireLiveTestsEnabled()

        let fixture = try AlpineSSHFixture()
        var scopedConnection: SSHConnection?
        let result = try await SSHClient.withConnection(privateKeyConfiguration(fixture: fixture)) { connection in
            scopedConnection = connection
            return try await connection.execute("printf scoped-success")
        }

        XCTAssertEqual(String(data: result.standardOutput, encoding: .utf8), "scoped-success")
        try await assertConnectionIsClosed(XCTUnwrap(scopedConnection))
    }

    func testWithConnectionClosesFixtureConnectionAfterThrow() async throws {
        try requireLiveTestsEnabled()

        let fixture = try AlpineSSHFixture()
        var scopedConnection: SSHConnection?
        do {
            try await SSHClient.withConnection(privateKeyConfiguration(fixture: fixture)) { connection in
                scopedConnection = connection
                throw ScopedConnectionFailure.expected
            }
            XCTFail("Scoped fixture operation completed successfully.")
        } catch ScopedConnectionFailure.expected {
            try await assertConnectionIsClosed(XCTUnwrap(scopedConnection))
        }
    }

    private enum ScopedConnectionFailure: Error {
        case expected
    }

    private func privateKeyConfiguration(fixture: AlpineSSHFixture) throws -> SSHClientConfiguration {
        try SSHClientConfiguration(
            host: fixture.host,
            port: fixture.port,
            username: fixture.username,
            authentication: .privateKeyFile(path: makePrivateKeyFile(fixture: fixture)),
            hostKeyPolicy: .knownHostsFile(makeKnownHostsFile(fixture: fixture)),
            timeout: 10
        )
    }

    private func assertConnectionIsClosed(
        _ connection: SSHConnection,
        file: StaticString = #filePath,
        line: UInt = #line
    ) async throws {
        do {
            _ = try await connection.execute("true")
            XCTFail("Scoped fixture connection accepted a command after close.", file: file, line: line)
        } catch let error as SSHKitError {
            XCTAssertEqual(error.code, SSHKitErrorCode.invalidState.rawValue, file: file, line: line)
        } catch {
            XCTFail("Closed scoped fixture connection returned unexpected error: \(error)", file: file, line: line)
        }
    }
}
