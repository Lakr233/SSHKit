import Foundation
import SSHKit
import XCTest

final class AlpineSSHFixtureTests: XCTestCase {
    func testPasswordLoginExecutesSmokeCommand() throws {
        try requireLiveTestsEnabled()

        let connection = try connect(
            authentication: .password(AlpineSSHFixture.password),
            knownHostsPath: makeKnownHostsFile(),
        )

        do {
            let result = try awaitSmokeCommand(on: connection)
            try close(connection)
            assertSmokeCommandResult(result)
        } catch {
            do {
                try close(connection)
            } catch {
                XCTFail("Closing connection after password smoke test failure failed: \(error)")
            }
            throw error
        }
    }

    func testPrivateKeyLoginExecutesSmokeCommand() throws {
        try requireLiveTestsEnabled()

        let connection = try connect(
            authentication: .privateKeyFile(path: makePrivateKeyFile()),
            knownHostsPath: makeKnownHostsFile(),
        )

        do {
            let result = try awaitSmokeCommand(on: connection)
            try close(connection)
            assertSmokeCommandResult(result)
        } catch {
            do {
                try close(connection)
            } catch {
                XCTFail("Closing connection after private-key smoke test failure failed: \(error)")
            }
            throw error
        }
    }

    private func requireLiveTestsEnabled() throws {
        guard ProcessInfo.processInfo.environment["SSHKIT_RUN_LIVE_TESTS"] == "1" else {
            throw XCTSkip("Set SSHKIT_RUN_LIVE_TESTS=1 to run Alpine SSH live fixture tests.")
        }
    }

    private func connect(
        authentication: SSHAuthentication,
        knownHostsPath: String,
    ) throws -> SSHConnection {
        let configuration = SSHClientConfiguration(
            host: AlpineSSHFixture.host,
            port: AlpineSSHFixture.port,
            username: AlpineSSHFixture.username,
            authentication: authentication,
            hostKeyPolicy: .knownHostsFile(knownHostsPath),
            timeout: 10,
        )

        let expectation = expectation(description: "Connect to Alpine SSH fixture")
        var connectionResult: Result<SSHConnection, SSHKitError>?

        SSHClient.connect(configuration: configuration, callbackQueue: .main) { result in
            connectionResult = result
            expectation.fulfill()
        }

        wait(for: [expectation], timeout: 15)
        return try XCTUnwrap(connectionResult).get()
    }

    private func makeKnownHostsFile() throws -> String {
        let fileURL = try makeTemporaryDirectory().appendingPathComponent("known_hosts")
        try AlpineSSHFixture.knownHostsEntry.write(to: fileURL, atomically: true, encoding: .utf8)
        return fileURL.path
    }

    private func makePrivateKeyFile() throws -> String {
        let fileURL = try makeTemporaryDirectory().appendingPathComponent("fixture_client_ed25519")
        try AlpineSSHFixture.privateKey.write(to: fileURL, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: fileURL.path)
        return fileURL.path
    }

    private func makeTemporaryDirectory() throws -> URL {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("SSHKitLiveTests")
            .appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        addTeardownBlock {
            try FileManager.default.removeItem(at: directory)
        }
        return directory
    }

    private func assertSmokeCommandResult(_ result: SSHCommandResult) {
        XCTAssertEqual(result.exitStatus, 0)
        XCTAssertEqual(result.standardError, Data())
        XCTAssertEqual(String(data: result.standardOutput, encoding: .utf8), "root\n3.21.7\n")
    }

    private func awaitSmokeCommand(on connection: SSHConnection) throws -> SSHCommandResult {
        let expectation = expectation(description: "Execute Alpine SSH smoke command")
        var commandResult: Result<SSHCommandResult, SSHKitError>?

        connection.execute("whoami && cat /etc/alpine-release", callbackQueue: .main) { result in
            commandResult = result
            expectation.fulfill()
        }

        wait(for: [expectation], timeout: 15)
        return try XCTUnwrap(commandResult).get()
    }

    private func close(_ connection: SSHConnection) throws {
        let expectation = expectation(description: "Close Alpine SSH fixture connection")
        var closeResult: Result<Void, SSHKitError>?

        connection.close(callbackQueue: .main) { result in
            closeResult = result
            expectation.fulfill()
        }

        wait(for: [expectation], timeout: 15)
        try XCTUnwrap(closeResult).get()
    }
}

private enum AlpineSSHFixture {
    static let host = requiredEnvironmentValue("SSHKIT_LIVE_HOST")
    static let port = UInt16(requiredEnvironmentValue("SSHKIT_LIVE_PORT"))!
    static let username = requiredEnvironmentValue("SSHKIT_LIVE_USERNAME")
    static let password = requiredEnvironmentValue("SSHKIT_LIVE_PASSWORD")
    static let knownHostsEntry = requiredEnvironmentValue("SSHKIT_LIVE_KNOWN_HOSTS")
    static let privateKey = requiredEnvironmentValue("SSHKIT_LIVE_PRIVATE_KEY")

    private static func requiredEnvironmentValue(_ name: String) -> String {
        guard let value = ProcessInfo.processInfo.environment[name], value.isEmpty == false else {
            fatalError("Missing required live SSH test environment value: \(name)")
        }
        return value
    }
}
