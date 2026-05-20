import Foundation
import SSHKit
import XCTest

final class AlpineSSHFixtureTests: XCTestCase {
    func testPasswordLoginExecutesSmokeCommand() throws {
        try requireLiveTestsEnabled()

        let fixture = try AlpineSSHFixture()
        let connection = try connect(
            authentication: .password(fixture.password),
            fixture: fixture,
            knownHostsPath: makeKnownHostsFile(fixture: fixture),
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

        let fixture = try AlpineSSHFixture()
        let connection = try connect(
            authentication: .privateKeyFile(path: makePrivateKeyFile(fixture: fixture)),
            fixture: fixture,
            knownHostsPath: makeKnownHostsFile(fixture: fixture),
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
        fixture: AlpineSSHFixture,
        knownHostsPath: String,
    ) throws -> SSHConnection {
        let configuration = SSHClientConfiguration(
            host: fixture.host,
            port: fixture.port,
            username: fixture.username,
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

    private func makeKnownHostsFile(fixture: AlpineSSHFixture) throws -> String {
        let fileURL = try makeTemporaryDirectory().appendingPathComponent("known_hosts")
        try fixture.knownHostsEntry.appending("\n").write(to: fileURL, atomically: true, encoding: .utf8)
        return fileURL.path
    }

    private func makePrivateKeyFile(fixture: AlpineSSHFixture) throws -> String {
        let fileURL = try makeTemporaryDirectory().appendingPathComponent("fixture_client_ed25519")
        try fixture.privateKey.appending("\n").write(to: fileURL, atomically: true, encoding: .utf8)
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
        XCTAssertEqual(String(data: result.standardOutput, encoding: .utf8), "root\n3.21.7\n")
        let standardError = String(data: result.standardError, encoding: .utf8) ?? ""
        XCTAssertFalse(standardError.localizedCaseInsensitiveContains("permission denied"))
        XCTAssertFalse(standardError.localizedCaseInsensitiveContains("verification failed"))
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

private struct AlpineSSHFixture {
    var host: String
    var port: UInt16
    var username: String
    var password: String
    var knownHostsEntry: String
    var privateKey: String

    init() throws {
        host = try Self.requiredEnvironmentValue("SSHKIT_LIVE_HOST")
        port = try UInt16(Self.requiredEnvironmentValue("SSHKIT_LIVE_PORT")).unwrap("SSHKIT_LIVE_PORT must be a valid UInt16.")
        username = try Self.requiredEnvironmentValue("SSHKIT_LIVE_USERNAME")
        password = try Self.requiredEnvironmentValue("SSHKIT_LIVE_PASSWORD")
        knownHostsEntry = try Self.requiredEnvironmentValue("SSHKIT_LIVE_KNOWN_HOSTS")
        privateKey = try Self.requiredEnvironmentValue("SSHKIT_LIVE_PRIVATE_KEY")
    }

    private static func requiredEnvironmentValue(_ name: String) throws -> String {
        guard let value = ProcessInfo.processInfo.environment[name], value.isEmpty == false else {
            throw XCTSkip("Missing required live SSH test environment value: \(name)")
        }
        return value
    }
}

private extension Optional {
    func unwrap(_ message: String) throws -> Wrapped {
        guard let wrapped = self else {
            throw XCTSkip(message)
        }
        return wrapped
    }
}
