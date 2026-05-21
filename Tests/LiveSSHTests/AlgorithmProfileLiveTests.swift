import Foundation
import SSHKit
import XCTest

final class AlgorithmProfileLiveTests: LiveSSHTestCase {
    func testLegacyRSAProfileAuthenticatesAgainstExternalFixture() throws {
        try requireLiveTestsEnabled()

        let fixture = try LegacyRSAFixture()
        let knownHostsPath = try makeKnownHostsFile(entry: fixture.knownHostsEntry)
        let configuration = SSHClientConfiguration(
            host: fixture.host,
            port: fixture.port,
            username: fixture.username,
            authentication: .password(fixture.password),
            hostKeyPolicy: .knownHostsFile(knownHostsPath),
            timeout: 10,
            algorithmProfile: .legacyRSA,
        )
        let connection = try connect(configuration: configuration)
        defer {
            try? close(connection)
        }

        let result = try runCommand("printf 'legacy-rsa-ok\\n'", on: connection)
        XCTAssertEqual(result.exitStatus, 0)
        XCTAssertEqual(String(data: result.standardOutput, encoding: .utf8), "legacy-rsa-ok\n")
    }

    private func makeKnownHostsFile(entry: String) throws -> String {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("SSHKitLegacyRSALiveTests")
            .appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        addTeardownBlock {
            try FileManager.default.removeItem(at: directory)
        }
        let fileURL = directory.appendingPathComponent("known_hosts")
        try entry.appending("\n").write(to: fileURL, atomically: true, encoding: .utf8)
        return fileURL.path
    }

    private func connect(configuration: SSHClientConfiguration) throws -> SSHConnection {
        let expectation = expectation(description: "Connect to external legacy RSA SSH fixture")
        var connectionResult: Result<SSHConnection, SSHKitError>?
        SSHClient.connect(configuration: configuration, callbackQueue: .main) { result in
            connectionResult = result
            expectation.fulfill()
        }
        wait(for: [expectation], timeout: 20)
        return try XCTUnwrap(connectionResult).get()
    }
}

private struct LegacyRSAFixture {
    var host: String
    var port: UInt16
    var username: String
    var password: String
    var knownHostsEntry: String

    init() throws {
        host = try Self.requiredEnvironmentValue("SSHKIT_LEGACY_RSA_HOST")
        try requireExternalFixtureHost(host)
        port = try UInt16(Self.requiredEnvironmentValue("SSHKIT_LEGACY_RSA_PORT"))
            .unwrap("SSHKIT_LEGACY_RSA_PORT must be a valid UInt16.")
        username = try Self.requiredEnvironmentValue("SSHKIT_LEGACY_RSA_USERNAME")
        password = try Self.requiredEnvironmentValue("SSHKIT_LEGACY_RSA_PASSWORD")
        knownHostsEntry = try Self.requiredEnvironmentValue("SSHKIT_LEGACY_RSA_KNOWN_HOSTS")
    }

    private static func requiredEnvironmentValue(_ name: String) throws -> String {
        guard let value = ProcessInfo.processInfo.environment[name], value.isEmpty == false else {
            throw LiveSSHFixtureError.missingEnvironment(name)
        }
        return value
    }
}
