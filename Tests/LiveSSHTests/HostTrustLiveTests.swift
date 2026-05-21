import SSHKit
import XCTest

final class HostTrustLiveTests: LiveSSHTestCase {
    func testPinnedFingerprintAcceptsFixtureHostKey() async throws {
        try requireLiveTestsEnabled()

        let fixture = try AlpineSSHFixture()
        let fingerprint = try await discoverFixtureFingerprint(fixture: fixture)
        let connection = try await SSHClient.connect(configuration: privateKeyConfiguration(
            fixture: fixture,
            hostKeyPolicy: .pinnedFingerprint(fingerprint),
        ))

        XCTAssertEqual(connection.hostKeyFingerprint, fingerprint)
        let result = try await connection.execute("whoami && cat /etc/alpine-release")
        try await connection.close()
        assertSmokeCommandResult(result)
    }

    func testPinnedFingerprintRejectsMismatchedFixtureHostKey() async throws {
        try requireLiveTestsEnabled()

        let fixture = try AlpineSSHFixture()
        do {
            let connection = try await SSHClient.connect(configuration: privateKeyConfiguration(
                fixture: fixture,
                hostKeyPolicy: .pinnedFingerprint(SSHHostKeyFingerprint("mismatched")),
            ))
            try await connection.close()
            XCTFail("Pinned fingerprint mismatch unexpectedly connected.")
        } catch let error as SSHKitError {
            XCTAssertEqual(error.code, SSHKitErrorCode.hostKeyVerificationFailed.rawValue)
        }
    }

    func testMemoryTrustStoreAcceptsFixtureHostKey() async throws {
        try requireLiveTestsEnabled()

        let fixture = try AlpineSSHFixture()
        let fingerprint = try await discoverFixtureFingerprint(fixture: fixture)
        let store = SSHMemoryHostTrustStore()
        try store.saveFingerprint(fingerprint, host: fixture.host, port: fixture.port)

        let connection = try await SSHClient.connect(configuration: privateKeyConfiguration(
            fixture: fixture,
            hostKeyPolicy: .trustStore(store),
        ))

        XCTAssertEqual(connection.hostKeyFingerprint, fingerprint)
        let result = try await connection.execute("whoami && cat /etc/alpine-release")
        try await connection.close()
        assertSmokeCommandResult(result)
    }

    func testMemoryTrustStoreRejectsMissingFixtureHostKey() async throws {
        try requireLiveTestsEnabled()

        let fixture = try AlpineSSHFixture()
        do {
            let connection = try await SSHClient.connect(configuration: privateKeyConfiguration(
                fixture: fixture,
                hostKeyPolicy: .trustStore(SSHMemoryHostTrustStore()),
            ))
            try await connection.close()
            XCTFail("Missing trust-store fingerprint unexpectedly connected.")
        } catch let error as SSHKitError {
            XCTAssertEqual(error.code, SSHKitErrorCode.hostKeyVerificationFailed.rawValue)
        }
    }

    private func discoverFixtureFingerprint(fixture: AlpineSSHFixture) async throws -> SSHHostKeyFingerprint {
        let connection = try await SSHClient.connect(configuration: privateKeyConfiguration(
            fixture: fixture,
            hostKeyPolicy: .insecureAcceptAnyHostKey,
        ))
        let fingerprint = try XCTUnwrap(connection.hostKeyFingerprint)
        try await connection.close()
        return fingerprint
    }

    private func privateKeyConfiguration(
        fixture: AlpineSSHFixture,
        hostKeyPolicy: SSHHostKeyPolicy,
    ) throws -> SSHClientConfiguration {
        try SSHClientConfiguration(
            host: fixture.host,
            port: fixture.port,
            username: fixture.username,
            authentication: .privateKeyFile(path: makePrivateKeyFile(fixture: fixture)),
            hostKeyPolicy: hostKeyPolicy,
            timeout: 10,
        )
    }
}
