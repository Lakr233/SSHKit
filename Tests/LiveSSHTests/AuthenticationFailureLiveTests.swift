import Foundation
import SSHKit
import XCTest

final class AuthenticationFailureLiveTests: LiveSSHTestCase {
    func testWrongPasswordReturnsAuthenticationFailureAgainstFixture() async throws {
        try requireLiveTestsEnabled()

        let fixture = try AlpineSSHFixture()
        do {
            let connection = try await SSHClient.connect(configuration: SSHClientConfiguration(
                host: fixture.host,
                port: fixture.port,
                username: fixture.username,
                authentication: .password("wrong-\(UUID().uuidString)"),
                hostKeyPolicy: .knownHostsFile(makeKnownHostsFile(fixture: fixture)),
                timeout: 10
            ))
            try await connection.close()
            XCTFail("Wrong password connected successfully.")
        } catch let error as SSHKitError {
            XCTAssertEqual(error.code, SSHKitErrorCode.authenticationFailed.rawValue)
        }
    }

    func testKnownHostsMismatchReturnsHostKeyFailureAgainstFixture() async throws {
        try requireLiveTestsEnabled()

        let fixture = try AlpineSSHFixture()
        do {
            let connection = try await SSHClient.connect(configuration: SSHClientConfiguration(
                host: fixture.host,
                port: fixture.port,
                username: fixture.username,
                authentication: .privateKeyFile(path: makePrivateKeyFile(fixture: fixture)),
                hostKeyPolicy: .knownHostsFile(makeMismatchedKnownHostsFile(fixture: fixture)),
                timeout: 10
            ))
            try await connection.close()
            XCTFail("Known-hosts mismatch connected successfully.")
        } catch let error as SSHKitError {
            XCTAssertEqual(error.code, SSHKitErrorCode.hostKeyVerificationFailed.rawValue)
        }
    }

    private func makeMismatchedKnownHostsFile(fixture: AlpineSSHFixture) throws -> String {
        var entry = fixture.knownHostsEntry
        guard let mutationIndex = entry.lastIndex(where: { $0.isLetter || $0.isNumber }) else {
            XCTFail("Fixture known_hosts entry has no key material to mutate.")
            return try makeKnownHostsFile(fixture: fixture)
        }

        let replacement: Character = entry[mutationIndex] == "A" ? "B" : "A"
        entry.replaceSubrange(mutationIndex ... mutationIndex, with: String(replacement))

        let fileURL = try makeTemporaryDirectory().appendingPathComponent("mismatched_known_hosts")
        try entry.appending("\n").write(to: fileURL, atomically: true, encoding: .utf8)
        return fileURL.path
    }
}
