import Foundation
import SSHKit
import XCTest

final class DropbearLiveTests: LiveSSHTestCase {
    func testPasswordLoginExecutesCommandAgainstDropbearFixture() async throws {
        try requireLiveTestsEnabled()

        let fixture = try DropbearSSHFixture()
        let knownHostsPath = try makeKnownHostsFile(entry: fixture.knownHostsEntry)
        let configuration = SSHClientConfiguration(
            host: fixture.host,
            port: fixture.port,
            username: fixture.username,
            authentication: .password(fixture.password),
            hostKeyPolicy: .knownHostsFile(knownHostsPath),
            timeout: 10
        )
        let connection = try await SSHClient.connect(configuration: configuration)

        do {
            let result = try await connection.execute("printf 'dropbear-ok\\n'")
            try await connection.close()
            XCTAssertEqual(result.exitStatus, 0)
            XCTAssertEqual(String(data: result.standardOutput, encoding: .utf8), "dropbear-ok\n")
            XCTAssertEqual(result.standardError, Data())
        } catch {
            try? await connection.close()
            throw error
        }
    }

    func testWrongPasswordReturnsAuthenticationFailureAgainstDropbearFixture() async throws {
        try requireLiveTestsEnabled()

        let fixture = try DropbearSSHFixture()
        let configuration = try SSHClientConfiguration(
            host: fixture.host,
            port: fixture.port,
            username: fixture.username,
            authentication: .password("\(fixture.password)-wrong"),
            hostKeyPolicy: .knownHostsFile(makeKnownHostsFile(entry: fixture.knownHostsEntry)),
            timeout: 10
        )

        do {
            let connection = try await SSHClient.connect(configuration: configuration)
            try await connection.close()
            XCTFail("Wrong-password Dropbear fixture authentication unexpectedly connected.")
        } catch let error as SSHKitError {
            XCTAssertEqual(error.code, SSHKitErrorCode.authenticationFailed.rawValue)
        }
    }

    func testKnownHostsMismatchReturnsHostKeyFailureAgainstDropbearFixture() async throws {
        try requireLiveTestsEnabled()

        let fixture = try DropbearSSHFixture()
        let configuration = try SSHClientConfiguration(
            host: fixture.host,
            port: fixture.port,
            username: fixture.username,
            authentication: .password(fixture.password),
            hostKeyPolicy: .knownHostsFile(makeKnownHostsFile(entry: mismatchedKnownHostsEntry(fixture.knownHostsEntry))),
            timeout: 10
        )

        do {
            let connection = try await SSHClient.connect(configuration: configuration)
            try await connection.close()
            XCTFail("Mismatched Dropbear fixture known-hosts entry unexpectedly connected.")
        } catch let error as SSHKitError {
            XCTAssertEqual(error.code, SSHKitErrorCode.hostKeyVerificationFailed.rawValue)
        }
    }

    private func makeKnownHostsFile(entry: String) throws -> String {
        let fileURL = try makeTemporaryDirectory().appendingPathComponent("dropbear_known_hosts")
        try entry.appending("\n").write(to: fileURL, atomically: true, encoding: .utf8)
        return fileURL.path
    }

    private func mismatchedKnownHostsEntry(_ entry: String) -> String {
        var mismatchedEntry = entry
        guard let mutationIndex = mismatchedEntry.lastIndex(where: { $0.isLetter || $0.isNumber }) else {
            XCTFail("Dropbear known_hosts entry has no key material to mutate.")
            return entry
        }

        let replacement: Character = mismatchedEntry[mutationIndex] == "A" ? "B" : "A"
        mismatchedEntry.replaceSubrange(mutationIndex ... mutationIndex, with: String(replacement))
        return mismatchedEntry
    }
}
