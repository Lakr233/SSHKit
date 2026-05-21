import Foundation
import SSHKit
import XCTest

final class SCPLiveTests: LiveSSHTestCase {
    func testPrivateKeyLoginUploadsAndDownloadsSingleFileWithSCP() async throws {
        try requireLiveTestsEnabled()

        let fixture = try AlpineSSHFixture()
        let connection = try await privateKeyConnection(fixture: fixture)
        defer {
            try? close(connection)
        }
        try await requireRemoteSCP(on: connection)

        let remotePath = "/tmp/sshkit-scp-\(UUID().uuidString).txt"

        let localSource = try makeSCPTemporaryDirectory().appendingPathComponent("scp-source.txt")
        let localDestination = try makeSCPTemporaryDirectory().appendingPathComponent("scp-destination.txt")
        let payload = "scp round trip \(UUID().uuidString)\n"
        try payload.write(to: localSource, atomically: true, encoding: .utf8)

        do {
            try await connection.uploadFileWithSCP(localURL: localSource, toRemotePath: remotePath, permissions: 0o640)
            let permissions = try await connection.execute("stat -c %a \(shellQuoted(remotePath))")
            let permissionText = try XCTUnwrap(String(data: permissions.standardOutput, encoding: .utf8))
            XCTAssertEqual(permissionText.trimmingCharacters(in: .whitespacesAndNewlines), "640")
            try await connection.downloadFileWithSCP(remotePath: remotePath, toLocalURL: localDestination)
            XCTAssertEqual(try String(contentsOf: localDestination, encoding: .utf8), payload)
            try await removeRemoteFile(remotePath, on: connection)
        } catch {
            try? await removeRemoteFile(remotePath, on: connection)
            throw error
        }
    }

    func testPrivateKeyLoginRejectsOversizedSCPReceive() async throws {
        try requireLiveTestsEnabled()

        let fixture = try AlpineSSHFixture()
        let connection = try await privateKeyConnection(fixture: fixture)
        defer {
            try? close(connection)
        }
        try await requireRemoteSCP(on: connection)

        let remotePath = "/tmp/sshkit-scp-oversized-\(UUID().uuidString).txt"

        _ = try await connection.execute("printf 'oversized' > \(shellQuoted(remotePath))")
        let localDestination = try makeSCPTemporaryDirectory().appendingPathComponent("oversized.txt")
        do {
            try await connection.downloadFileWithSCP(remotePath: remotePath, toLocalURL: localDestination, maximumSize: 1)
            XCTFail("Oversized SCP receive should fail.")
        } catch let error as SSHKitError {
            XCTAssertEqual(error.code, SSHKitErrorCode.commandFailed.rawValue)
            try await removeRemoteFile(remotePath, on: connection)
        } catch {
            try? await removeRemoteFile(remotePath, on: connection)
            throw error
        }
    }

    private func privateKeyConnection(fixture: AlpineSSHFixture) async throws -> SSHConnection {
        let configuration = try SSHClientConfiguration(
            host: fixture.host,
            port: fixture.port,
            username: fixture.username,
            authentication: .privateKeyFile(path: makePrivateKeyFile(fixture: fixture)),
            hostKeyPolicy: .knownHostsFile(makeKnownHostsFile(fixture: fixture)),
            timeout: 10
        )
        return try await SSHClient.connect(configuration: configuration)
    }

    private func requireRemoteSCP(on connection: SSHConnection) async throws {
        let result = try await connection.execute("command -v scp >/dev/null 2>&1")
        try requireLiveFixtureCapability(
            result.exitStatus == 0,
            "SCP live tests require scp on the fixture host."
        )
    }

    private func shellQuoted(_ value: String) -> String {
        "'\(value.replacingOccurrences(of: "'", with: "'\\''"))'"
    }

    private func removeRemoteFile(_ path: String, on connection: SSHConnection) async throws {
        _ = try await connection.execute("rm -f \(shellQuoted(path))")
    }

    private func makeSCPTemporaryDirectory() throws -> URL {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("SSHKitSCPLiveTests")
            .appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        return directory
    }
}
