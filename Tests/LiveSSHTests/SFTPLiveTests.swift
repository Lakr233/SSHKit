import Foundation
import SSHKit
import XCTest

final class SFTPLiveTests: LiveSSHTestCase {
    func testPrivateKeyLoginUploadsListsAndDownloadsFile() throws {
        try requireLiveTestsEnabled()

        try withPrivateKeyConnection { connection in
            try assertSFTPUploadListDownloadRoundTrip(on: connection)
        }
    }

    func testPasswordLoginUploadsListsAndDownloadsFile() throws {
        try requireLiveTestsEnabled()

        try withPasswordConnection { connection in
            try assertSFTPUploadListDownloadRoundTrip(on: connection)
        }
    }

    func testPrivateKeyLoginRejectsCommandWhileSFTPOpen() throws {
        try requireLiveTestsEnabled()

        try withPrivateKeyConnection { connection in
            let sftp = try openSFTP(on: connection)
            defer {
                try? close(sftp)
            }

            let commandExpectation = expectation(description: "Reject command while SFTP is open")
            var commandResult: Result<SSHCommandResult, SSHKitError>?
            connection.execute("true", callbackQueue: .main) { result in
                commandResult = result
                commandExpectation.fulfill()
            }
            wait(for: [commandExpectation], timeout: 15)
            XCTAssertThrowsError(try XCTUnwrap(commandResult).get()) { error in
                XCTAssertEqual((error as? SSHKitError)?.code, SSHKitErrorCode.invalidState.rawValue)
            }
        }
    }

    private func assertSFTPUploadListDownloadRoundTrip(on connection: SSHConnection) throws {
        let sftp = try openSFTP(on: connection)
        let fixtureID = UUID().uuidString
        let remoteFilename = "sshkit-sftp-\(fixtureID).txt"
        let remotePath = "/tmp/\(remoteFilename)"
        let localDirectory = try makeLocalDirectory()
        let uploadURL = localDirectory.appendingPathComponent("upload.txt")
        let downloadURL = localDirectory.appendingPathComponent("download.txt")
        let payload = "sshkit-sftp-round-trip-\(fixtureID)\n"
        try payload.write(to: uploadURL, atomically: true, encoding: .utf8)

        do {
            try upload(uploadURL, to: remotePath, using: sftp)
            let entries = try listDirectory("/tmp", using: sftp)
            XCTAssertTrue(entries.contains(SFTPEntry(filename: remoteFilename)))
            try download(remotePath, to: downloadURL, using: sftp)
            XCTAssertEqual(try String(contentsOf: downloadURL, encoding: .utf8), payload)
            try close(sftp)
            try removeRemoteFile(remotePath, on: connection)
        } catch {
            try? close(sftp)
            try? removeRemoteFile(remotePath, on: connection)
            throw error
        }
    }

    private func openSFTP(on connection: SSHConnection) throws -> SFTPClient {
        let expectation = expectation(description: "Open SFTP client")
        var openResult: Result<SFTPClient, SSHKitError>?
        connection.openSFTP(callbackQueue: .main) { result in
            openResult = result
            expectation.fulfill()
        }
        wait(for: [expectation], timeout: 15)
        return try XCTUnwrap(openResult).get()
    }

    private func upload(_ localURL: URL, to remotePath: String, using sftp: SFTPClient) throws {
        let expectation = expectation(description: "Upload SFTP file")
        var uploadResult: Result<Void, SSHKitError>?
        sftp.upload(localURL: localURL, to: remotePath, callbackQueue: .main) { result in
            uploadResult = result
            expectation.fulfill()
        }
        wait(for: [expectation], timeout: 30)
        try XCTUnwrap(uploadResult).get()
    }

    private func listDirectory(_ remotePath: String, using sftp: SFTPClient) throws -> [SFTPEntry] {
        let expectation = expectation(description: "List SFTP directory")
        var listResult: Result<[SFTPEntry], SSHKitError>?
        sftp.listDirectory(remotePath, callbackQueue: .main) { result in
            listResult = result
            expectation.fulfill()
        }
        wait(for: [expectation], timeout: 30)
        return try XCTUnwrap(listResult).get()
    }

    private func download(_ remotePath: String, to localURL: URL, using sftp: SFTPClient) throws {
        let expectation = expectation(description: "Download SFTP file")
        var downloadResult: Result<Void, SSHKitError>?
        sftp.download(remotePath: remotePath, to: localURL, callbackQueue: .main) { result in
            downloadResult = result
            expectation.fulfill()
        }
        wait(for: [expectation], timeout: 30)
        try XCTUnwrap(downloadResult).get()
    }

    private func removeRemoteFile(_ remotePath: String, on connection: SSHConnection) throws {
        let expectation = expectation(description: "Remove SFTP remote fixture file")
        var commandResult: Result<SSHCommandResult, SSHKitError>?
        connection.execute("rm -f \(shellQuoted(remotePath))", callbackQueue: .main) { result in
            commandResult = result
            expectation.fulfill()
        }
        wait(for: [expectation], timeout: 15)
        let result = try XCTUnwrap(commandResult).get()
        XCTAssertEqual(result.exitStatus, 0)
    }

    private func makeLocalDirectory() throws -> URL {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("SSHKitSFTPLiveTests")
            .appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        addTeardownBlock {
            try FileManager.default.removeItem(at: directory)
        }
        return directory
    }

    private func shellQuoted(_ value: String) -> String {
        "'\(value.replacingOccurrences(of: "'", with: "'\\''"))'"
    }
}
