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
            XCTAssertTrue(entries.contains { $0.filename == remoteFilename })
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

    func testPrivateKeyLoginPerformsFullDirectoryAndFileLifecycle() throws {
        try requireLiveTestsEnabled()

        try withPrivateKeyConnection { connection in
            let sftp = try openSFTP(on: connection)
            let fixtureID = UUID().uuidString
            let directory = "/tmp/sshkit-sftp-lifecycle-\(fixtureID)"
            let file = "\(directory)/payload.txt"
            let renamedFile = "\(directory)/renamed.txt"
            let link = "\(directory)/payload-link"
            let resumeUploadFile = "\(directory)/resume-upload.txt"
            let payload = Data("sshkit-sftp-lifecycle-\(fixtureID)\n".utf8)
            let localDirectory = try makeLocalDirectory()
            let resumeDownloadURL = localDirectory.appendingPathComponent("resume-download.txt")
            let resumeUploadURL = localDirectory.appendingPathComponent("resume-upload.txt")
            try payload.write(to: resumeUploadURL)

            do {
                let tmpRealpath = try realpath("/tmp", using: sftp)
                XCTAssertFalse(tmpRealpath.isEmpty)
                try createDirectory(directory, using: sftp)
                try writeFileWithHandle(payload, to: file, using: sftp)
                let attributes = try stat(file, using: sftp)
                XCTAssertEqual(attributes.size, UInt64(payload.count))
                XCTAssertEqual(try readFileWithHandle(file, using: sftp), payload)
                try Data(payload.prefix(8)).write(to: resumeDownloadURL)
                try resumeDownload(file, to: resumeDownloadURL, using: sftp)
                XCTAssertEqual(try Data(contentsOf: resumeDownloadURL), payload)
                try writeFile(Data(payload.prefix(10)), to: resumeUploadFile, using: sftp)
                try resumeUpload(resumeUploadURL, to: resumeUploadFile, using: sftp)
                XCTAssertEqual(try readFile(resumeUploadFile, using: sftp), payload)
                try setPermissions(0o600, at: file, using: sftp)
                XCTAssertEqual(try stat(file, using: sftp).permissions & 0o777, 0o600)
                try rename(file, to: renamedFile, using: sftp)
                try createSymbolicLink(link, targetPath: renamedFile, using: sftp)
                XCTAssertEqual(try readLink(link, using: sftp), renamedFile)
                _ = try lstat(link, using: sftp)
                XCTAssertFalse(try fileSystemAttributes(at: directory, using: sftp).isEmpty)
                try removeFile(link, using: sftp)
                try removeFile(renamedFile, using: sftp)
                try removeFile(resumeUploadFile, using: sftp)
                try removeDirectory(directory, using: sftp)
                try close(sftp)
            } catch {
                try? close(sftp)
                try? removeRemoteTree(directory, on: connection)
                throw error
            }
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

    private func resumeDownload(_ remotePath: String, to localURL: URL, using sftp: SFTPClient) throws {
        try waitForSFTPVoid("Resume SFTP download") { completion in
            sftp.resumeDownload(remotePath: remotePath, to: localURL, callbackQueue: .main, completion: completion)
        }
    }

    private func resumeUpload(_ localURL: URL, to remotePath: String, using sftp: SFTPClient) throws {
        try waitForSFTPVoid("Resume SFTP upload") { completion in
            sftp.resumeUpload(localURL: localURL, to: remotePath, callbackQueue: .main, completion: completion)
        }
    }

    private func realpath(_ path: String, using sftp: SFTPClient) throws -> String {
        try waitForSFTPValue("Resolve SFTP realpath") { completion in
            sftp.realpath(path, callbackQueue: .main, completion: completion)
        }
    }

    private func stat(_ path: String, using sftp: SFTPClient) throws -> SFTPAttributes {
        try waitForSFTPValue("Stat SFTP path") { completion in
            sftp.stat(path, callbackQueue: .main, completion: completion)
        }
    }

    private func lstat(_ path: String, using sftp: SFTPClient) throws -> SFTPAttributes {
        try waitForSFTPValue("Lstat SFTP path") { completion in
            sftp.lstat(path, callbackQueue: .main, completion: completion)
        }
    }

    private func fileSystemAttributes(at path: String, using sftp: SFTPClient) throws -> [String: UInt64] {
        try waitForSFTPValue("Stat SFTP filesystem") { completion in
            sftp.fileSystemAttributes(at: path, callbackQueue: .main, completion: completion)
        }
    }

    private func readLink(_ path: String, using sftp: SFTPClient) throws -> String {
        try waitForSFTPValue("Read SFTP link") { completion in
            sftp.readLink(path, callbackQueue: .main, completion: completion)
        }
    }

    private func readFile(_ path: String, using sftp: SFTPClient) throws -> Data {
        try waitForSFTPValue("Read SFTP file") { completion in
            sftp.readFile(path, callbackQueue: .main, completion: completion)
        }
    }

    private func writeFileWithHandle(_ data: Data, to path: String, using sftp: SFTPClient) throws {
        let handle = try openFile(path, flags: [.write, .create, .truncate], using: sftp)
        do {
            try waitForSFTPVoid("Write SFTP file handle") { completion in
                handle.writeData(data, callbackQueue: .main, completion: completion)
            }
            try close(handle)
        } catch {
            try? close(handle)
            throw error
        }
    }

    private func readFileWithHandle(_ path: String, using sftp: SFTPClient) throws -> Data {
        let handle = try openFile(path, flags: [.read], using: sftp)
        var chunks = Data()
        do {
            while true {
                let chunk = try waitForSFTPValue("Read SFTP file handle") { completion in
                    handle.readData(maximumLength: 7, callbackQueue: .main, completion: completion)
                }
                if chunk.isEmpty {
                    break
                }
                chunks.append(chunk)
            }
            try close(handle)
            return chunks
        } catch {
            try? close(handle)
            throw error
        }
    }

    private func openFile(_ path: String, flags: SFTPFileOpenFlags, using sftp: SFTPClient) throws -> SFTPFileHandle {
        try waitForSFTPValue("Open SFTP file handle") { completion in
            sftp.openFile(path, flags: flags, callbackQueue: .main, completion: completion)
        }
    }

    private func close(_ handle: SFTPFileHandle) throws {
        try waitForSFTPVoid("Close SFTP file handle") { completion in
            handle.close(callbackQueue: .main, completion: completion)
        }
    }

    private func createDirectory(_ path: String, using sftp: SFTPClient) throws {
        try waitForSFTPVoid("Create SFTP directory") { completion in
            sftp.createDirectory(path, callbackQueue: .main, completion: completion)
        }
    }

    private func setPermissions(_ permissions: UInt32, at path: String, using sftp: SFTPClient) throws {
        try waitForSFTPVoid("Set SFTP permissions") { completion in
            sftp.setPermissions(permissions, at: path, callbackQueue: .main, completion: completion)
        }
    }

    private func writeFile(_ data: Data, to path: String, using sftp: SFTPClient) throws {
        try waitForSFTPVoid("Write SFTP file") { completion in
            sftp.writeFile(data, to: path, callbackQueue: .main, completion: completion)
        }
    }

    private func rename(_ sourcePath: String, to destinationPath: String, using sftp: SFTPClient) throws {
        try waitForSFTPVoid("Rename SFTP path") { completion in
            sftp.rename(sourcePath, to: destinationPath, callbackQueue: .main, completion: completion)
        }
    }

    private func createSymbolicLink(_ linkPath: String, targetPath: String, using sftp: SFTPClient) throws {
        try waitForSFTPVoid("Create SFTP symlink") { completion in
            sftp.createSymbolicLink(linkPath, targetPath: targetPath, callbackQueue: .main, completion: completion)
        }
    }

    private func removeFile(_ path: String, using sftp: SFTPClient) throws {
        try waitForSFTPVoid("Remove SFTP file") { completion in
            sftp.removeFile(path, callbackQueue: .main, completion: completion)
        }
    }

    private func removeDirectory(_ path: String, using sftp: SFTPClient) throws {
        try waitForSFTPVoid("Remove SFTP directory") { completion in
            sftp.removeDirectory(path, callbackQueue: .main, completion: completion)
        }
    }

    private func waitForSFTPValue<Value>(
        _ description: String,
        operation: (@escaping (Result<Value, SSHKitError>) -> Void) -> Void
    ) throws -> Value {
        let expectation = expectation(description: description)
        var result: Result<Value, SSHKitError>?
        operation { operationResult in
            result = operationResult
            expectation.fulfill()
        }
        wait(for: [expectation], timeout: 30)
        return try XCTUnwrap(result).get()
    }

    private func waitForSFTPVoid(
        _ description: String,
        operation: (@escaping (Result<Void, SSHKitError>) -> Void) -> Void
    ) throws {
        let expectation = expectation(description: description)
        var result: Result<Void, SSHKitError>?
        operation { operationResult in
            result = operationResult
            expectation.fulfill()
        }
        wait(for: [expectation], timeout: 30)
        try XCTUnwrap(result).get()
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

    private func removeRemoteTree(_ remotePath: String, on connection: SSHConnection) throws {
        let expectation = expectation(description: "Remove SFTP remote fixture tree")
        var commandResult: Result<SSHCommandResult, SSHKitError>?
        connection.execute("rm -rf \(shellQuoted(remotePath))", callbackQueue: .main) { result in
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
