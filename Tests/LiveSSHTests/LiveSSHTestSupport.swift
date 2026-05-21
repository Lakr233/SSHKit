import Foundation
import SSHKit
import XCTest

class LiveSSHTestCase: XCTestCase {
    func requireLiveTestsEnabled() throws {
        guard ProcessInfo.processInfo.environment["SSHKIT_RUN_LIVE_TESTS"] == "1" else {
            throw XCTSkip("Set SSHKIT_RUN_LIVE_TESTS=1 to run Alpine SSH live fixture tests.")
        }
    }

    func requireLiveFixtureCapability(
        _ condition: Bool,
        _ message: String,
    ) throws {
        guard condition else {
            throw LiveSSHFixtureError.missingCapability(message)
        }
    }

    func connect(
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

    func makeKnownHostsFile(fixture: AlpineSSHFixture) throws -> String {
        let fileURL = try makeTemporaryDirectory().appendingPathComponent("known_hosts")
        try fixture.knownHostsEntry.appending("\n").write(to: fileURL, atomically: true, encoding: .utf8)
        return fileURL.path
    }

    func makePrivateKeyFile(fixture: AlpineSSHFixture) throws -> String {
        let fileURL = try makeTemporaryDirectory().appendingPathComponent("fixture_client_ed25519")
        try fixture.privateKey.appending("\n").write(to: fileURL, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: fileURL.path)
        return fileURL.path
    }

    func assertSmokeCommandResult(_ result: SSHCommandResult) {
        XCTAssertEqual(result.exitStatus, 0)
        let standardOutput = String(data: result.standardOutput, encoding: .utf8) ?? ""
        let outputLines = standardOutput
            .split(separator: "\n", omittingEmptySubsequences: false)
            .map(String.init)
            .filter { $0.isEmpty == false }
        XCTAssertEqual(outputLines.first, "root")
        XCTAssertTrue(
            outputLines.dropFirst().first?.range(of: #"^\d+\.\d+(\.\d+)?$"#, options: .regularExpression) != nil,
            "Expected Alpine release output, received: \(standardOutput)",
        )
        let standardError = String(data: result.standardError, encoding: .utf8) ?? ""
        XCTAssertFalse(standardError.localizedCaseInsensitiveContains("permission denied"))
        XCTAssertFalse(standardError.localizedCaseInsensitiveContains("verification failed"))
    }

    func awaitSmokeCommand(on connection: SSHConnection) throws -> SSHCommandResult {
        try runCommand("whoami && cat /etc/alpine-release", on: connection)
    }

    func runCommand(_ command: String, on connection: SSHConnection) throws -> SSHCommandResult {
        let expectation = expectation(description: "Execute Alpine SSH smoke command")
        var commandResult: Result<SSHCommandResult, SSHKitError>?

        connection.execute(command, callbackQueue: .main) { result in
            commandResult = result
            expectation.fulfill()
        }

        wait(for: [expectation], timeout: 15)
        return try XCTUnwrap(commandResult).get()
    }

    func discoverAuthenticationMethods(fixture: AlpineSSHFixture, knownHostsPath: String) throws -> SSHAuthenticationDiscoveryResult {
        let configuration = SSHClientConfiguration(
            host: fixture.host,
            port: fixture.port,
            username: fixture.username,
            authentication: .password(fixture.password),
            hostKeyPolicy: .knownHostsFile(knownHostsPath),
            timeout: 10,
        )

        let expectation = expectation(description: "Discover Alpine SSH authentication methods")
        var discoveryResult: Result<SSHAuthenticationDiscoveryResult, SSHKitError>?
        SSHClient.discoverAuthenticationMethods(configuration: configuration, callbackQueue: .main) { result in
            discoveryResult = result
            expectation.fulfill()
        }

        wait(for: [expectation], timeout: 15)
        return try XCTUnwrap(discoveryResult).get()
    }

    func awaitShellPTYSession(on connection: SSHConnection) throws -> SSHCommandResult {
        let openExpectation = expectation(description: "Open Alpine SSH PTY shell")
        let closedExpectation = expectation(description: "Close Alpine SSH PTY shell")
        let eventCapture = CommandEventCapture()
        var openResult: Result<SSHShell, SSHKitError>?

        connection.openShell(terminalType: "xterm-256color", columns: 100, rows: 40, callbackQueue: .main) { event in
            switch event {
            case let .standardOutput(data), let .standardError(data):
                eventCapture.appendStandardOutput(data)
            case let .closed(status):
                eventCapture.setExitStatus(status)
                closedExpectation.fulfill()
            }
        } completion: { result in
            openResult = result
            openExpectation.fulfill()
        }

        wait(for: [openExpectation], timeout: 15)
        let shell = try XCTUnwrap(openResult).get()
        try resize(shell, columns: 120, rows: 42)
        try write("tty && printf 'shell-ok\\n'\nexit\n", to: shell)
        wait(for: [closedExpectation], timeout: 15)
        try assertShellRejectsUseAfterClose(shell)

        return try SSHCommandResult(
            standardOutput: eventCapture.standardOutput(),
            standardError: Data(),
            exitStatus: XCTUnwrap(eventCapture.exitStatus()),
        )
    }

    func assertPTYCommandResult(_ result: SSHCommandResult) {
        XCTAssertEqual(result.exitStatus, 0)
        let standardOutput = String(data: result.standardOutput, encoding: .utf8) ?? ""
        XCTAssertTrue(standardOutput.contains("/dev/pts/") || standardOutput.contains("/dev/ttys"))
        XCTAssertTrue(standardOutput.contains("shell-ok"))
    }

    func awaitStreamingCommand(on connection: SSHConnection) throws -> SSHCommandResult {
        let openExpectation = expectation(description: "Open streamed command")
        let closedExpectation = expectation(description: "Close streamed command")
        let eventCapture = CommandEventCapture()
        var openResult: Result<SSHCommand, SSHKitError>?

        connection.openCommand("cat && printf 'err-line\\n' >&2", callbackQueue: .main) { event in
            switch event {
            case let .standardOutput(data):
                eventCapture.appendStandardOutput(data)
            case let .standardError(data):
                eventCapture.appendStandardError(data)
            case let .closed(status, exitSignal: exitSignal):
                eventCapture.setExitStatus(status)
                eventCapture.setExitSignal(exitSignal)
                closedExpectation.fulfill()
            }
        } completion: { result in
            openResult = result
            openExpectation.fulfill()
        }

        wait(for: [openExpectation], timeout: 15)
        let command = try XCTUnwrap(openResult).get()
        try write("stdin-line\n", to: command)
        try sendEOF(to: command)
        wait(for: [closedExpectation], timeout: 15)
        try assertCommandRejectsUseAfterClose(command)

        return try SSHCommandResult(
            standardOutput: eventCapture.standardOutput(),
            standardError: eventCapture.standardError(),
            exitStatus: XCTUnwrap(eventCapture.exitStatus()),
            exitSignal: eventCapture.exitSignal(),
        )
    }

    func assertStreamingCommandResult(_ result: SSHCommandResult) {
        XCTAssertEqual(result.exitStatus, 0)
        XCTAssertEqual(String(data: result.standardOutput, encoding: .utf8), "stdin-line\n")
        XCTAssertEqual(String(data: result.standardError, encoding: .utf8), "err-line\n")
    }

    func withPrivateKeyConnection(_ body: (SSHConnection) throws -> Void) throws {
        let fixture = try AlpineSSHFixture()
        let connection = try connect(
            authentication: .privateKeyFile(path: makePrivateKeyFile(fixture: fixture)),
            fixture: fixture,
            knownHostsPath: makeKnownHostsFile(fixture: fixture),
        )

        do {
            try body(connection)
            try close(connection)
        } catch {
            do {
                try close(connection)
            } catch {
                XCTFail("Closing connection after live SSH test failure failed: \(error)")
            }
            throw error
        }
    }

    func withPasswordConnection(_ body: (SSHConnection) throws -> Void) throws {
        let fixture = try AlpineSSHFixture()
        let connection = try connect(
            authentication: .password(fixture.password),
            fixture: fixture,
            knownHostsPath: makeKnownHostsFile(fixture: fixture),
        )

        do {
            try body(connection)
            try close(connection)
        } catch {
            do {
                try close(connection)
            } catch {
                XCTFail("Closing password connection after live SSH test failure failed: \(error)")
            }
            throw error
        }
    }

    func openStreamingCommand(
        _ commandLine: String,
        on connection: SSHConnection,
        eventHandler: @escaping @Sendable (SSHCommandEvent) -> Void,
    ) throws -> SSHCommand {
        let openExpectation = expectation(description: "Open streamed command")
        var openResult: Result<SSHCommand, SSHKitError>?

        connection.openCommand(commandLine, callbackQueue: .main, eventHandler: eventHandler) { result in
            openResult = result
            openExpectation.fulfill()
        }

        wait(for: [openExpectation], timeout: 15)
        return try XCTUnwrap(openResult).get()
    }

    func close(_ connection: SSHConnection) throws {
        let expectation = expectation(description: "Close Alpine SSH fixture connection")
        var closeResult: Result<Void, SSHKitError>?

        connection.close(callbackQueue: .main) { result in
            closeResult = result
            expectation.fulfill()
        }

        wait(for: [expectation], timeout: 15)
        try XCTUnwrap(closeResult).get()
    }

    func close(_ command: SSHCommand) throws {
        let expectation = expectation(description: "Close streamed command")
        var closeResult: Result<Void, SSHKitError>?
        command.close(callbackQueue: .main) { result in
            closeResult = result
            expectation.fulfill()
        }
        wait(for: [expectation], timeout: 15)
        try XCTUnwrap(closeResult).get()
    }

    func close(_ shell: SSHShell) throws {
        let expectation = expectation(description: "Close PTY shell")
        var closeResult: Result<Void, SSHKitError>?
        shell.close(callbackQueue: .main) { result in
            closeResult = result
            expectation.fulfill()
        }
        wait(for: [expectation], timeout: 15)
        try XCTUnwrap(closeResult).get()
    }

    func close(_ sftp: SFTPClient) throws {
        let expectation = expectation(description: "Close SFTP client")
        var closeResult: Result<Void, SSHKitError>?
        sftp.close(callbackQueue: .main) { result in
            closeResult = result
            expectation.fulfill()
        }
        wait(for: [expectation], timeout: 15)
        try XCTUnwrap(closeResult).get()
    }

    func makeTemporaryDirectory() throws -> URL {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("SSHKitLiveTests")
            .appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        addTeardownBlock {
            try FileManager.default.removeItem(at: directory)
        }
        return directory
    }

    private func resize(_ shell: SSHShell, columns: UInt16, rows: UInt16) throws {
        let expectation = expectation(description: "Resize Alpine SSH PTY shell")
        var resizeResult: Result<Void, SSHKitError>?
        shell.resize(columns: columns, rows: rows, callbackQueue: .main) { result in
            resizeResult = result
            expectation.fulfill()
        }
        wait(for: [expectation], timeout: 15)
        try XCTUnwrap(resizeResult).get()
    }

    private func write(_ string: String, to shell: SSHShell) throws {
        let expectation = expectation(description: "Write Alpine SSH PTY shell command")
        var writeResult: Result<Void, SSHKitError>?
        shell.write(Data(string.utf8), callbackQueue: .main) { result in
            writeResult = result
            expectation.fulfill()
        }
        wait(for: [expectation], timeout: 15)
        try XCTUnwrap(writeResult).get()
    }

    func write(_ string: String, to command: SSHCommand) throws {
        let expectation = expectation(description: "Write streamed command input")
        var writeResult: Result<Void, SSHKitError>?
        command.write(Data(string.utf8), callbackQueue: .main) { result in
            writeResult = result
            expectation.fulfill()
        }
        wait(for: [expectation], timeout: 15)
        try XCTUnwrap(writeResult).get()
    }

    func sendEOF(to command: SSHCommand) throws {
        let expectation = expectation(description: "Send streamed command EOF")
        var eofResult: Result<Void, SSHKitError>?
        command.sendEOF(callbackQueue: .main) { result in
            eofResult = result
            expectation.fulfill()
        }
        wait(for: [expectation], timeout: 15)
        try XCTUnwrap(eofResult).get()
    }

    func assertShellRejectsUseAfterClose(_ shell: SSHShell) throws {
        let resizeExpectation = expectation(description: "Reject resize after shell close")
        var resizeResult: Result<Void, SSHKitError>?
        shell.resize(columns: 120, rows: 42, callbackQueue: .main) { result in
            resizeResult = result
            resizeExpectation.fulfill()
        }
        wait(for: [resizeExpectation], timeout: 15)
        XCTAssertThrowsError(try XCTUnwrap(resizeResult).get()) { error in
            XCTAssertEqual((error as? SSHKitError)?.code, SSHKitErrorCode.invalidState.rawValue)
        }

        let writeExpectation = expectation(description: "Reject write after shell close")
        var writeResult: Result<Void, SSHKitError>?
        shell.write(Data("printf after-close\n".utf8), callbackQueue: .main) { result in
            writeResult = result
            writeExpectation.fulfill()
        }
        wait(for: [writeExpectation], timeout: 15)
        XCTAssertThrowsError(try XCTUnwrap(writeResult).get()) { error in
            XCTAssertEqual((error as? SSHKitError)?.code, SSHKitErrorCode.invalidState.rawValue)
        }
    }

    func assertCommandRejectsUseAfterClose(_ command: SSHCommand) throws {
        let writeExpectation = expectation(description: "Reject command write after close")
        var writeResult: Result<Void, SSHKitError>?
        command.write(Data("after-close\n".utf8), callbackQueue: .main) { result in
            writeResult = result
            writeExpectation.fulfill()
        }
        wait(for: [writeExpectation], timeout: 15)
        XCTAssertThrowsError(try XCTUnwrap(writeResult).get()) { error in
            XCTAssertEqual((error as? SSHKitError)?.code, SSHKitErrorCode.invalidState.rawValue)
        }

        let eofExpectation = expectation(description: "Reject command EOF after close")
        var eofResult: Result<Void, SSHKitError>?
        command.sendEOF(callbackQueue: .main) { result in
            eofResult = result
            eofExpectation.fulfill()
        }
        wait(for: [eofExpectation], timeout: 15)
        XCTAssertThrowsError(try XCTUnwrap(eofResult).get()) { error in
            XCTAssertEqual((error as? SSHKitError)?.code, SSHKitErrorCode.invalidState.rawValue)
        }

        try close(command)
    }
}

func requireExternalFixtureHost(_ host: String) throws {
    let normalizedHost = host.trimmingCharacters(in: CharacterSet(charactersIn: "[]")).lowercased()
    let localHosts = ["localhost", "ip6-localhost", "::1", "0:0:0:0:0:0:0:1", "0.0.0.0"]
    guard localHosts.contains(normalizedHost) == false,
          normalizedHost.hasPrefix("127.") == false,
          normalizedHost.hasPrefix("::ffff:127.") == false
    else {
        throw LiveSSHFixtureError.localHost(host)
    }
}

struct AlpineSSHFixture {
    var host: String
    var port: UInt16
    var username: String
    var password: String
    var knownHostsEntry: String
    var privateKey: String

    init() throws {
        host = try Self.requiredEnvironmentValue("SSHKIT_LIVE_HOST")
        try requireExternalFixtureHost(host)
        port = try UInt16(Self.requiredEnvironmentValue("SSHKIT_LIVE_PORT")).unwrap("SSHKIT_LIVE_PORT must be a valid UInt16.")
        username = try Self.requiredEnvironmentValue("SSHKIT_LIVE_USERNAME")
        password = try Self.requiredEnvironmentValue("SSHKIT_LIVE_PASSWORD")
        knownHostsEntry = try Self.requiredEnvironmentValue("SSHKIT_LIVE_KNOWN_HOSTS")
        privateKey = try Self.requiredEnvironmentValue("SSHKIT_LIVE_PRIVATE_KEY")
    }

    private static func requiredEnvironmentValue(_ name: String) throws -> String {
        guard let value = ProcessInfo.processInfo.environment[name], value.isEmpty == false else {
            throw LiveSSHFixtureError.missingEnvironment(name)
        }
        return value
    }
}

struct DropbearSSHFixture {
    var host: String
    var port: UInt16
    var username: String
    var password: String
    var knownHostsEntry: String

    init() throws {
        host = try Self.requiredEnvironmentValue("SSHKIT_DROPBEAR_HOST")
        try requireExternalFixtureHost(host)
        port = try UInt16(Self.requiredEnvironmentValue("SSHKIT_DROPBEAR_PORT")).unwrap("SSHKIT_DROPBEAR_PORT must be a valid UInt16.")
        username = try Self.requiredEnvironmentValue("SSHKIT_DROPBEAR_USERNAME")
        password = try Self.requiredEnvironmentValue("SSHKIT_DROPBEAR_PASSWORD")
        knownHostsEntry = try Self.requiredEnvironmentValue("SSHKIT_DROPBEAR_KNOWN_HOSTS")
    }

    private static func requiredEnvironmentValue(_ name: String) throws -> String {
        guard let value = ProcessInfo.processInfo.environment[name], value.isEmpty == false else {
            throw LiveSSHFixtureError.missingEnvironment(name)
        }
        return value
    }
}

enum LiveSSHFixtureError: Error, CustomStringConvertible {
    case localHost(String)
    case missingCapability(String)
    case missingEnvironment(String)
    case invalidEnvironment(String)

    var description: String {
        switch self {
        case let .localHost(host):
            "Live SSH fixture host must be a remote fixture host; received local host '\(host)'."
        case let .missingCapability(message):
            message
        case let .missingEnvironment(name):
            "Missing required live SSH test environment value: \(name)."
        case let .invalidEnvironment(message):
            message
        }
    }
}

final class CommandEventCapture: @unchecked Sendable {
    private let lock = NSLock()
    private var output = Data()
    private var outputChunks = [Data]()
    private var error = Data()
    private var errorChunks = [Data]()
    private var status: Int32?
    private var signal: String?

    func appendStandardOutput(_ data: Data) {
        lock.lock()
        output.append(data)
        outputChunks.append(data)
        lock.unlock()
    }

    func appendStandardError(_ data: Data) {
        lock.lock()
        error.append(data)
        errorChunks.append(data)
        lock.unlock()
    }

    func setExitStatus(_ exitStatus: Int32) {
        lock.lock()
        status = exitStatus
        lock.unlock()
    }

    func setExitSignal(_ exitSignal: String?) {
        lock.lock()
        signal = exitSignal
        lock.unlock()
    }

    func standardOutput() -> Data {
        lock.lock()
        defer { lock.unlock() }
        return output
    }

    func standardError() -> Data {
        lock.lock()
        defer { lock.unlock() }
        return error
    }

    func exitStatus() -> Int32? {
        lock.lock()
        defer { lock.unlock() }
        return status
    }

    func exitSignal() -> String? {
        lock.lock()
        defer { lock.unlock() }
        return signal
    }

    func standardOutputEventCount() -> Int {
        lock.lock()
        defer { lock.unlock() }
        return outputChunks.count
    }

    func standardErrorEventCount() -> Int {
        lock.lock()
        defer { lock.unlock() }
        return errorChunks.count
    }
}

final class AsyncCommandEventResultBox: @unchecked Sendable {
    private let lock = NSLock()
    private var storedResult: Result<[SSHCommandEvent], Error>?

    func setResult(_ result: Result<[SSHCommandEvent], Error>) {
        lock.lock()
        storedResult = result
        lock.unlock()
    }

    func result() -> Result<[SSHCommandEvent], Error>? {
        lock.lock()
        defer { lock.unlock() }
        return storedResult
    }
}

extension Optional {
    func unwrap(_ message: String) throws -> Wrapped {
        guard let wrapped = self else {
            throw LiveSSHFixtureError.invalidEnvironment(message)
        }
        return wrapped
    }
}
