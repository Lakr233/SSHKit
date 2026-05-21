import SSHKit
import XCTest

final class AuthenticationLiveTests: LiveSSHTestCase {
    func testDiscoversFixtureAuthenticationMethods() throws {
        try requireLiveTestsEnabled()

        let fixture = try AlpineSSHFixture()
        let discovery = try discoverAuthenticationMethods(
            fixture: fixture,
            knownHostsPath: makeKnownHostsFile(fixture: fixture),
        )

        XCTAssertTrue(discovery.methods.contains(.password) || discovery.methods.contains(.publicKey))
        XCTAssertTrue(discovery.serverBanner?.hasPrefix("SSH-2.0-") == true)
    }

    func testKeyboardInteractiveExecutesSmokeCommandWhenAdvertised() throws {
        try requireLiveTestsEnabled()

        let fixture = try AlpineSSHFixture()
        let knownHostsPath = try makeKnownHostsFile(fixture: fixture)
        let discovery = try discoverAuthenticationMethods(fixture: fixture, knownHostsPath: knownHostsPath)
        guard discovery.methods.contains(.keyboardInteractive) else {
            throw XCTSkip("Fixture SSH server does not advertise keyboard-interactive authentication.")
        }

        let connection = try connect(
            authentication: .keyboardInteractive { _, _, prompts in
                prompts.map { prompt in
                    prompt.echo ? "" : fixture.password
                }
            },
            fixture: fixture,
            knownHostsPath: knownHostsPath,
        )

        do {
            let result = try awaitSmokeCommand(on: connection)
            try close(connection)
            assertSmokeCommandResult(result)
        } catch {
            do {
                try close(connection)
            } catch {
                XCTFail("Closing connection after keyboard-interactive smoke test failure failed: \(error)")
            }
            throw error
        }
    }

    func testAgentLoginExecutesSmokeCommandAgainstFixture() throws {
        try requireLiveTestsEnabled()

        let fixture = try AlpineSSHFixture()
        let agent = try TemporarySSHAgent()
        let keyPath = try makePrivateKeyFile(fixture: fixture)
        try agent.addKey(path: keyPath)
        defer {
            do {
                try agent.stop()
            } catch {
                XCTFail("Stopping temporary SSH agent failed: \(error)")
            }
        }

        let connection = try connect(
            authentication: .agent(SSHAgentConfiguration(socketPath: agent.socketPath)),
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
                XCTFail("Closing connection after agent smoke test failure failed: \(error)")
            }
            throw error
        }
    }

    func testGeneratedOpenSSHKeyAuthenticatesAfterAuthorizedKeyInstall() throws {
        try requireLiveTestsEnabled()

        let fixture = try AlpineSSHFixture()
        let adminConnection = try connect(
            authentication: .password(fixture.password),
            fixture: fixture,
            knownHostsPath: makeKnownHostsFile(fixture: fixture),
        )
        let comment = "sshkit-generated-\(UUID().uuidString)"
        let keyPair = try SSHKeyGenerator.generateOpenSSHKeyPair(type: .ed25519, comment: comment)
        var installedAuthorizedKey = false
        defer {
            if installedAuthorizedKey {
                cleanupGeneratedAuthorizedKey(comment: comment, fixture: fixture)
            }
        }

        do {
            _ = try runCommand(
                "umask 077 && mkdir -p ~/.ssh && touch ~/.ssh/authorized_keys && printf '%s\\n' \(shellQuoted(keyPair.authorizedKey)) >> ~/.ssh/authorized_keys",
                on: adminConnection,
            )
            installedAuthorizedKey = true
            try close(adminConnection)

            let privateKeyPath = try makePrivateKeyFile(contents: keyPair.privateKeyOpenSSH, filename: "generated_ed25519")
            let privateKeyDirectory = URL(fileURLWithPath: privateKeyPath).deletingLastPathComponent()
            defer {
                do {
                    try FileManager.default.removeItem(at: privateKeyDirectory)
                } catch {
                    XCTFail("Removing generated private key file failed: \(error)")
                }
            }
            let generatedKeyConnection = try connect(
                authentication: .privateKeyFile(path: privateKeyPath),
                fixture: fixture,
                knownHostsPath: makeKnownHostsFile(fixture: fixture),
            )
            let result = try awaitSmokeCommand(on: generatedKeyConnection)
            try close(generatedKeyConnection)
            assertSmokeCommandResult(result)
        } catch {
            try? close(adminConnection)
            throw error
        }
    }

    private func makePrivateKeyFile(contents: String, filename: String) throws -> String {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("SSHKitGeneratedKeyLiveTests")
            .appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let fileURL = directory.appendingPathComponent(filename)
        try contents.appending("\n").write(to: fileURL, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: fileURL.path)
        return fileURL.path
    }

    private func shellQuoted(_ value: String) -> String {
        "'\(value.replacingOccurrences(of: "'", with: "'\\''"))'"
    }

    private func cleanupGeneratedAuthorizedKey(comment: String, fixture: AlpineSSHFixture) {
        do {
            let cleanupConnection = try connect(
                authentication: .password(fixture.password),
                fixture: fixture,
                knownHostsPath: makeKnownHostsFile(fixture: fixture),
            )
            _ = try runCommand(
                "grep -F -v -- \(shellQuoted(comment)) ~/.ssh/authorized_keys > ~/.ssh/authorized_keys.sshkit.tmp || true; mv ~/.ssh/authorized_keys.sshkit.tmp ~/.ssh/authorized_keys",
                on: cleanupConnection,
            )
            try close(cleanupConnection)
        } catch {
            XCTFail("Cleaning generated authorized_keys entry failed: \(error)")
        }
    }
}

private final class TemporarySSHAgent {
    let socketPath: String
    private let directory: URL
    private let processIdentifier: String

    init() throws {
        directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("SSHKitAgentLiveTests")
            .appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        socketPath = directory.appendingPathComponent("agent.sock").path
        let output = try Self.run("/usr/bin/ssh-agent", arguments: ["-a", socketPath, "-s"], environment: ProcessInfo.processInfo.environment)
        processIdentifier = try Self.parseAgentPID(output)
    }

    func addKey(path: String) throws {
        var environment = ProcessInfo.processInfo.environment
        environment["SSH_AUTH_SOCK"] = socketPath
        _ = try Self.run("/usr/bin/ssh-add", arguments: [path], environment: environment)
    }

    func stop() throws {
        _ = try Self.run("/bin/kill", arguments: [processIdentifier], environment: ProcessInfo.processInfo.environment)
        try FileManager.default.removeItem(at: directory)
    }

    private static func parseAgentPID(_ output: String) throws -> String {
        let marker = "SSH_AGENT_PID="
        guard let start = output.range(of: marker)?.upperBound else {
            throw XCTSkip("ssh-agent did not report SSH_AGENT_PID.")
        }
        let suffix = output[start...]
        guard let end = suffix.firstIndex(where: { $0 == ";" || $0 == "\n" }) else {
            throw XCTSkip("ssh-agent returned an unparseable SSH_AGENT_PID.")
        }
        return String(suffix[..<end])
    }

    private static func run(_ launchPath: String, arguments: [String], environment: [String: String]) throws -> String {
        guard FileManager.default.isExecutableFile(atPath: launchPath) else {
            throw XCTSkip("\(launchPath) is required for SSH agent live tests.")
        }
        let process = Process()
        process.executableURL = URL(fileURLWithPath: launchPath)
        process.arguments = arguments
        process.environment = environment

        let outputPipe = Pipe()
        let errorPipe = Pipe()
        process.standardOutput = outputPipe
        process.standardError = errorPipe
        try process.run()
        process.waitUntilExit()

        let output = String(data: outputPipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
        let error = String(data: errorPipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
        guard process.terminationStatus == 0 else {
            throw XCTSkip("\(launchPath) failed: \(error)")
        }
        return output
    }
}
