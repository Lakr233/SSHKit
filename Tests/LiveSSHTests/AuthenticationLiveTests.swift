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
}
