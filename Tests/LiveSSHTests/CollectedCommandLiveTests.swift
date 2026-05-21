import SSHKit
import XCTest

final class CollectedCommandLiveTests: LiveSSHTestCase {
    func testPasswordLoginExecutesSmokeCommand() throws {
        try requireLiveTestsEnabled()

        let fixture = try AlpineSSHFixture()
        let connection = try connect(
            authentication: .password(fixture.password),
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
                XCTFail("Closing connection after password smoke test failure failed: \(error)")
            }
            throw error
        }
    }

    func testPrivateKeyLoginExecutesSmokeCommand() throws {
        try requireLiveTestsEnabled()

        let fixture = try AlpineSSHFixture()
        let connection = try connect(
            authentication: .privateKeyFile(path: makePrivateKeyFile(fixture: fixture)),
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
                XCTFail("Closing connection after private-key smoke test failure failed: \(error)")
            }
            throw error
        }
    }

    func testPrivateKeyLoginCapturesExitSignal() throws {
        try requireLiveTestsEnabled()

        try withPrivateKeyConnection { connection in
            let result = try runCommand("sh -c 'kill -TERM $$'", on: connection)

            XCTAssertEqual(result.exitSignal, "TERM")
        }
    }
}
