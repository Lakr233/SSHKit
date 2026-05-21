import SSHKit
import XCTest

final class ShellLiveTests: LiveSSHTestCase {
    func testPrivateKeyLoginExecutesPTYCommand() throws {
        try requireLiveTestsEnabled()

        try withPrivateKeyConnection { connection in
            let result = try awaitShellPTYSession(on: connection)
            assertPTYCommandResult(result)
        }
    }

    func testPasswordLoginExecutesPTYCommand() throws {
        try requireLiveTestsEnabled()

        try withPasswordConnection { connection in
            let result = try awaitShellPTYSession(on: connection)
            assertPTYCommandResult(result)
        }
    }

    func testPrivateKeyLoginClosesPTYShellMidStream() throws {
        try requireLiveTestsEnabled()

        try withPrivateKeyConnection { connection in
            let openExpectation = expectation(description: "Open PTY shell")
            let firstOutputExpectation = expectation(description: "Receive PTY output before close")
            let closedExpectation = expectation(description: "PTY shell closes")
            let eventCapture = CommandEventCapture()
            var openResult: Result<SSHShell, SSHKitError>?

            connection.openShell(terminalType: "xterm-256color", columns: 100, rows: 40, callbackQueue: .main) { event in
                switch event {
                case let .standardOutput(data), let .standardError(data):
                    let isFirstOutput = eventCapture.standardOutputEventCount() == 0
                    eventCapture.appendStandardOutput(data)
                    if isFirstOutput {
                        firstOutputExpectation.fulfill()
                    }
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
            try writeLoopCommand(to: shell)
            wait(for: [firstOutputExpectation], timeout: 15)
            try close(shell)
            wait(for: [closedExpectation], timeout: 15)
            try assertShellRejectsUseAfterClose(shell)

            XCTAssertTrue((String(data: eventCapture.standardOutput(), encoding: .utf8) ?? "").contains("pty-loop"))
            XCTAssertNotEqual(try XCTUnwrap(eventCapture.exitStatus()), 0)
        }
    }

    private func writeLoopCommand(to shell: SSHShell) throws {
        let expectation = expectation(description: "Write PTY loop command")
        var writeResult: Result<Void, SSHKitError>?
        shell.write(Data("while true; do printf 'pty-loop\\n'; sleep 1; done\n".utf8), callbackQueue: .main) { result in
            writeResult = result
            expectation.fulfill()
        }
        wait(for: [expectation], timeout: 15)
        try XCTUnwrap(writeResult).get()
    }
}
