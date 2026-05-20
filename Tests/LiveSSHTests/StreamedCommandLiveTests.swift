import SSHKit
import XCTest

final class StreamedCommandLiveTests: LiveSSHTestCase {
    func testPrivateKeyLoginStreamsCommandOutputAndInput() throws {
        try requireLiveTestsEnabled()

        try withPrivateKeyConnection { connection in
            let result = try awaitStreamingCommand(on: connection)
            assertStreamingCommandResult(result)
        }
    }

    func testPasswordLoginStreamsCommandOutputAndInput() throws {
        try requireLiveTestsEnabled()

        try withPasswordConnection { connection in
            let result = try awaitStreamingCommand(on: connection)
            assertStreamingCommandResult(result)
        }
    }

    func testPrivateKeyLoginConsumesAsyncCommandEvents() throws {
        try requireLiveTestsEnabled()

        try withPrivateKeyConnection { connection in
            let semaphore = DispatchSemaphore(value: 0)
            let resultBox = AsyncCommandEventResultBox()

            Task.detached {
                do {
                    let command = try await connection.openCommand("printf 'async-out\\n'; printf 'async-err\\n' >&2")
                    var events = [SSHCommandEvent]()
                    for await event in command.events {
                        events.append(event)
                    }
                    resultBox.setResult(.success(events))
                } catch {
                    resultBox.setResult(.failure(error))
                }
                semaphore.signal()
            }

            XCTAssertEqual(semaphore.wait(timeout: .now() + 15), .success)
            let events = try XCTUnwrap(resultBox.result()).get()
            XCTAssertEqual(events, [
                .standardOutput(Data("async-out\n".utf8)),
                .standardError(Data("async-err\n".utf8)),
                .closed(0),
            ])
        }
    }

    func testPrivateKeyLoginStreamsOutputIncrementally() throws {
        try requireLiveTestsEnabled()

        try withPrivateKeyConnection { connection in
            let closedExpectation = expectation(description: "Incremental streamed command closes")
            let eventCapture = CommandEventCapture()
            let command = try openStreamingCommand(
                "for item in one two three; do printf 'tick-%s\\n' \"$item\"; sleep 1; done",
                on: connection,
            ) { event in
                switch event {
                case let .standardOutput(data):
                    eventCapture.appendStandardOutput(data)
                case let .standardError(data):
                    eventCapture.appendStandardError(data)
                case let .closed(status):
                    eventCapture.setExitStatus(status)
                    closedExpectation.fulfill()
                }
            }

            wait(for: [closedExpectation], timeout: 20)
            try assertCommandRejectsUseAfterClose(command)
            XCTAssertEqual(try XCTUnwrap(eventCapture.exitStatus()), 0)
            XCTAssertEqual(String(data: eventCapture.standardOutput(), encoding: .utf8), "tick-one\ntick-two\ntick-three\n")
            XCTAssertGreaterThanOrEqual(eventCapture.standardOutputEventCount(), 2)
            XCTAssertEqual(eventCapture.standardError(), Data())
        }
    }

    func testPrivateKeyLoginClosesCommandMidStream() throws {
        try requireLiveTestsEnabled()

        try withPrivateKeyConnection { connection in
            let firstOutputExpectation = expectation(description: "Receive streamed output before close")
            let closedExpectation = expectation(description: "Mid-stream command closes")
            let eventCapture = CommandEventCapture()
            let command = try openStreamingCommand("while true; do printf 'loop\\n'; sleep 1; done", on: connection) { event in
                switch event {
                case let .standardOutput(data):
                    let isFirstOutput = eventCapture.standardOutputEventCount() == 0
                    eventCapture.appendStandardOutput(data)
                    if isFirstOutput {
                        firstOutputExpectation.fulfill()
                    }
                case let .standardError(data):
                    eventCapture.appendStandardError(data)
                case let .closed(status):
                    eventCapture.setExitStatus(status)
                    closedExpectation.fulfill()
                }
            }

            wait(for: [firstOutputExpectation], timeout: 15)
            try close(command)
            wait(for: [closedExpectation], timeout: 15)
            try assertCommandRejectsUseAfterClose(command)

            XCTAssertTrue((String(data: eventCapture.standardOutput(), encoding: .utf8) ?? "").contains("loop\n"))
            XCTAssertNotEqual(try XCTUnwrap(eventCapture.exitStatus()), 0)
        }
    }

    func testPrivateKeyLoginStreamsNonZeroExitStatus() throws {
        try requireLiveTestsEnabled()

        try withPrivateKeyConnection { connection in
            let closedExpectation = expectation(description: "Non-zero streamed command closes")
            let eventCapture = CommandEventCapture()
            let command = try openStreamingCommand(
                "printf 'before-fail\\n'; printf 'fail-err\\n' >&2; exit 7",
                on: connection,
            ) { event in
                switch event {
                case let .standardOutput(data):
                    eventCapture.appendStandardOutput(data)
                case let .standardError(data):
                    eventCapture.appendStandardError(data)
                case let .closed(status):
                    eventCapture.setExitStatus(status)
                    closedExpectation.fulfill()
                }
            }

            wait(for: [closedExpectation], timeout: 15)
            try assertCommandRejectsUseAfterClose(command)

            XCTAssertEqual(try XCTUnwrap(eventCapture.exitStatus()), 7)
            XCTAssertEqual(String(data: eventCapture.standardOutput(), encoding: .utf8), "before-fail\n")
            XCTAssertEqual(String(data: eventCapture.standardError(), encoding: .utf8), "fail-err\n")
        }
    }

    func testPrivateKeyLoginRejectsSecondStreamingCommandWhileFirstRuns() throws {
        try requireLiveTestsEnabled()

        try withPrivateKeyConnection { connection in
            let closedExpectation = expectation(description: "Long streamed command closes")
            var secondOpenResult: Result<SSHCommand, SSHKitError>?
            let command = try openStreamingCommand("sleep 10", on: connection) { event in
                if case let .closed(status) = event {
                    XCTAssertNotEqual(status, 0)
                    closedExpectation.fulfill()
                }
            }

            let secondOpenExpectation = expectation(description: "Reject second streamed command")
            connection.openCommand("true", callbackQueue: .main) { _ in
                XCTFail("Second streamed command delivered an event")
            } completion: { result in
                secondOpenResult = result
                secondOpenExpectation.fulfill()
            }
            wait(for: [secondOpenExpectation], timeout: 15)
            XCTAssertThrowsError(try XCTUnwrap(secondOpenResult).get()) { error in
                XCTAssertEqual((error as? SSHKitError)?.code, SSHKitErrorCode.invalidState.rawValue)
            }

            try close(command)
            wait(for: [closedExpectation], timeout: 15)
            try assertCommandRejectsUseAfterClose(command)
        }
    }
}
