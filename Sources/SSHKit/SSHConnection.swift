import Foundation
import SSHKitObjC

public final class SSHConnection: @unchecked Sendable {
    private let session: SSHKitConnection

    init(session: SSHKitConnection) {
        self.session = session
    }

    public func execute(
        _ command: String,
        callbackQueue: DispatchQueue = .main,
        completion: @escaping (Result<SSHCommandResult, SSHKitError>) -> Void,
    ) {
        session.executeCommand(command) { result, error in
            if let error = error as NSError? {
                callbackQueue.async {
                    completion(.failure(SSHKitError(error)))
                }
                return
            }

            guard let result else {
                callbackQueue.async {
                    completion(.failure(SSHKitError(code: SSHKitErrorCode.unavailable.rawValue, message: "SSH command completed without a result.")))
                }
                return
            }

            let commandResult = SSHCommandResult(
                standardOutput: result.standardOutput,
                standardError: result.standardError,
                exitStatus: result.exitStatus,
            )
            callbackQueue.async {
                completion(.success(commandResult))
            }
        }
    }

    public func close(
        callbackQueue: DispatchQueue = .main,
        completion: @escaping (Result<Void, SSHKitError>) -> Void,
    ) {
        session.disconnect { error in
            if let error = error as NSError? {
                callbackQueue.async {
                    completion(.failure(SSHKitError(error)))
                }
                return
            }

            callbackQueue.async {
                completion(.success(()))
            }
        }
    }

    public func openShell(
        terminalType: String = "xterm-256color",
        columns: UInt16 = 80,
        rows: UInt16 = 24,
        callbackQueue: DispatchQueue = .main,
        eventHandler: @escaping @Sendable (SSHShellEvent) -> Void,
        completion: @escaping (Result<SSHShell, SSHKitError>) -> Void,
    ) {
        precondition(terminalType.isEmpty == false, "Shell terminal type must not be empty.")
        precondition(columns > 0, "PTY columns must be greater than zero.")
        precondition(rows > 0, "PTY rows must be greater than zero.")

        session.openShell(
            withTerminalType: terminalType,
            columns: columns,
            rows: rows,
            eventHandler: { event in
                let shellEvent = SSHShell.makeEvent(event)
                callbackQueue.async {
                    eventHandler(shellEvent)
                }
            },
        ) { shell, error in
            if let error = error as NSError? {
                callbackQueue.async {
                    completion(.failure(SSHKitError(error)))
                }
                return
            }

            guard let shell else {
                callbackQueue.async {
                    completion(.failure(SSHKitError(code: SSHKitErrorCode.unavailable.rawValue, message: "SSH shell opened without a shell object.")))
                }
                return
            }

            callbackQueue.async {
                completion(.success(SSHShell(shell: shell)))
            }
        }
    }

    public func openShell(
        terminalType: String = "xterm-256color",
        columns: UInt16 = 80,
        rows: UInt16 = 24,
        eventHandler: @escaping @Sendable (SSHShellEvent) -> Void,
    ) async throws -> SSHShell {
        try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                openShell(
                    terminalType: terminalType,
                    columns: columns,
                    rows: rows,
                    callbackQueue: .global(),
                    eventHandler: eventHandler,
                ) { result in
                    continuation.resume(with: result)
                }
            }
        } onCancel: {
            close(callbackQueue: .global()) { _ in
            }
        }
    }

    public func execute(_ command: String) async throws -> SSHCommandResult {
        try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                execute(command, callbackQueue: .global()) { result in
                    continuation.resume(with: result)
                }
            }
        } onCancel: {
            close(callbackQueue: .global()) { _ in
            }
        }
    }

    public func close() async throws {
        try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                close(callbackQueue: .global()) { result in
                    continuation.resume(with: result)
                }
            }
        } onCancel: {
            close(callbackQueue: .global()) { _ in
            }
        }
    }
}
