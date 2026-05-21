import Foundation
import SSHKitObjC

public enum SSHShellEvent: Equatable, Sendable {
    case standardOutput(Data)
    /// Reserved for channel backends that expose a distinct stderr stream. PTY-backed shells merge stderr into stdout.
    case standardError(Data)
    case closed(Int32)
}

public final class SSHShell: @unchecked Sendable {
    private let shell: SSHKitObjC.SSHKitShell

    init(shell: SSHKitObjC.SSHKitShell) {
        self.shell = shell
    }

    public func write(
        _ data: Data,
        callbackQueue: DispatchQueue = .main,
        completion: @escaping (Result<Void, SSHKitError>) -> Void
    ) {
        precondition(data.isEmpty == false, "Shell write data must not be empty.")

        shell.write(data) { error in
            Self.complete(error: error, callbackQueue: callbackQueue, completion: completion)
        }
    }

    public func write(_ string: String, encoding: String.Encoding = .utf8) async throws {
        guard let data = string.data(using: encoding) else {
            throw SSHKitError(code: SSHKitErrorCode.invalidState.rawValue, message: "Shell write string could not be encoded.")
        }
        try await write(data)
    }

    public func write(_ data: Data) async throws {
        let cancellation = SSHAsyncCancellationBox()
        try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                write(data, callbackQueue: .global()) { result in
                    guard let result = cancellation.complete(result) else {
                        return
                    }
                    continuation.resume(with: result)
                }
            }
        } onCancel: {
            cancellation.cancel {
                close(callbackQueue: .global()) { _ in
                }
            }
        }
    }

    public func resize(
        columns: UInt16,
        rows: UInt16,
        callbackQueue: DispatchQueue = .main,
        completion: @escaping (Result<Void, SSHKitError>) -> Void
    ) {
        precondition(columns > 0, "PTY columns must be greater than zero.")
        precondition(rows > 0, "PTY rows must be greater than zero.")

        shell.resize(withColumns: columns, rows: rows) { error in
            Self.complete(error: error, callbackQueue: callbackQueue, completion: completion)
        }
    }

    public func resize(columns: UInt16, rows: UInt16) async throws {
        try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                resize(columns: columns, rows: rows, callbackQueue: .global()) { result in
                    continuation.resume(with: result)
                }
            }
        } onCancel: {
            close(callbackQueue: .global()) { _ in
            }
        }
    }

    public func close(
        callbackQueue: DispatchQueue = .main,
        completion: @escaping (Result<Void, SSHKitError>) -> Void
    ) {
        shell.close { error in
            Self.complete(error: error, callbackQueue: callbackQueue, completion: completion)
        }
    }

    public func close() async throws {
        try await withCheckedThrowingContinuation { continuation in
            close(callbackQueue: .global()) { result in
                continuation.resume(with: result)
            }
        }
    }

    static func makeEvent(_ event: SSHKitObjC.SSHKitShellEvent) -> SSHShellEvent {
        switch event.kind {
        case .standardOutput:
            return .standardOutput(event.data)
        case .standardError:
            return .standardError(event.data)
        case .closed:
            return .closed(event.exitStatus)
        @unknown default:
            preconditionFailure("Unknown SSH shell event kind: \(event.kind.rawValue).")
        }
    }

    private static func complete(
        error: Error?,
        callbackQueue: DispatchQueue,
        completion: @escaping (Result<Void, SSHKitError>) -> Void
    ) {
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
