import Foundation
import SSHKitObjC

public enum SSHCommandEvent: Equatable, Sendable {
    case standardOutput(Data)
    case standardError(Data)
    case closed(Int32, exitSignal: String? = nil)
}

public final class SSHCommand: @unchecked Sendable {
    public let events: AsyncStream<SSHCommandEvent>

    private let command: SSHKitObjC.SSHKitCommand
    private let eventSink: SSHCommandEventSink

    init(command: SSHKitObjC.SSHKitCommand, eventSink: SSHCommandEventSink) {
        self.command = command
        self.eventSink = eventSink
        events = eventSink.stream
    }

    public func write(
        _ data: Data,
        callbackQueue: DispatchQueue = .main,
        completion: @escaping (Result<Void, SSHKitError>) -> Void
    ) {
        precondition(data.isEmpty == false, "Command write data must not be empty.")

        command.write(data) { error in
            Self.complete(error: error, callbackQueue: callbackQueue, completion: completion)
        }
    }

    public func write(_ string: String, encoding: String.Encoding = .utf8) async throws {
        guard let data = string.data(using: encoding) else {
            throw SSHKitError(code: SSHKitErrorCode.invalidState.rawValue, message: "Command write string could not be encoded.")
        }
        try await write(data)
    }

    public func write(_ data: Data) async throws {
        try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                write(data, callbackQueue: .global()) { result in
                    continuation.resume(with: result)
                }
            }
        } onCancel: {
            close(callbackQueue: .global()) { _ in
            }
        }
    }

    public func sendEOF(
        callbackQueue: DispatchQueue = .main,
        completion: @escaping (Result<Void, SSHKitError>) -> Void
    ) {
        command.sendEOF { error in
            Self.complete(error: error, callbackQueue: callbackQueue, completion: completion)
        }
    }

    public func sendEOF() async throws {
        try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                sendEOF(callbackQueue: .global()) { result in
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
        command.close { error in
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

    static func makeEvent(_ event: SSHKitObjC.SSHKitCommandEvent) -> SSHCommandEvent {
        switch event.kind {
        case .standardOutput:
            return .standardOutput(event.data)
        case .standardError:
            return .standardError(event.data)
        case .closed:
            return .closed(event.exitStatus, exitSignal: event.exitSignal)
        @unknown default:
            preconditionFailure("Unknown SSH command event kind: \(event.kind.rawValue).")
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

final class SSHCommandEventSink: @unchecked Sendable {
    let stream: AsyncStream<SSHCommandEvent>

    private let lock = NSLock()
    private var continuation: AsyncStream<SSHCommandEvent>.Continuation?
    private var isFinished = false

    init() {
        var capturedContinuation: AsyncStream<SSHCommandEvent>.Continuation?
        stream = AsyncStream { continuation in
            capturedContinuation = continuation
        }
        continuation = capturedContinuation
    }

    func yield(_ event: SSHCommandEvent) {
        lock.lock()
        guard isFinished == false else {
            lock.unlock()
            return
        }
        let continuation = continuation
        if case .closed = event {
            isFinished = true
            self.continuation = nil
        }
        lock.unlock()

        continuation?.yield(event)
        if case .closed = event {
            continuation?.finish()
        }
    }

    func finish() {
        lock.lock()
        guard isFinished == false else {
            lock.unlock()
            return
        }
        isFinished = true
        let continuation = continuation
        self.continuation = nil
        lock.unlock()

        continuation?.finish()
    }
}
