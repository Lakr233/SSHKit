import Foundation
import SSHKitObjC

public final class SSHTunnelChannel: @unchecked Sendable {
    private let channel: SSHKitObjC.SSHKitTunnelChannel
    private let cancelConnection: @Sendable () -> Void

    init(channel: SSHKitObjC.SSHKitTunnelChannel, cancelConnection: @escaping @Sendable () -> Void) {
        self.channel = channel
        self.cancelConnection = cancelConnection
    }

    public func read(
        maximumLength: Int = 32768,
        callbackQueue: DispatchQueue = .main,
        completion: @escaping (Result<Data, SSHKitError>) -> Void,
    ) {
        precondition(maximumLength > 0, "Tunnel read maximum length must be greater than zero.")

        channel.readData(withMaximumLength: UInt(maximumLength)) { data, error in
            if let error = error as NSError? {
                callbackQueue.async {
                    completion(.failure(SSHKitError(error)))
                }
                return
            }

            callbackQueue.async {
                completion(.success(data ?? Data()))
            }
        }
    }

    public func write(
        _ data: Data,
        callbackQueue: DispatchQueue = .main,
        completion: @escaping (Result<Void, SSHKitError>) -> Void,
    ) {
        precondition(data.isEmpty == false, "Tunnel write data must not be empty.")

        channel.write(data) { error in
            Self.complete(error: error, callbackQueue: callbackQueue, completion: completion)
        }
    }

    public func close(
        callbackQueue: DispatchQueue = .main,
        completion: @escaping (Result<Void, SSHKitError>) -> Void,
    ) {
        channel.close { error in
            Self.complete(error: error, callbackQueue: callbackQueue, completion: completion)
        }
    }

    public func read(maximumLength: Int = 32768) async throws -> Data {
        let cancellation = CancellationMarker()
        return try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                read(maximumLength: maximumLength, callbackQueue: .global()) { result in
                    continuation.resume(with: cancellation.result(for: result))
                }
            }
        } onCancel: {
            cancellation.cancel()
            cancelConnection()
        }
    }

    public func write(_ data: Data) async throws {
        let cancellation = CancellationMarker()
        try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                write(data, callbackQueue: .global()) { result in
                    continuation.resume(with: cancellation.result(for: result))
                }
            }
        } onCancel: {
            cancellation.cancel()
            cancelConnection()
        }
    }

    public func close() async throws {
        try await withCheckedThrowingContinuation { continuation in
            close(callbackQueue: .global()) { result in
                continuation.resume(with: result)
            }
        }
    }

    private static func complete(
        error: Error?,
        callbackQueue: DispatchQueue,
        completion: @escaping (Result<Void, SSHKitError>) -> Void,
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

private final class CancellationMarker: @unchecked Sendable {
    private let lock = NSLock()
    private var isCancelled = false

    func cancel() {
        lock.lock()
        isCancelled = true
        lock.unlock()
    }

    func result<Success>(for result: Result<Success, SSHKitError>) -> Result<Success, SSHKitError> {
        lock.lock()
        let cancelled = isCancelled
        lock.unlock()

        guard cancelled else {
            return result
        }
        return .failure(SSHKitError(code: SSHKitErrorCode.cancelled.rawValue, message: "SSH tunnel channel was cancelled."))
    }
}
