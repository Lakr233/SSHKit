import Foundation
import SSHKitObjC

public final class SSHTunnelChannel: @unchecked Sendable {
    private let channel: SSHKitObjC.SSHKitTunnelChannel

    init(channel: SSHKitObjC.SSHKitTunnelChannel) {
        self.channel = channel
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
        try await withCheckedThrowingContinuation { continuation in
            read(maximumLength: maximumLength, callbackQueue: .global()) { result in
                continuation.resume(with: result)
            }
        }
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
