import Foundation
import SSHKitObjC

public enum SSHClient {
    public typealias Configuration = SSHClientConfiguration

    public static func connect(
        configuration: SSHClientConfiguration,
        callbackQueue: DispatchQueue = .main,
        completion: @escaping (Result<SSHConnection, SSHKitError>) -> Void
    ) {
        let session = SSHKitConnection(configuration: configuration.bridgeConfiguration)
        session.connect { error in
            if let error = error as NSError? {
                callbackQueue.async {
                    completion(.failure(SSHKitError(error)))
                }
                return
            }

            callbackQueue.async {
                completion(.success(SSHConnection(session: session, configuration: configuration)))
            }
        }
    }

    public static func connect(configuration: SSHClientConfiguration) async throws -> SSHConnection {
        let sessionBox = SSHLockedSession()
        return try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                let session = SSHKitConnection(configuration: configuration.bridgeConfiguration)
                let connection = SSHConnection(session: session, configuration: configuration)
                sessionBox.store(session)
                session.connect { error in
                    if let error = error as NSError? {
                        if sessionBox.isCancelled {
                            continuation.resume(throwing: SSHKitError(code: SSHKitErrorCode.cancelled.rawValue, message: "SSH connection was cancelled."))
                            return
                        }

                        continuation.resume(throwing: SSHKitError(error))
                        return
                    }

                    if sessionBox.shouldReturnConnectedSession() {
                        continuation.resume(returning: connection)
                        return
                    }

                    sessionBox.cancelStoredSession()
                    continuation.resume(throwing: SSHKitError(code: SSHKitErrorCode.cancelled.rawValue, message: "SSH connection was cancelled."))
                }
            }
        } onCancel: {
            sessionBox.cancel()
        }
    }

    public static func discoverAuthenticationMethods(
        configuration: SSHClientConfiguration,
        callbackQueue: DispatchQueue = .main,
        completion: @escaping (Result<SSHAuthenticationDiscoveryResult, SSHKitError>) -> Void
    ) {
        let session = SSHKitConnection(configuration: configuration.bridgeConfiguration)
        session.discoverAuthenticationMethods { result, error in
            if let error = error as NSError? {
                callbackQueue.async {
                    completion(.failure(SSHKitError(error)))
                }
                return
            }

            guard let result else {
                callbackQueue.async {
                    completion(.failure(SSHKitError(code: SSHKitErrorCode.unavailable.rawValue, message: "SSH authentication discovery completed without a result.")))
                }
                return
            }

            callbackQueue.async {
                completion(.success(SSHAuthenticationDiscoveryResult(result)))
            }
        }
    }

    public static func discoverAuthenticationMethods(configuration: SSHClientConfiguration) async throws -> SSHAuthenticationDiscoveryResult {
        let sessionBox = SSHLockedSession()
        return try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                let session = SSHKitConnection(configuration: configuration.bridgeConfiguration)
                sessionBox.store(session)
                session.discoverAuthenticationMethods { result, error in
                    if let error = error as NSError? {
                        continuation.resume(throwing: SSHKitError(error))
                        return
                    }

                    guard let result else {
                        continuation.resume(throwing: SSHKitError(code: SSHKitErrorCode.unavailable.rawValue, message: "SSH authentication discovery completed without a result."))
                        return
                    }

                    if sessionBox.shouldReturnConnectedSession() {
                        continuation.resume(returning: SSHAuthenticationDiscoveryResult(result))
                        return
                    }

                    sessionBox.cancelStoredSession()
                    continuation.resume(throwing: SSHKitError(code: SSHKitErrorCode.cancelled.rawValue, message: "SSH authentication discovery was cancelled."))
                }
            }
        } onCancel: {
            sessionBox.cancel()
        }
    }

    public static func discoverHostKey(
        configuration: SSHHostKeyDiscoveryConfiguration,
        callbackQueue: DispatchQueue = .main,
        completion: @escaping (Result<SSHDiscoveredHostKey, SSHKitError>) -> Void
    ) {
        let session = SSHKitConnection(configuration: configuration.bridgeConfiguration)
        session.discoverHostKey { result, error in
            if let error = error as NSError? {
                callbackQueue.async {
                    completion(.failure(SSHKitError(error)))
                }
                return
            }

            guard let result else {
                callbackQueue.async {
                    completion(.failure(SSHKitError(code: SSHKitErrorCode.unavailable.rawValue, message: "SSH host key discovery completed without a result.")))
                }
                return
            }

            callbackQueue.async {
                completion(.success(SSHDiscoveredHostKey(result)))
            }
        }
    }

    public static func discoverHostKey(configuration: SSHHostKeyDiscoveryConfiguration) async throws -> SSHDiscoveredHostKey {
        let sessionBox = SSHLockedSession()
        return try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                let session = SSHKitConnection(configuration: configuration.bridgeConfiguration)
                sessionBox.store(session)
                session.discoverHostKey { result, error in
                    if let error = error as NSError? {
                        if sessionBox.isCancelled {
                            continuation.resume(throwing: SSHKitError(code: SSHKitErrorCode.cancelled.rawValue, message: "SSH host key discovery was cancelled."))
                            return
                        }

                        continuation.resume(throwing: SSHKitError(error))
                        return
                    }

                    guard let result else {
                        continuation.resume(throwing: SSHKitError(code: SSHKitErrorCode.unavailable.rawValue, message: "SSH host key discovery completed without a result."))
                        return
                    }

                    if sessionBox.shouldReturnConnectedSession() {
                        continuation.resume(returning: SSHDiscoveredHostKey(result))
                        return
                    }

                    sessionBox.cancelStoredSession()
                    continuation.resume(throwing: SSHKitError(code: SSHKitErrorCode.cancelled.rawValue, message: "SSH host key discovery was cancelled."))
                }
            }
        } onCancel: {
            sessionBox.cancel()
        }
    }
}

private final class SSHLockedSession: @unchecked Sendable {
    private let lock = NSLock()
    private var session: SSHKitConnection?
    private var cancelled = false
    private var finished = false

    func store(_ session: SSHKitConnection) {
        lock.lock()
        self.session = session
        let shouldCancel = cancelled
        lock.unlock()

        if shouldCancel {
            session.disconnect { _ in
            }
        }
    }

    func cancel() {
        lock.lock()
        cancelled = true
        let session = session
        let shouldCancel = finished == false
        lock.unlock()

        if shouldCancel {
            session?.disconnect { _ in
            }
        }
    }

    func shouldReturnConnectedSession() -> Bool {
        lock.lock()
        finished = true
        let shouldReturn = cancelled == false
        lock.unlock()
        return shouldReturn
    }

    var isCancelled: Bool {
        lock.lock()
        let value = cancelled
        lock.unlock()
        return value
    }

    func cancelStoredSession() {
        lock.lock()
        let session = session
        lock.unlock()

        session?.disconnect { _ in
        }
    }
}

public extension SSHClient {
    static func withConnection<Result>(
        _ configuration: SSHClientConfiguration,
        operation: (SSHConnection) async throws -> Result
    ) async throws -> Result {
        let connection = try await connect(configuration: configuration)
        do {
            let value = try await operation(connection)
            try await connection.close()
            return value
        } catch {
            try? await connection.close()
            throw error
        }
    }
}
