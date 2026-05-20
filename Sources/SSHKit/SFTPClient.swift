import Foundation
import SSHKitObjC

public struct SFTPEntry: Equatable, Sendable {
    public var filename: String

    public init(filename: String) {
        self.filename = filename
    }
}

public final class SFTPClient: @unchecked Sendable {
    private let client: SSHKitObjC.SSHKitSFTPClient

    init(client: SSHKitObjC.SSHKitSFTPClient) {
        self.client = client
    }

    public func listDirectory(
        _ path: String,
        callbackQueue: DispatchQueue = .main,
        completion: @escaping (Result<[SFTPEntry], SSHKitError>) -> Void,
    ) {
        precondition(path.isEmpty == false, "SFTP directory path must not be empty.")

        client.listDirectory(path) { entries, error in
            if let error = error as NSError? {
                callbackQueue.async {
                    completion(.failure(SSHKitError(error)))
                }
                return
            }

            let swiftEntries = (entries ?? []).map { SFTPEntry(filename: $0.filename) }
            callbackQueue.async {
                completion(.success(swiftEntries))
            }
        }
    }

    public func download(
        remotePath: String,
        to localURL: URL,
        callbackQueue: DispatchQueue = .main,
        completion: @escaping (Result<Void, SSHKitError>) -> Void,
    ) {
        precondition(remotePath.isEmpty == false, "SFTP remote download path must not be empty.")
        precondition(localURL.path.isEmpty == false, "SFTP local download path must not be empty.")

        client.downloadFile(atPath: remotePath, toLocalPath: localURL.path) { error in
            Self.complete(error: error, callbackQueue: callbackQueue, completion: completion)
        }
    }

    public func upload(
        localURL: URL,
        to remotePath: String,
        callbackQueue: DispatchQueue = .main,
        completion: @escaping (Result<Void, SSHKitError>) -> Void,
    ) {
        precondition(localURL.path.isEmpty == false, "SFTP local upload path must not be empty.")
        precondition(remotePath.isEmpty == false, "SFTP remote upload path must not be empty.")

        client.uploadFile(atPath: localURL.path, toRemotePath: remotePath) { error in
            Self.complete(error: error, callbackQueue: callbackQueue, completion: completion)
        }
    }

    public func close(
        callbackQueue: DispatchQueue = .main,
        completion: @escaping (Result<Void, SSHKitError>) -> Void,
    ) {
        client.close { error in
            Self.complete(error: error, callbackQueue: callbackQueue, completion: completion)
        }
    }

    public func listDirectory(_ path: String) async throws -> [SFTPEntry] {
        try await withCheckedThrowingContinuation { continuation in
            listDirectory(path, callbackQueue: .global()) { result in
                continuation.resume(with: result)
            }
        }
    }

    public func download(remotePath: String, to localURL: URL) async throws {
        try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                download(remotePath: remotePath, to: localURL, callbackQueue: .global()) { result in
                    continuation.resume(with: result)
                }
            }
        } onCancel: {
            close(callbackQueue: .global()) { _ in
            }
        }
    }

    public func upload(localURL: URL, to remotePath: String) async throws {
        try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                upload(localURL: localURL, to: remotePath, callbackQueue: .global()) { result in
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
