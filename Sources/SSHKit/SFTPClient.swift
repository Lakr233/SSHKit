import Foundation
import SSHKitObjC

public struct SFTPEntry: Equatable, Sendable {
    public var filename: String
    public var attributes: SFTPAttributes?

    public init(filename: String, attributes: SFTPAttributes? = nil) {
        self.filename = filename
        self.attributes = attributes
    }
}

public struct SFTPAttributes: Equatable, Sendable {
    public var size: UInt64
    public var permissions: UInt32
    public var uid: UInt32
    public var gid: UInt32
    public var type: UInt8
    public var accessedAt: Date?
    public var modifiedAt: Date?

    public init(
        size: UInt64,
        permissions: UInt32,
        uid: UInt32,
        gid: UInt32,
        type: UInt8,
        accessedAt: Date? = nil,
        modifiedAt: Date? = nil,
    ) {
        self.size = size
        self.permissions = permissions
        self.uid = uid
        self.gid = gid
        self.type = type
        self.accessedAt = accessedAt
        self.modifiedAt = modifiedAt
    }

    init(_ attributes: SSHKitObjC.SSHKitSFTPAttributes) {
        self.init(
            size: attributes.size,
            permissions: attributes.permissions,
            uid: attributes.uid,
            gid: attributes.gid,
            type: attributes.type,
            accessedAt: attributes.accessedAt,
            modifiedAt: attributes.modifiedAt,
        )
    }
}

public struct SFTPFileOpenFlags: OptionSet, Sendable {
    public let rawValue: UInt

    public init(rawValue: UInt) {
        self.rawValue = rawValue
    }

    public static let read = SFTPFileOpenFlags(rawValue: 1 << 0)
    public static let write = SFTPFileOpenFlags(rawValue: 1 << 1)
    public static let create = SFTPFileOpenFlags(rawValue: 1 << 2)
    public static let truncate = SFTPFileOpenFlags(rawValue: 1 << 3)
    public static let append = SFTPFileOpenFlags(rawValue: 1 << 4)
}

public final class SFTPFileHandle: @unchecked Sendable {
    private let handle: SSHKitObjC.SSHKitSFTPFileHandle
    private let cancelConnection: @Sendable () -> Void

    init(handle: SSHKitObjC.SSHKitSFTPFileHandle, cancelConnection: @escaping @Sendable () -> Void) {
        self.handle = handle
        self.cancelConnection = cancelConnection
    }

    deinit {
        handle.close { _ in }
    }

    public func readData(
        maximumLength: Int,
        callbackQueue: DispatchQueue = .main,
        completion: @escaping (Result<Data, SSHKitError>) -> Void,
    ) {
        precondition(maximumLength > 0, "SFTP file read length must be greater than zero.")

        handle.readData(withMaximumLength: UInt(maximumLength)) { data, error in
            if let error = error as NSError? {
                callbackQueue.async { completion(.failure(SSHKitError(error))) }
                return
            }
            guard let data else {
                callbackQueue.async {
                    completion(.failure(SSHKitError(code: SSHKitErrorCode.unavailable.rawValue, message: "SFTP file handle read completed without data.")))
                }
                return
            }
            callbackQueue.async { completion(.success(data)) }
        }
    }

    public func writeData(
        _ data: Data,
        callbackQueue: DispatchQueue = .main,
        completion: @escaping (Result<Void, SSHKitError>) -> Void,
    ) {
        precondition(data.isEmpty == false, "SFTP file write data must not be empty.")
        handle.write(data) { error in
            SFTPClient.complete(error: error, callbackQueue: callbackQueue, completion: completion)
        }
    }

    public func seek(
        to offset: UInt64,
        callbackQueue: DispatchQueue = .main,
        completion: @escaping (Result<Void, SSHKitError>) -> Void,
    ) {
        handle.seek(toOffset: offset) { error in
            SFTPClient.complete(error: error, callbackQueue: callbackQueue, completion: completion)
        }
    }

    public func close(
        callbackQueue: DispatchQueue = .main,
        completion: @escaping (Result<Void, SSHKitError>) -> Void,
    ) {
        handle.close { error in
            SFTPClient.complete(error: error, callbackQueue: callbackQueue, completion: completion)
        }
    }

    public func readData(maximumLength: Int) async throws -> Data {
        try await withCancellation { completion in
            readData(maximumLength: maximumLength, callbackQueue: .global(), completion: completion)
        }
    }

    public func writeData(_ data: Data) async throws {
        try await withCancellation { completion in
            writeData(data, callbackQueue: .global(), completion: completion)
        }
    }

    public func seek(to offset: UInt64) async throws {
        try await withCancellation { completion in
            seek(to: offset, callbackQueue: .global(), completion: completion)
        }
    }

    public func close() async throws {
        try await withCheckedThrowingContinuation { continuation in
            close(callbackQueue: .global()) { result in
                continuation.resume(with: result)
            }
        }
    }

    private func withCancellation<Value>(
        _ operation: (@escaping (Result<Value, SSHKitError>) -> Void) -> Void,
    ) async throws -> Value {
        try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                operation { result in
                    continuation.resume(with: result)
                }
            }
        } onCancel: {
            cancelConnection()
        }
    }
}

public final class SFTPClient: @unchecked Sendable {
    private let client: SSHKitObjC.SSHKitSFTPClient
    private let cancelConnection: @Sendable () -> Void

    init(client: SSHKitObjC.SSHKitSFTPClient, cancelConnection: @escaping @Sendable () -> Void) {
        self.client = client
        self.cancelConnection = cancelConnection
    }

    deinit {
        client.close { _ in }
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

            let swiftEntries = (entries ?? []).map { entry in
                SFTPEntry(filename: entry.filename, attributes: entry.attributes.map(SFTPAttributes.init))
            }
            callbackQueue.async {
                completion(.success(swiftEntries))
            }
        }
    }

    public func realpath(_ path: String, callbackQueue: DispatchQueue = .main, completion: @escaping (Result<String, SSHKitError>) -> Void) {
        precondition(path.isEmpty == false, "SFTP path must not be empty.")
        client.realpath(path) { value, error in
            Self.complete(value: value, missingMessage: "SFTP realpath completed without a path.", error: error, callbackQueue: callbackQueue, completion: completion)
        }
    }

    public func stat(_ path: String, callbackQueue: DispatchQueue = .main, completion: @escaping (Result<SFTPAttributes, SSHKitError>) -> Void) {
        precondition(path.isEmpty == false, "SFTP path must not be empty.")
        client.statPath(path) { attributes, error in
            Self.complete(attributes: attributes, error: error, callbackQueue: callbackQueue, completion: completion)
        }
    }

    public func lstat(_ path: String, callbackQueue: DispatchQueue = .main, completion: @escaping (Result<SFTPAttributes, SSHKitError>) -> Void) {
        precondition(path.isEmpty == false, "SFTP path must not be empty.")
        client.lstatPath(path) { attributes, error in
            Self.complete(attributes: attributes, error: error, callbackQueue: callbackQueue, completion: completion)
        }
    }

    public func setPermissions(_ permissions: UInt32, at path: String, callbackQueue: DispatchQueue = .main, completion: @escaping (Result<Void, SSHKitError>) -> Void) {
        precondition(path.isEmpty == false, "SFTP path must not be empty.")
        client.setPermissions(permissions, atPath: path) { error in
            Self.complete(error: error, callbackQueue: callbackQueue, completion: completion)
        }
    }

    public func fileSystemAttributes(at path: String, callbackQueue: DispatchQueue = .main, completion: @escaping (Result<[String: UInt64], SSHKitError>) -> Void) {
        precondition(path.isEmpty == false, "SFTP path must not be empty.")
        client.fileSystemAttributes(atPath: path) { attributes, error in
            if let error = error as NSError? {
                callbackQueue.async { completion(.failure(SSHKitError(error))) }
                return
            }
            guard let attributes else {
                callbackQueue.async {
                    completion(.failure(SSHKitError(code: SSHKitErrorCode.unavailable.rawValue, message: "SFTP filesystem stat completed without attributes.")))
                }
                return
            }
            callbackQueue.async {
                completion(.success(attributes.mapValues { $0.uint64Value }))
            }
        }
    }

    public func createDirectory(_ path: String, permissions: UInt32 = 0o755, callbackQueue: DispatchQueue = .main, completion: @escaping (Result<Void, SSHKitError>) -> Void) {
        precondition(path.isEmpty == false, "SFTP directory path must not be empty.")
        client.createDirectory(atPath: path, permissions: permissions) { error in
            Self.complete(error: error, callbackQueue: callbackQueue, completion: completion)
        }
    }

    public func removeDirectory(_ path: String, callbackQueue: DispatchQueue = .main, completion: @escaping (Result<Void, SSHKitError>) -> Void) {
        precondition(path.isEmpty == false, "SFTP directory path must not be empty.")
        client.removeDirectory(atPath: path) { error in
            Self.complete(error: error, callbackQueue: callbackQueue, completion: completion)
        }
    }

    public func removeFile(_ path: String, callbackQueue: DispatchQueue = .main, completion: @escaping (Result<Void, SSHKitError>) -> Void) {
        precondition(path.isEmpty == false, "SFTP file path must not be empty.")
        client.removeFile(atPath: path) { error in
            Self.complete(error: error, callbackQueue: callbackQueue, completion: completion)
        }
    }

    public func rename(_ sourcePath: String, to destinationPath: String, callbackQueue: DispatchQueue = .main, completion: @escaping (Result<Void, SSHKitError>) -> Void) {
        precondition(sourcePath.isEmpty == false, "SFTP source path must not be empty.")
        precondition(destinationPath.isEmpty == false, "SFTP destination path must not be empty.")
        client.renamePath(sourcePath, toPath: destinationPath) { error in
            Self.complete(error: error, callbackQueue: callbackQueue, completion: completion)
        }
    }

    public func readLink(_ path: String, callbackQueue: DispatchQueue = .main, completion: @escaping (Result<String, SSHKitError>) -> Void) {
        precondition(path.isEmpty == false, "SFTP link path must not be empty.")
        client.readLink(atPath: path) { value, error in
            Self.complete(value: value, missingMessage: "SFTP readlink completed without a target.", error: error, callbackQueue: callbackQueue, completion: completion)
        }
    }

    public func createSymbolicLink(_ linkPath: String, targetPath: String, callbackQueue: DispatchQueue = .main, completion: @escaping (Result<Void, SSHKitError>) -> Void) {
        precondition(linkPath.isEmpty == false, "SFTP link path must not be empty.")
        precondition(targetPath.isEmpty == false, "SFTP target path must not be empty.")
        client.createSymbolicLink(atPath: linkPath, targetPath: targetPath) { error in
            Self.complete(error: error, callbackQueue: callbackQueue, completion: completion)
        }
    }

    public func openFile(
        _ path: String,
        flags: SFTPFileOpenFlags,
        permissions: UInt32 = 0o600,
        callbackQueue: DispatchQueue = .main,
        completion: @escaping (Result<SFTPFileHandle, SSHKitError>) -> Void,
    ) {
        precondition(path.isEmpty == false, "SFTP file path must not be empty.")
        precondition(flags.isEmpty == false, "SFTP file open flags must not be empty.")

        client.openFile(
            atPath: path,
            flags: SSHKitObjC.SSHKitSFTPFileOpenFlags(rawValue: flags.rawValue),
            permissions: permissions,
        ) { handle, error in
            if let error = error as NSError? {
                callbackQueue.async { completion(.failure(SSHKitError(error))) }
                return
            }
            guard let handle else {
                callbackQueue.async {
                    completion(.failure(SSHKitError(code: SSHKitErrorCode.unavailable.rawValue, message: "SFTP file open completed without a handle.")))
                }
                return
            }
            callbackQueue.async {
                completion(.success(SFTPFileHandle(handle: handle, cancelConnection: self.cancelConnection)))
            }
        }
    }

    public func readFile(_ path: String, callbackQueue: DispatchQueue = .main, completion: @escaping (Result<Data, SSHKitError>) -> Void) {
        precondition(path.isEmpty == false, "SFTP file path must not be empty.")
        client.readFile(atPath: path) { data, error in
            if let error = error as NSError? {
                callbackQueue.async { completion(.failure(SSHKitError(error))) }
                return
            }
            guard let data else {
                callbackQueue.async {
                    completion(.failure(SSHKitError(code: SSHKitErrorCode.unavailable.rawValue, message: "SFTP read completed without data.")))
                }
                return
            }
            callbackQueue.async { completion(.success(data)) }
        }
    }

    public func writeFile(_ data: Data, to path: String, callbackQueue: DispatchQueue = .main, completion: @escaping (Result<Void, SSHKitError>) -> Void) {
        precondition(path.isEmpty == false, "SFTP file path must not be empty.")
        client.write(data, toFileAtPath: path) { error in
            Self.complete(error: error, callbackQueue: callbackQueue, completion: completion)
        }
    }

    public func download(
        remotePath: String,
        to localURL: URL,
        progress: (@Sendable (UInt64, UInt64) -> Void)? = nil,
        callbackQueue: DispatchQueue = .main,
        completion: @escaping (Result<Void, SSHKitError>) -> Void,
    ) {
        precondition(remotePath.isEmpty == false, "SFTP remote download path must not be empty.")
        precondition(localURL.path.isEmpty == false, "SFTP local download path must not be empty.")

        let deliveryQueue = Self.makeTransferDeliveryQueue(target: callbackQueue)
        client.downloadFile(atPath: remotePath, toLocalPath: localURL.path, progress: Self.wrapProgress(progress, deliveryQueue: deliveryQueue)) { error in
            Self.complete(error: error, callbackQueue: deliveryQueue, completion: completion)
        }
    }

    public func resumeDownload(
        remotePath: String,
        to localURL: URL,
        progress: (@Sendable (UInt64, UInt64) -> Void)? = nil,
        callbackQueue: DispatchQueue = .main,
        completion: @escaping (Result<Void, SSHKitError>) -> Void,
    ) {
        precondition(remotePath.isEmpty == false, "SFTP remote download path must not be empty.")
        precondition(localURL.path.isEmpty == false, "SFTP local download path must not be empty.")

        let deliveryQueue = Self.makeTransferDeliveryQueue(target: callbackQueue)
        client.resumeDownloadFile(atPath: remotePath, toLocalPath: localURL.path, progress: Self.wrapProgress(progress, deliveryQueue: deliveryQueue)) { error in
            Self.complete(error: error, callbackQueue: deliveryQueue, completion: completion)
        }
    }

    public func upload(
        localURL: URL,
        to remotePath: String,
        progress: (@Sendable (UInt64, UInt64) -> Void)? = nil,
        callbackQueue: DispatchQueue = .main,
        completion: @escaping (Result<Void, SSHKitError>) -> Void,
    ) {
        precondition(localURL.path.isEmpty == false, "SFTP local upload path must not be empty.")
        precondition(remotePath.isEmpty == false, "SFTP remote upload path must not be empty.")

        let deliveryQueue = Self.makeTransferDeliveryQueue(target: callbackQueue)
        client.uploadFile(atPath: localURL.path, toRemotePath: remotePath, progress: Self.wrapProgress(progress, deliveryQueue: deliveryQueue)) { error in
            Self.complete(error: error, callbackQueue: deliveryQueue, completion: completion)
        }
    }

    public func resumeUpload(
        localURL: URL,
        to remotePath: String,
        progress: (@Sendable (UInt64, UInt64) -> Void)? = nil,
        callbackQueue: DispatchQueue = .main,
        completion: @escaping (Result<Void, SSHKitError>) -> Void,
    ) {
        precondition(localURL.path.isEmpty == false, "SFTP local upload path must not be empty.")
        precondition(remotePath.isEmpty == false, "SFTP remote upload path must not be empty.")

        let deliveryQueue = Self.makeTransferDeliveryQueue(target: callbackQueue)
        client.resumeUploadFile(atPath: localURL.path, toRemotePath: remotePath, progress: Self.wrapProgress(progress, deliveryQueue: deliveryQueue)) { error in
            Self.complete(error: error, callbackQueue: deliveryQueue, completion: completion)
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
        try await withCancellation { completion in
            listDirectory(path, callbackQueue: .global()) { result in
                completion(result)
            }
        }
    }

    public func realpath(_ path: String) async throws -> String {
        try await withCancellation { completion in realpath(path, callbackQueue: .global(), completion: completion) }
    }

    public func stat(_ path: String) async throws -> SFTPAttributes {
        try await withCancellation { completion in stat(path, callbackQueue: .global(), completion: completion) }
    }

    public func lstat(_ path: String) async throws -> SFTPAttributes {
        try await withCancellation { completion in lstat(path, callbackQueue: .global(), completion: completion) }
    }

    public func setPermissions(_ permissions: UInt32, at path: String) async throws {
        try await withCancellation { completion in setPermissions(permissions, at: path, callbackQueue: .global(), completion: completion) }
    }

    public func fileSystemAttributes(at path: String) async throws -> [String: UInt64] {
        try await withCancellation { completion in fileSystemAttributes(at: path, callbackQueue: .global(), completion: completion) }
    }

    public func createDirectory(_ path: String, permissions: UInt32 = 0o755) async throws {
        try await withCancellation { completion in createDirectory(path, permissions: permissions, callbackQueue: .global(), completion: completion) }
    }

    public func removeDirectory(_ path: String) async throws {
        try await withCancellation { completion in removeDirectory(path, callbackQueue: .global(), completion: completion) }
    }

    public func removeFile(_ path: String) async throws {
        try await withCancellation { completion in removeFile(path, callbackQueue: .global(), completion: completion) }
    }

    public func rename(_ sourcePath: String, to destinationPath: String) async throws {
        try await withCancellation { completion in rename(sourcePath, to: destinationPath, callbackQueue: .global(), completion: completion) }
    }

    public func readLink(_ path: String) async throws -> String {
        try await withCancellation { completion in readLink(path, callbackQueue: .global(), completion: completion) }
    }

    public func createSymbolicLink(_ linkPath: String, targetPath: String) async throws {
        try await withCancellation { completion in createSymbolicLink(linkPath, targetPath: targetPath, callbackQueue: .global(), completion: completion) }
    }

    public func openFile(_ path: String, flags: SFTPFileOpenFlags, permissions: UInt32 = 0o600) async throws -> SFTPFileHandle {
        try await withCancellation { completion in openFile(path, flags: flags, permissions: permissions, callbackQueue: .global(), completion: completion) }
    }

    public func readFile(_ path: String) async throws -> Data {
        try await withCancellation { completion in readFile(path, callbackQueue: .global(), completion: completion) }
    }

    public func writeFile(_ data: Data, to path: String) async throws {
        try await withCancellation { completion in writeFile(data, to: path, callbackQueue: .global(), completion: completion) }
    }

    public func download(remotePath: String, to localURL: URL, progress: (@Sendable (UInt64, UInt64) -> Void)? = nil) async throws {
        try await withCancellation { completion in
            download(remotePath: remotePath, to: localURL, progress: progress, callbackQueue: .global(), completion: completion)
        }
    }

    public func upload(localURL: URL, to remotePath: String, progress: (@Sendable (UInt64, UInt64) -> Void)? = nil) async throws {
        try await withCancellation { completion in
            upload(localURL: localURL, to: remotePath, progress: progress, callbackQueue: .global(), completion: completion)
        }
    }

    public func resumeDownload(remotePath: String, to localURL: URL, progress: (@Sendable (UInt64, UInt64) -> Void)? = nil) async throws {
        try await withCancellation { completion in
            resumeDownload(remotePath: remotePath, to: localURL, progress: progress, callbackQueue: .global(), completion: completion)
        }
    }

    public func resumeUpload(localURL: URL, to remotePath: String, progress: (@Sendable (UInt64, UInt64) -> Void)? = nil) async throws {
        try await withCancellation { completion in
            resumeUpload(localURL: localURL, to: remotePath, progress: progress, callbackQueue: .global(), completion: completion)
        }
    }

    public func close() async throws {
        try await withCheckedThrowingContinuation { continuation in
            close(callbackQueue: .global()) { result in
                continuation.resume(with: result)
            }
        }
    }

    fileprivate static func complete(
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

    private static func complete(
        value: String?,
        missingMessage: String,
        error: Error?,
        callbackQueue: DispatchQueue,
        completion: @escaping (Result<String, SSHKitError>) -> Void,
    ) {
        if let error = error as NSError? {
            callbackQueue.async { completion(.failure(SSHKitError(error))) }
            return
        }
        guard let value else {
            callbackQueue.async { completion(.failure(SSHKitError(code: SSHKitErrorCode.unavailable.rawValue, message: missingMessage))) }
            return
        }
        callbackQueue.async { completion(.success(value)) }
    }

    private static func complete(
        attributes: SSHKitObjC.SSHKitSFTPAttributes?,
        error: Error?,
        callbackQueue: DispatchQueue,
        completion: @escaping (Result<SFTPAttributes, SSHKitError>) -> Void,
    ) {
        if let error = error as NSError? {
            callbackQueue.async { completion(.failure(SSHKitError(error))) }
            return
        }
        guard let attributes else {
            callbackQueue.async { completion(.failure(SSHKitError(code: SSHKitErrorCode.unavailable.rawValue, message: "SFTP stat completed without attributes."))) }
            return
        }
        callbackQueue.async { completion(.success(SFTPAttributes(attributes))) }
    }

    private static func wrapProgress(
        _ progress: (@Sendable (UInt64, UInt64) -> Void)?,
        deliveryQueue: DispatchQueue,
    ) -> SSHKitSFTPProgressHandler? {
        guard let progress else {
            return nil
        }
        return { completedBytes, totalBytes in
            deliveryQueue.async {
                progress(completedBytes, totalBytes)
            }
        }
    }

    private static func makeTransferDeliveryQueue(target: DispatchQueue) -> DispatchQueue {
        DispatchQueue(label: "io.github.sshkit.sftp.transfer-delivery", target: target)
    }

    private func withCancellation<Value>(
        _ operation: (@escaping (Result<Value, SSHKitError>) -> Void) -> Void,
    ) async throws -> Value {
        let cancellation = SSHAsyncCancellationBox()
        return try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                operation { result in
                    guard let result = cancellation.complete(result) else {
                        return
                    }
                    continuation.resume(with: result)
                }
            }
        } onCancel: {
            cancellation.cancel {
                cancelConnection()
            }
        }
    }
}
