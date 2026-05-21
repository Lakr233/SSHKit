import Foundation
import SSHKitObjC

public final class SSHPortForward: @unchecked Sendable {
    public let boundHost: String
    public let boundPort: UInt16

    private let forward: SSHKitObjC.SSHKitPortForward

    init(forward: SSHKitObjC.SSHKitPortForward) {
        self.forward = forward
        boundHost = forward.boundHost
        boundPort = forward.boundPort
    }

    public func close(
        callbackQueue: DispatchQueue = .main,
        completion: @escaping (Result<Void, SSHKitError>) -> Void
    ) {
        forward.close { error in
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

    public func close() async throws {
        try await withCheckedThrowingContinuation { continuation in
            close(callbackQueue: .global()) { result in
                continuation.resume(with: result)
            }
        }
    }
}
