import Foundation
import SSHKitObjC

public final class SSHConnection {
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
}
