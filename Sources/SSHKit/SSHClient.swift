import Foundation
import SSHKitObjC

public enum SSHClient {
    public static func connect(
        configuration: SSHClientConfiguration,
        callbackQueue: DispatchQueue = .main,
        completion: @escaping (Result<SSHConnection, SSHKitError>) -> Void,
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
                completion(.success(SSHConnection(session: session)))
            }
        }
    }
}
