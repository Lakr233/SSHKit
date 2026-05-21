import Foundation

final class SSHAsyncCancellationBox: @unchecked Sendable {
    private let lock = NSLock()
    private var cancelled = false
    private var completed = false

    func cancel(_ handler: () -> Void) {
        lock.lock()
        cancelled = true
        let shouldCancel = completed == false
        lock.unlock()

        if shouldCancel {
            handler()
        }
    }

    func complete<Value>(_ result: Result<Value, SSHKitError>) -> Result<Value, SSHKitError>? {
        lock.lock()
        guard completed == false else {
            lock.unlock()
            return nil
        }
        completed = true
        let shouldReturnCancellation = cancelled
        lock.unlock()

        if shouldReturnCancellation {
            return .failure(SSHKitError(code: SSHKitErrorCode.cancelled.rawValue, message: "SSH operation was cancelled."))
        }
        return result
    }
}
