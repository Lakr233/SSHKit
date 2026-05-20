import Foundation

public enum SSHKitErrorCode: Int, Sendable {
    case unavailable = 1
    case invalidState = 2
    case connectionFailed = 3
    case authenticationFailed = 4
    case commandFailed = 5
}

public struct SSHKitError: Error, Equatable, LocalizedError, Sendable {
    public var code: Int
    public var message: String

    public var errorDescription: String? {
        message
    }

    public init(code: Int, message: String) {
        self.code = code
        self.message = message
    }

    init(_ error: NSError) {
        code = error.code
        message = error.localizedDescription
    }
}
