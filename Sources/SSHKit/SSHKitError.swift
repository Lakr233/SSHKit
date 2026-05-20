import Foundation

public struct SSHKitError: Error, Equatable, LocalizedError {
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
        self.code = error.code
        self.message = error.localizedDescription
    }
}
