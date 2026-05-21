import Foundation

public struct SSHCommandResult: Equatable, Sendable {
    public var standardOutput: Data
    public var standardError: Data
    public var exitStatus: Int32
    public var exitSignal: String?

    public init(standardOutput: Data, standardError: Data, exitStatus: Int32, exitSignal: String? = nil) {
        self.standardOutput = standardOutput
        self.standardError = standardError
        self.exitStatus = exitStatus
        self.exitSignal = exitSignal
    }
}
