import Foundation

public struct SSHCommandResult: Equatable {
    public var standardOutput: Data
    public var standardError: Data
    public var exitStatus: Int32

    public init(standardOutput: Data, standardError: Data, exitStatus: Int32) {
        self.standardOutput = standardOutput
        self.standardError = standardError
        self.exitStatus = exitStatus
    }
}
