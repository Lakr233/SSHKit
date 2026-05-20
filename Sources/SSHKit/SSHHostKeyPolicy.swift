import Foundation

public enum SSHHostKeyPolicy: Equatable, Sendable {
    case insecureAcceptAnyHostKey
    case knownHostsFile(String)

    var diagnosticName: String {
        switch self {
        case .insecureAcceptAnyHostKey:
            "insecureAcceptAnyHostKey"
        case .knownHostsFile:
            "knownHostsFile"
        }
    }
}
