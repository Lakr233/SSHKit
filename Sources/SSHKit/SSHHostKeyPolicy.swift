import Foundation

public enum SSHHostKeyPolicy: Sendable {
    case insecureAcceptAnyHostKey
    case knownHostsFile(String)
    case pinnedFingerprint(SSHHostKeyFingerprint)
    case trustStore(any SSHHostTrustStore)

    var diagnosticName: String {
        switch self {
        case .insecureAcceptAnyHostKey:
            "insecureAcceptAnyHostKey"
        case .knownHostsFile:
            "knownHostsFile"
        case .pinnedFingerprint:
            "pinnedFingerprint"
        case .trustStore:
            "trustStore"
        }
    }
}
