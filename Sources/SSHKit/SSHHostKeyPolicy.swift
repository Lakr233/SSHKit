import Foundation

public enum SSHHostKeyPolicy: Equatable, Sendable {
    case acceptAnyVerifiedHostKey
    case knownHostsFile(String)
}
