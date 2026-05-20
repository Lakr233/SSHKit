import Foundation

public enum SSHHostKeyPolicy: Equatable {
    case acceptAnyVerifiedHostKey
    case knownHostsFile(String)
}
