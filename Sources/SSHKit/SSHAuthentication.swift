import Foundation

public enum SSHAuthentication: Equatable, Sendable {
    case password(String)
    case privateKeyFile(path: String, passphrase: String? = nil)
}
