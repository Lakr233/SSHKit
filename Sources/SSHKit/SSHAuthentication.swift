import Foundation

public enum SSHAuthentication: Equatable {
    case password(String)
    case privateKeyFile(path: String, passphrase: String? = nil)
}
