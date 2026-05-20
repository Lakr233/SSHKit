import Foundation
import SSHKitObjC

extension SSHClientConfiguration {
    var bridgeConfiguration: SSHKitConfiguration {
        let configuration = SSHKitConfiguration(host: host, username: username)
        configuration.port = port
        configuration.timeout = timeout

        switch authentication {
        case let .password(password):
            configuration.authenticationKind = .password
            configuration.password = password
        case let .privateKeyFile(path, passphrase):
            configuration.authenticationKind = .privateKeyFile
            configuration.privateKeyPath = path
            configuration.privateKeyPassphrase = passphrase
        }

        switch hostKeyPolicy {
        case .acceptAnyVerifiedHostKey:
            configuration.hostKeyPolicyKind = .acceptAnyVerifiedHostKey
        case let .knownHostsFile(path):
            configuration.hostKeyPolicyKind = .knownHostsFile
            configuration.knownHostsPath = path
        }

        return configuration
    }
}
