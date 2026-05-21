import Foundation
import SSHKit

enum HostTrustStoreFactory {
    static let keychainServiceName = "wiki.qaq.sshkit"

    static func makeDefault() -> SSHKeychainHostTrustStore {
        SSHKeychainHostTrustStore(service: keychainServiceName)
    }
}
