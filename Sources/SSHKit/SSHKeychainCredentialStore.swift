import Foundation
import KeychainAccess

public struct SSHPrivateKeyCredential: Codable, Equatable, Sendable {
    public var privateKeyOpenSSH: String
    public var passphrase: String?

    public init(privateKeyOpenSSH: String, passphrase: String? = nil) {
        precondition(privateKeyOpenSSH.isEmpty == false, "Private key must not be empty.")
        self.privateKeyOpenSSH = privateKeyOpenSSH
        self.passphrase = passphrase
    }
}

public struct SSHKeychainCredentialStore: @unchecked Sendable {
    public static let defaultService = "wiki.qaq.sshkit.credentials"

    private let keychain: Keychain

    public init(service: String = SSHKeychainCredentialStore.defaultService, accessGroup: String? = nil) {
        precondition(service.isEmpty == false, "Keychain service must not be empty.")
        if let accessGroup {
            keychain = Keychain(service: service, accessGroup: accessGroup)
        } else {
            keychain = Keychain(service: service)
        }
    }

    public func savePassword(_ password: String, account: String) throws {
        precondition(account.isEmpty == false, "Keychain account must not be empty.")
        try keychain.set(password, key: passwordKey(account: account))
    }

    public func password(account: String) throws -> String? {
        precondition(account.isEmpty == false, "Keychain account must not be empty.")
        return try keychain.get(passwordKey(account: account))
    }

    public func savePrivateKey(_ credential: SSHPrivateKeyCredential, account: String) throws {
        precondition(account.isEmpty == false, "Keychain account must not be empty.")
        let data = try JSONEncoder().encode(credential)
        try keychain.set(data, key: privateKeyKey(account: account))
    }

    public func privateKey(account: String) throws -> SSHPrivateKeyCredential? {
        precondition(account.isEmpty == false, "Keychain account must not be empty.")
        guard let data = try keychain.getData(privateKeyKey(account: account)) else {
            return nil
        }
        return try JSONDecoder().decode(SSHPrivateKeyCredential.self, from: data)
    }

    public func removeCredentials(account: String) throws {
        precondition(account.isEmpty == false, "Keychain account must not be empty.")
        var removalError: Error?
        do {
            try keychain.remove(passwordKey(account: account))
        } catch {
            removalError = error
        }
        do {
            try keychain.remove(privateKeyKey(account: account))
        } catch {
            if removalError == nil {
                removalError = error
            }
        }
        if let removalError {
            throw removalError
        }
    }

    private func passwordKey(account: String) -> String {
        "password:\(account)"
    }

    private func privateKeyKey(account: String) -> String {
        "privateKey:\(account)"
    }
}
