import Foundation
import KeychainAccess

public struct SSHHostKeyFingerprint: Equatable, Codable, Sendable {
    public var rawValue: String

    public init(_ rawValue: String) {
        let normalizedValue = rawValue.trimmingCharacters(in: .whitespacesAndNewlines)
        precondition(normalizedValue.isEmpty == false, "Host key fingerprint must not be empty.")
        if normalizedValue.range(of: "SHA256:", options: [.caseInsensitive, .anchored]) != nil {
            self.rawValue = normalizedValue
        } else {
            self.rawValue = "SHA256:\(normalizedValue)"
        }
    }
}

public protocol SSHHostTrustStore: Sendable {
    func fingerprint(host: String, port: UInt16) throws -> SSHHostKeyFingerprint?
    func saveFingerprint(_ fingerprint: SSHHostKeyFingerprint, host: String, port: UInt16) throws
    func removeFingerprint(host: String, port: UInt16) throws
}

public final class SSHMemoryHostTrustStore: SSHHostTrustStore, @unchecked Sendable {
    private let lock = NSLock()
    private var fingerprints: [String: SSHHostKeyFingerprint]

    public init(fingerprints: [String: SSHHostKeyFingerprint] = [:]) {
        self.fingerprints = fingerprints
    }

    public func fingerprint(host: String, port: UInt16) throws -> SSHHostKeyFingerprint? {
        lock.lock()
        let fingerprint = fingerprints[key(host: host, port: port)]
        lock.unlock()
        return fingerprint
    }

    public func saveFingerprint(_ fingerprint: SSHHostKeyFingerprint, host: String, port: UInt16) throws {
        lock.lock()
        fingerprints[key(host: host, port: port)] = fingerprint
        lock.unlock()
    }

    public func removeFingerprint(host: String, port: UInt16) throws {
        lock.lock()
        fingerprints.removeValue(forKey: key(host: host, port: port))
        lock.unlock()
    }

    private func key(host: String, port: UInt16) -> String {
        "\(host.lowercased()):\(port)"
    }
}

public struct SSHKeychainHostTrustStore: SSHHostTrustStore, @unchecked Sendable {
    public static let defaultService = "wiki.qaq.sshkit"

    private let keychain: Keychain

    public init(service: String = SSHKeychainHostTrustStore.defaultService, accessGroup: String? = nil) {
        precondition(service.isEmpty == false, "Keychain service must not be empty.")
        if let accessGroup {
            keychain = Keychain(service: service, accessGroup: accessGroup)
        } else {
            keychain = Keychain(service: service)
        }
    }

    public func fingerprint(host: String, port: UInt16) throws -> SSHHostKeyFingerprint? {
        try keychain.get(key(host: host, port: port)).map(SSHHostKeyFingerprint.init)
    }

    public func saveFingerprint(_ fingerprint: SSHHostKeyFingerprint, host: String, port: UInt16) throws {
        try keychain.set(fingerprint.rawValue, key: key(host: host, port: port))
    }

    public func removeFingerprint(host: String, port: UInt16) throws {
        try keychain.remove(key(host: host, port: port))
    }

    private func key(host: String, port: UInt16) -> String {
        "hostKey:\(host.lowercased()):\(port)"
    }
}
