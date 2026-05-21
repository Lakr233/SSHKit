import Foundation
import SSHKitObjC

public struct SSHDiscoveredHostKey: Equatable, Sendable {
    public let host: String
    public let port: UInt16
    public let fingerprint: SSHHostKeyFingerprint

    public init(host: String, port: UInt16, fingerprint: SSHHostKeyFingerprint) {
        precondition(host.isEmpty == false, "Host key discovery host must not be empty.")
        precondition(port > 0, "Host key discovery port must be greater than zero.")
        self.host = host
        self.port = port
        self.fingerprint = fingerprint
    }

    init(_ result: SSHKitHostKeyDiscoveryResult) {
        self.init(
            host: result.host,
            port: result.port,
            fingerprint: SSHHostKeyFingerprint(result.fingerprint)
        )
    }
}

public struct SSHHostKeyDiscoveryConfiguration: Sendable {
    public var host: String
    public var port: UInt16
    public var timeout: TimeInterval
    public var logHandler: SSHLogHandler?
    public var proxyRoute: SSHProxyRoute?
    public var algorithmProfile: SSHAlgorithmProfile

    public init(
        host: String,
        port: UInt16 = 22,
        timeout: TimeInterval = 30,
        logHandler: SSHLogHandler? = nil,
        proxyRoute: SSHProxyRoute? = nil,
        algorithmProfile: SSHAlgorithmProfile = .modern
    ) {
        precondition(host.isEmpty == false, "Host key discovery host must not be empty.")
        precondition(port > 0, "Host key discovery port must be greater than zero.")
        precondition(timeout > 0, "Host key discovery timeout must be greater than zero.")
        self.host = host
        self.port = port
        self.timeout = timeout
        self.logHandler = logHandler
        self.proxyRoute = proxyRoute
        self.algorithmProfile = algorithmProfile
    }
}
