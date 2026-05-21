import Foundation

public struct SSHClientConfiguration: Sendable {
    public var host: String
    public var port: UInt16
    public var username: String
    public var authentication: SSHAuthentication
    public var hostKeyPolicy: SSHHostKeyPolicy
    public var timeout: TimeInterval
    public var logHandler: SSHLogHandler?
    public var proxyRoute: SSHProxyRoute?

    public init(
        host: String,
        port: UInt16 = 22,
        username: String,
        authentication: SSHAuthentication,
        hostKeyPolicy: SSHHostKeyPolicy,
        timeout: TimeInterval = 30,
        logHandler: SSHLogHandler? = nil,
        proxyRoute: SSHProxyRoute? = nil,
    ) {
        self.host = host
        self.port = port
        self.username = username
        self.authentication = authentication
        self.hostKeyPolicy = hostKeyPolicy
        self.timeout = timeout
        self.logHandler = logHandler
        self.proxyRoute = proxyRoute
    }

    public func diagnosticReport(
        phase: String = "configuration",
        metadata: [String: String] = [:],
        recentEvents: [SSHLogEvent] = [],
    ) -> SSHDiagnosticReport {
        SSHDiagnosticReport(
            phase: phase,
            host: host,
            port: port,
            username: username,
            authentication: authentication.diagnosticName,
            hostKeyPolicy: hostKeyPolicy.diagnosticName,
            metadata: metadata,
            recentEvents: recentEvents,
        )
    }
}

public struct SSHProxyEndpoint: Sendable {
    public var host: String
    public var port: UInt16
    public var username: String?
    public var password: String?

    public init(host: String, port: UInt16, username: String? = nil, password: String? = nil) {
        precondition(host.isEmpty == false, "Proxy host must not be empty.")
        precondition(port > 0, "Proxy port must be greater than zero.")
        self.host = host
        self.port = port
        self.username = username
        self.password = password
    }
}

public struct SSHJumpHost: Sendable {
    public var host: String
    public var port: UInt16
    public var username: String
    public var authentication: SSHAuthentication
    public var hostKeyPolicy: SSHHostKeyPolicy
    public var timeout: TimeInterval

    public init(
        host: String,
        port: UInt16 = 22,
        username: String,
        authentication: SSHAuthentication,
        hostKeyPolicy: SSHHostKeyPolicy,
        timeout: TimeInterval = 30,
    ) {
        precondition(host.isEmpty == false, "Jump host must not be empty.")
        precondition(port > 0, "Jump port must be greater than zero.")
        precondition(username.isEmpty == false, "Jump username must not be empty.")
        precondition(timeout > 0, "Jump timeout must be greater than zero.")
        self.host = host
        self.port = port
        self.username = username
        self.authentication = authentication
        self.hostKeyPolicy = hostKeyPolicy
        self.timeout = timeout
    }
}

public enum SSHProxyRoute: Sendable {
    case socks5(SSHProxyEndpoint)
    case httpConnect(SSHProxyEndpoint)
    case proxyJump(SSHJumpHost)
}
