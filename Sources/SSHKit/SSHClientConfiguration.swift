import Foundation

public struct SSHClientConfiguration: Sendable {
    public var host: String
    public var port: UInt16
    public var username: String
    public var authentication: SSHAuthentication
    public var hostKeyPolicy: SSHHostKeyPolicy
    public var timeout: TimeInterval
    public var logHandler: SSHLogHandler?

    public init(
        host: String,
        port: UInt16 = 22,
        username: String,
        authentication: SSHAuthentication,
        hostKeyPolicy: SSHHostKeyPolicy,
        timeout: TimeInterval = 30,
        logHandler: SSHLogHandler? = nil,
    ) {
        self.host = host
        self.port = port
        self.username = username
        self.authentication = authentication
        self.hostKeyPolicy = hostKeyPolicy
        self.timeout = timeout
        self.logHandler = logHandler
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
