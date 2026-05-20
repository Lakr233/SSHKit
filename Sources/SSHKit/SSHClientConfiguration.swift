import Foundation

public struct SSHClientConfiguration: Equatable, Sendable {
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
        self.host = host
        self.port = port
        self.username = username
        self.authentication = authentication
        self.hostKeyPolicy = hostKeyPolicy
        self.timeout = timeout
    }
}
