import Foundation

public enum SSHPortLatencyRoute: Equatable, Sendable {
    case direct
    case socks5(host: String, port: UInt16)
    case httpConnect(host: String, port: UInt16)
    case proxyJump(host: String, port: UInt16)

    init(proxyRoute: SSHProxyRoute?) {
        switch proxyRoute {
        case nil:
            self = .direct
        case let .socks5(endpoint):
            self = .socks5(host: endpoint.host, port: endpoint.port)
        case let .httpConnect(endpoint):
            self = .httpConnect(host: endpoint.host, port: endpoint.port)
        case let .proxyJump(jumpHost):
            self = .proxyJump(host: jumpHost.host, port: jumpHost.port)
        }
    }
}

public struct SSHPortLatencyReport: Equatable, Sendable {
    public var host: String
    public var port: UInt16
    public var route: SSHPortLatencyRoute
    public var connectDuration: TimeInterval
    public var sshServiceDuration: TimeInterval
    public var totalDuration: TimeInterval

    public init(
        host: String,
        port: UInt16,
        route: SSHPortLatencyRoute,
        connectDuration: TimeInterval,
        sshServiceDuration: TimeInterval,
        totalDuration: TimeInterval
    ) {
        self.host = host
        self.port = port
        self.route = route
        self.connectDuration = connectDuration
        self.sshServiceDuration = sshServiceDuration
        self.totalDuration = totalDuration
    }
}

public enum SSHPortLatencyProbe {
    public static func measure(
        configuration: SSHClientConfiguration,
        serviceCommand: String = "true"
    ) async throws -> SSHPortLatencyReport {
        precondition(serviceCommand.isEmpty == false, "Latency probe service command must not be empty.")

        let start = currentTime()
        let connection = try await SSHClient.connect(configuration: configuration)
        let connected = currentTime()

        do {
            let serviceStart = currentTime()
            let serviceResult = try await connection.execute(serviceCommand)
            let serviceEnd = currentTime()
            guard serviceResult.exitStatus == 0 else {
                throw SSHKitError(
                    code: SSHKitErrorCode.commandFailed.rawValue,
                    message: "SSH latency service command exited with status \(serviceResult.exitStatus)."
                )
            }
            try await connection.close()
            let finished = currentTime()
            return SSHPortLatencyReport(
                host: configuration.host,
                port: configuration.port,
                route: SSHPortLatencyRoute(proxyRoute: configuration.proxyRoute),
                connectDuration: connected - start,
                sshServiceDuration: serviceEnd - serviceStart,
                totalDuration: finished - start
            )
        } catch {
            try? await connection.close()
            throw error
        }
    }

    public static func measure(
        configuration: SSHClientConfiguration,
        serviceCommand: String = "true",
        callbackQueue: DispatchQueue = .main,
        completion: @escaping (Result<SSHPortLatencyReport, SSHKitError>) -> Void
    ) {
        Task {
            do {
                let report = try await measure(configuration: configuration, serviceCommand: serviceCommand)
                callbackQueue.async {
                    completion(.success(report))
                }
            } catch let error as SSHKitError {
                callbackQueue.async {
                    completion(.failure(error))
                }
            } catch {
                callbackQueue.async {
                    completion(.failure(SSHKitError(code: SSHKitErrorCode.unavailable.rawValue, message: error.localizedDescription)))
                }
            }
        }
    }

    private static func currentTime() -> TimeInterval {
        ProcessInfo.processInfo.systemUptime
    }
}
