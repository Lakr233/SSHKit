import Foundation
import Observation
import SSHKit

struct PendingEnrollment: Identifiable {
    let id = UUID()
    let host: String
    let port: UInt16
    let username: String
    let authentication: SSHAuthentication
    let fingerprint: SSHHostKeyFingerprint
}

enum ActiveSheet: Identifiable {
    case setup
    case enrollment(PendingEnrollment)

    var id: String {
        switch self {
        case .setup: "setup"
        case let .enrollment(pending): "enrollment-\(pending.id)"
        }
    }
}

@MainActor
@Observable
final class ConnectionStore {
    var configuration: SSHClientConfiguration?
    var pool: ConnectionPool?
    var lastError: SSHKitError?
    var activeSheet: ActiveSheet?

    let trustStore = HostTrustStoreFactory.makeDefault()
    let logRecorder = AppLog.recorder

    init() {
        AppLog.info(.lifecycle, "ConnectionStore initialized", metadata: [
            "trustStore": String(describing: type(of: trustStore)),
        ])
        if configuration == nil {
            AppLog.info(.lifecycle, "No active configuration, opening setup sheet")
            activeSheet = .setup
        }
    }

    func startSetupFlow() {
        AppLog.info(.ui, "User invoked Connect/Reconnect", metadata: [
            "hadConfiguration": String(configuration != nil),
        ])
        activeSheet = .setup
    }

    /// Discover the host key first, then verify the password before the
    /// example app publishes a reusable connection configuration.
    func beginConnect(
        host: String,
        port: UInt16,
        username: String,
        authentication: SSHAuthentication
    ) async {
        let endpoint = endpointMetadata(host: host, port: port, username: username)
        AppLog.info(.connection, "Begin password connection flow", metadata: endpoint)

        let discoveryConfig = SSHHostKeyDiscoveryConfiguration(
            host: host,
            port: port,
            logHandler: AppLog.sshLogHandler
        )

        do {
            let discovered = try await AppLog.span(.hostTrust, "discoverHostKey", metadata: endpoint) {
                try await SSHClient.discoverHostKey(configuration: discoveryConfig)
            }
            AppLog.info(.hostTrust, "Host key discovered", metadata: endpoint.merging([
                "fingerprint": discovered.fingerprint.rawValue,
            ]) { _, new in new })

            AppLog.debug(.hostTrust, "Loading trusted fingerprint", metadata: endpoint)
            let stored = try trustStore.fingerprint(host: host, port: port)
            if let stored {
                try await continueWithStoredFingerprint(
                    stored,
                    discovered: discovered.fingerprint,
                    host: host,
                    port: port,
                    username: username,
                    authentication: authentication
                )
                return
            }

            AppLog.info(.hostTrust, "Host key needs enrollment", metadata: endpoint.merging([
                "fingerprint": discovered.fingerprint.rawValue,
            ]) { _, new in new })
            activeSheet = .enrollment(
                PendingEnrollment(
                    host: host,
                    port: port,
                    username: username,
                    authentication: authentication,
                    fingerprint: discovered.fingerprint
                )
            )
        } catch let error as SSHKitError {
            AppLog.error(.connection, "Password connection flow failed", metadata: endpoint.merging(error.logMetadata) { _, new in new })
            lastError = error
        } catch {
            AppLog.error(.connection, "Password connection flow failed with unexpected error", metadata: endpoint.merging([
                "errorMessage": String(describing: error),
            ]) { _, new in new })
            lastError = SSHKitError(
                code: SSHKitErrorCode.unavailable.rawValue,
                message: String(describing: error)
            )
        }
    }

    func approveEnrollment(_ pending: PendingEnrollment) async {
        let endpoint = endpointMetadata(host: pending.host, port: pending.port, username: pending.username)
        AppLog.info(.hostTrust, "User approved host key enrollment", metadata: endpoint.merging([
            "fingerprint": pending.fingerprint.rawValue,
        ]) { _, new in new })

        do {
            try trustStore.saveFingerprint(
                pending.fingerprint,
                host: pending.host,
                port: pending.port
            )
            AppLog.info(.hostTrust, "Trusted fingerprint saved", metadata: endpoint)
        } catch {
            AppLog.error(.hostTrust, "Failed to save trusted fingerprint", metadata: endpoint.merging([
                "errorMessage": error.localizedDescription,
            ]) { _, new in new })
            lastError = SSHKitError(
                code: SSHKitErrorCode.unavailable.rawValue,
                message: "Failed to save trusted fingerprint: \(error.localizedDescription)"
            )
            return
        }

        do {
            try await finalizeConnect(
                host: pending.host,
                port: pending.port,
                username: pending.username,
                authentication: pending.authentication
            )
        } catch let error as SSHKitError {
            AppLog.error(.connection, "Password verification after enrollment failed", metadata: endpoint.merging(error.logMetadata) { _, new in new })
            lastError = error
            activeSheet = .setup
        } catch {
            AppLog.error(.connection, "Password verification after enrollment failed with unexpected error", metadata: endpoint.merging([
                "errorMessage": String(describing: error),
            ]) { _, new in new })
            lastError = SSHKitError(
                code: SSHKitErrorCode.unavailable.rawValue,
                message: String(describing: error)
            )
            activeSheet = .setup
        }
    }

    func denyEnrollment() {
        AppLog.info(.hostTrust, "User denied host key enrollment")
        activeSheet = .setup
    }

    func disconnect() {
        AppLog.info(.connection, "Disconnect requested", metadata: configuration.map {
            endpointMetadata(host: $0.host, port: $0.port, username: $0.username)
        } ?? [:])
        configuration = nil
        pool = nil
    }

    func wipeTrustedFingerprint(host: String, port: UInt16) {
        let endpoint = ["host": host, "port": String(port)]
        AppLog.warning(.hostTrust, "Removing trusted fingerprint", metadata: endpoint)
        do {
            try trustStore.removeFingerprint(host: host, port: port)
            AppLog.info(.hostTrust, "Trusted fingerprint removed", metadata: endpoint)
        } catch {
            AppLog.error(.hostTrust, "Failed to remove trusted fingerprint", metadata: endpoint.merging([
                "errorMessage": error.localizedDescription,
            ]) { _, new in new })
            lastError = SSHKitError(
                code: SSHKitErrorCode.unavailable.rawValue,
                message: "Failed to remove trusted fingerprint: \(error.localizedDescription)"
            )
        }
    }

    private func continueWithStoredFingerprint(
        _ stored: SSHHostKeyFingerprint,
        discovered: SSHHostKeyFingerprint,
        host: String,
        port: UInt16,
        username: String,
        authentication: SSHAuthentication
    ) async throws {
        let endpoint = endpointMetadata(host: host, port: port, username: username)
        guard stored == discovered else {
            AppLog.error(.hostTrust, "Trusted fingerprint mismatch", metadata: endpoint.merging([
                "trustedFingerprint": stored.rawValue,
                "serverFingerprint": discovered.rawValue,
            ]) { _, new in new })
            lastError = SSHKitError(
                code: SSHKitErrorCode.hostKeyVerificationFailed.rawValue,
                message: """
                Host key for \(host):\(port) does not match the trusted fingerprint.
                Trusted: \(stored.rawValue)
                Server:  \(discovered.rawValue)
                """
            )
            return
        }

        AppLog.info(.hostTrust, "Trusted fingerprint matched", metadata: endpoint)
        try await finalizeConnect(
            host: host,
            port: port,
            username: username,
            authentication: authentication
        )
    }

    private func finalizeConnect(
        host: String,
        port: UInt16,
        username: String,
        authentication: SSHAuthentication
    ) async throws {
        let endpoint = endpointMetadata(host: host, port: port, username: username)
        AppLog.info(.connection, "Finalizing password connection", metadata: endpoint)
        let configuration = try await verifiedConfiguration(
            host: host,
            port: port,
            username: username,
            authentication: authentication
        )
        self.configuration = configuration
        pool = ConnectionPool(configuration: configuration)
        activeSheet = nil
        AppLog.info(.connection, "Connection pool ready", metadata: endpoint)
    }

    private func verifiedConfiguration(
        host: String,
        port: UInt16,
        username: String,
        authentication: SSHAuthentication
    ) async throws -> SSHClientConfiguration {
        let configuration = configuration(
            host: host,
            port: port,
            username: username,
            authentication: authentication
        )
        do {
            try await verify(configuration: configuration)
            return configuration
        } catch let error as SSHKitError {
            throw Self.authenticationRejectedError(
                host: host,
                port: port,
                username: username,
                underlying: error
            )
        }
    }

    private func verify(configuration: SSHClientConfiguration) async throws {
        let metadata = endpointMetadata(
            host: configuration.host,
            port: configuration.port,
            username: configuration.username
        ).merging([
            "authentication": Self.authenticationName(configuration.authentication),
        ]) { _, new in new }

        try await AppLog.span(.auth, "verifyPasswordCredentials", metadata: metadata) {
            let connection = try await SSHClient.connect(configuration: configuration)
            AppLog.info(.auth, "Password credentials accepted", metadata: metadata)
            try await connection.close()
            AppLog.debug(.connection, "Verification connection closed", metadata: metadata)
        }
    }

    private static func authenticationName(_ authentication: SSHAuthentication) -> String {
        switch authentication {
        case .password:
            "password"
        case .privateKeyFile:
            "privateKeyFile"
        case .keyboardInteractive:
            "keyboardInteractive"
        case .agent:
            "agent"
        }
    }

    private static func authenticationRejectedError(
        host: String,
        port: UInt16,
        username: String,
        underlying: SSHKitError
    ) -> SSHKitError {
        SSHKitError(
            code: underlying.code,
            message: """
            Password login was rejected for \(username)@\(host):\(port). Check the username, password, and server login policy.
            Detail: \(underlying.message)
            """
        )
    }

    private func configuration(
        host: String,
        port: UInt16,
        username: String,
        authentication: SSHAuthentication
    ) -> SSHClientConfiguration {
        SSHClientConfiguration(
            host: host,
            port: port,
            username: username,
            authentication: authentication,
            hostKeyPolicy: .trustStore(trustStore),
            logHandler: AppLog.sshLogHandler
        )
    }

    private func endpointMetadata(host: String, port: UInt16, username: String) -> [String: String] {
        ["host": host, "port": String(port), "username": username]
    }
}
