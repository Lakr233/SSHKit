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

@MainActor
@Observable
final class ConnectionStore {
    var configuration: SSHClientConfiguration?
    var pool: ConnectionPool?
    var lastError: SSHKitError?
    var pendingEnrollment: PendingEnrollment?

    let trustStore = HostTrustStoreFactory.makeDefault()
    let logRecorder = AppLog.recorder

    init() {
        AppLog.info(.lifecycle, "ConnectionStore initialized", metadata: [
            "trustStore": String(describing: type(of: trustStore)),
        ])
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
            AppLog.info(.hostTrust, "Host key discovered", metadata: endpoint + [
                "fingerprint": discovered.fingerprint.rawValue,
            ])

            AppLog.debug(.hostTrust, "Loading trusted fingerprint", metadata: endpoint)
            let stored = try trustStore.fingerprint(host: host, port: port)
            if let stored {
                try await verifyStoredFingerprintMatches(
                    stored,
                    against: discovered.fingerprint,
                    host: host,
                    port: port,
                    username: username,
                    authentication: authentication
                )
                return
            }

            AppLog.info(.hostTrust, "Host key needs enrollment", metadata: endpoint + [
                "fingerprint": discovered.fingerprint.rawValue,
            ])
            pendingEnrollment = PendingEnrollment(
                host: host,
                port: port,
                username: username,
                authentication: authentication,
                fingerprint: discovered.fingerprint
            )
        } catch let sshError as SSHKitError {
            AppLog.error(.connection, "Password connection flow failed", metadata: endpoint + sshError.logMetadata)
            lastError = sshError
        } catch {
            let message = AppLog.report(error, as: .connection, message: "Password connection flow failed", metadata: endpoint)
            lastError = SSHKitError(code: SSHKitErrorCode.unavailable.rawValue, message: message)
        }
    }

    func approveEnrollment(_ pending: PendingEnrollment) async {
        let endpoint = endpointMetadata(host: pending.host, port: pending.port, username: pending.username)
        AppLog.info(.hostTrust, "User approved host key enrollment", metadata: endpoint + [
            "fingerprint": pending.fingerprint.rawValue,
        ])

        do {
            try trustStore.saveFingerprint(
                pending.fingerprint,
                host: pending.host,
                port: pending.port
            )
            AppLog.info(.hostTrust, "Trusted fingerprint saved", metadata: endpoint)
        } catch {
            let message = AppLog.report(error, as: .hostTrust, message: "Failed to save trusted fingerprint", metadata: endpoint)
            lastError = SSHKitError(
                code: SSHKitErrorCode.unavailable.rawValue,
                message: "Failed to save trusted fingerprint: \(message)"
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
        } catch let sshError as SSHKitError {
            AppLog.error(.connection, "Password verification after enrollment failed", metadata: endpoint + sshError.logMetadata)
            lastError = sshError
            pendingEnrollment = nil
        } catch {
            let message = AppLog.report(error, as: .connection, message: "Password verification after enrollment failed", metadata: endpoint)
            lastError = SSHKitError(code: SSHKitErrorCode.unavailable.rawValue, message: message)
            pendingEnrollment = nil
        }
    }

    func denyEnrollment() {
        AppLog.info(.hostTrust, "User denied host key enrollment")
        pendingEnrollment = nil
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
            let message = AppLog.report(error, as: .hostTrust, message: "Failed to remove trusted fingerprint", metadata: endpoint)
            lastError = SSHKitError(
                code: SSHKitErrorCode.unavailable.rawValue,
                message: "Failed to remove trusted fingerprint: \(message)"
            )
        }
    }

    private func verifyStoredFingerprintMatches(
        _ stored: SSHHostKeyFingerprint,
        against discovered: SSHHostKeyFingerprint,
        host: String,
        port: UInt16,
        username: String,
        authentication: SSHAuthentication
    ) async throws {
        let endpoint = endpointMetadata(host: host, port: port, username: username)
        guard stored == discovered else {
            AppLog.error(.hostTrust, "Trusted fingerprint mismatch", metadata: endpoint + [
                "trustedFingerprint": stored.rawValue,
                "serverFingerprint": discovered.rawValue,
            ])
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
        pendingEnrollment = nil
        AppLog.info(.connection, "Connection pool ready", metadata: endpoint)
    }

    private func verifiedConfiguration(
        host: String,
        port: UInt16,
        username: String,
        authentication: SSHAuthentication
    ) async throws -> SSHClientConfiguration {
        let candidate = makeClientConfiguration(
            host: host,
            port: port,
            username: username,
            authentication: authentication
        )
        do {
            try await verify(candidate)
            return candidate
        } catch let error as SSHKitError {
            throw Self.authenticationRejectedError(
                host: host,
                port: port,
                username: username,
                underlying: error
            )
        }
    }

    private func verify(_ configuration: SSHClientConfiguration) async throws {
        let metadata = endpointMetadata(
            host: configuration.host,
            port: configuration.port,
            username: configuration.username
        ) + [
            "authentication": Self.authenticationName(configuration.authentication),
        ]

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

    private func makeClientConfiguration(
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
