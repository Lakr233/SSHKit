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
    let logRecorder = SSHLogRecorder()

    init() {
        if configuration == nil {
            activeSheet = .setup
        }
    }

    func startSetupFlow() {
        activeSheet = .setup
    }

    /// Discover the host key first (no auth required), then either auto-connect
    /// when the keychain already trusts this host, or stage a pending
    /// enrollment so the user can approve the fingerprint.
    func beginConnect(
        host: String,
        port: UInt16,
        username: String,
        authentication: SSHAuthentication,
    ) async {
        let logHandler = logRecorder.logHandler
        let discoveryConfig = SSHHostKeyDiscoveryConfiguration(
            host: host,
            port: port,
            logHandler: logHandler,
        )
        do {
            let discovered = try await SSHClient.discoverHostKey(configuration: discoveryConfig)
            let stored = try trustStore.fingerprint(host: host, port: port)
            if let stored {
                if stored == discovered.fingerprint {
                    finalizeConnect(
                        host: host,
                        port: port,
                        username: username,
                        authentication: authentication,
                    )
                } else {
                    lastError = SSHKitError(
                        code: SSHKitErrorCode.hostKeyVerificationFailed.rawValue,
                        message: """
                        Host key for \(host):\(port) does not match the trusted fingerprint.
                        Trusted: \(stored.rawValue)
                        Server:  \(discovered.fingerprint.rawValue)
                        """,
                    )
                }
                return
            }
            activeSheet = .enrollment(
                PendingEnrollment(
                    host: host,
                    port: port,
                    username: username,
                    authentication: authentication,
                    fingerprint: discovered.fingerprint,
                ),
            )
        } catch let error as SSHKitError {
            lastError = error
        } catch {
            lastError = SSHKitError(
                code: SSHKitErrorCode.unavailable.rawValue,
                message: String(describing: error),
            )
        }
    }

    func approveEnrollment(_ pending: PendingEnrollment) {
        do {
            try trustStore.saveFingerprint(
                pending.fingerprint,
                host: pending.host,
                port: pending.port,
            )
        } catch {
            lastError = SSHKitError(
                code: SSHKitErrorCode.unavailable.rawValue,
                message: "Failed to save trusted fingerprint: \(error.localizedDescription)",
            )
            return
        }
        activeSheet = nil
        finalizeConnect(
            host: pending.host,
            port: pending.port,
            username: pending.username,
            authentication: pending.authentication,
        )
    }

    func denyEnrollment() {
        activeSheet = .setup
    }

    func disconnect() {
        configuration = nil
        pool = nil
    }

    func wipeTrustedFingerprint(host: String, port: UInt16) {
        do {
            try trustStore.removeFingerprint(host: host, port: port)
        } catch {
            lastError = SSHKitError(
                code: SSHKitErrorCode.unavailable.rawValue,
                message: "Failed to remove trusted fingerprint: \(error.localizedDescription)",
            )
        }
    }

    private func finalizeConnect(
        host: String,
        port: UInt16,
        username: String,
        authentication: SSHAuthentication,
    ) {
        let configuration = SSHClientConfiguration(
            host: host,
            port: port,
            username: username,
            authentication: authentication,
            hostKeyPolicy: .trustStore(trustStore),
            logHandler: logRecorder.logHandler,
        )
        self.configuration = configuration
        pool = ConnectionPool(configuration: configuration)
        activeSheet = nil
    }
}

extension SSHLogRecorder {
    var logHandler: SSHLogHandler {
        { [weak self] event in
            self?.record(event)
        }
    }
}
