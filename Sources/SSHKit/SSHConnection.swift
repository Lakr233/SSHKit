import Foundation
import SSHKitObjC

public final class SSHConnection: @unchecked Sendable {
    private let session: SSHKitConnection
    private let configuration: SSHClientConfiguration

    init(session: SSHKitConnection, configuration: SSHClientConfiguration) {
        self.session = session
        self.configuration = configuration
    }

    public func diagnosticReport(
        phase: String = "connected",
        metadata: [String: String] = [:],
        recentEvents: [SSHLogEvent] = [],
    ) -> SSHDiagnosticReport {
        configuration.diagnosticReport(phase: phase, metadata: metadata, recentEvents: recentEvents)
    }

    public func execute(
        _ command: String,
        callbackQueue: DispatchQueue = .main,
        completion: @escaping (Result<SSHCommandResult, SSHKitError>) -> Void,
    ) {
        session.executeCommand(command) { result, error in
            if let error = error as NSError? {
                callbackQueue.async {
                    completion(.failure(SSHKitError(error)))
                }
                return
            }

            guard let result else {
                callbackQueue.async {
                    completion(.failure(SSHKitError(code: SSHKitErrorCode.unavailable.rawValue, message: "SSH command completed without a result.")))
                }
                return
            }

            let commandResult = SSHCommandResult(
                standardOutput: result.standardOutput,
                standardError: result.standardError,
                exitStatus: result.exitStatus,
            )
            callbackQueue.async {
                completion(.success(commandResult))
            }
        }
    }

    public func close(
        callbackQueue: DispatchQueue = .main,
        completion: @escaping (Result<Void, SSHKitError>) -> Void,
    ) {
        session.disconnect { error in
            if let error = error as NSError? {
                callbackQueue.async {
                    completion(.failure(SSHKitError(error)))
                }
                return
            }

            callbackQueue.async {
                completion(.success(()))
            }
        }
    }

    public func openShell(
        terminalType: String = "xterm-256color",
        columns: UInt16 = 80,
        rows: UInt16 = 24,
        callbackQueue: DispatchQueue = .main,
        eventHandler: @escaping @Sendable (SSHShellEvent) -> Void,
        completion: @escaping (Result<SSHShell, SSHKitError>) -> Void,
    ) {
        precondition(terminalType.isEmpty == false, "Shell terminal type must not be empty.")
        precondition(columns > 0, "PTY columns must be greater than zero.")
        precondition(rows > 0, "PTY rows must be greater than zero.")

        session.openShell(
            withTerminalType: terminalType,
            columns: columns,
            rows: rows,
            eventHandler: { event in
                let shellEvent = SSHShell.makeEvent(event)
                callbackQueue.async {
                    eventHandler(shellEvent)
                }
            },
        ) { shell, error in
            if let error = error as NSError? {
                callbackQueue.async {
                    completion(.failure(SSHKitError(error)))
                }
                return
            }

            guard let shell else {
                callbackQueue.async {
                    completion(.failure(SSHKitError(code: SSHKitErrorCode.unavailable.rawValue, message: "SSH shell opened without a shell object.")))
                }
                return
            }

            callbackQueue.async {
                completion(.success(SSHShell(shell: shell)))
            }
        }
    }

    public func openCommand(
        _ command: String,
        callbackQueue: DispatchQueue = .main,
        eventHandler: @escaping @Sendable (SSHCommandEvent) -> Void,
        completion: @escaping (Result<SSHCommand, SSHKitError>) -> Void,
    ) {
        precondition(command.isEmpty == false, "Command must not be empty.")

        let eventSink = SSHCommandEventSink()
        session.openCommand(command, eventHandler: { event in
            let commandEvent = SSHCommand.makeEvent(event)
            eventSink.yield(commandEvent)
            callbackQueue.async {
                eventHandler(commandEvent)
            }
        }) { command, error in
            if let error = error as NSError? {
                eventSink.finish()
                callbackQueue.async {
                    completion(.failure(SSHKitError(error)))
                }
                return
            }

            guard let command else {
                eventSink.finish()
                callbackQueue.async {
                    completion(.failure(SSHKitError(code: SSHKitErrorCode.unavailable.rawValue, message: "SSH command opened without a command object.")))
                }
                return
            }

            callbackQueue.async {
                completion(.success(SSHCommand(command: command, eventSink: eventSink)))
            }
        }
    }

    public func openCommand(_ command: String) async throws -> SSHCommand {
        let eventSink = SSHCommandEventSink()
        return try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                session.openCommand(command, eventHandler: { event in
                    eventSink.yield(SSHCommand.makeEvent(event))
                }) { command, error in
                    if let error = error as NSError? {
                        eventSink.finish()
                        continuation.resume(throwing: SSHKitError(error))
                        return
                    }

                    guard let command else {
                        eventSink.finish()
                        continuation.resume(throwing: SSHKitError(code: SSHKitErrorCode.unavailable.rawValue, message: "SSH command opened without a command object."))
                        return
                    }

                    continuation.resume(returning: SSHCommand(command: command, eventSink: eventSink))
                }
            }
        } onCancel: {
            close(callbackQueue: .global()) { _ in
            }
        }
    }

    public func openSFTP(
        callbackQueue: DispatchQueue = .main,
        completion: @escaping (Result<SFTPClient, SSHKitError>) -> Void,
    ) {
        session.openSFTP { client, error in
            if let error = error as NSError? {
                callbackQueue.async {
                    completion(.failure(SSHKitError(error)))
                }
                return
            }

            guard let client else {
                callbackQueue.async {
                    completion(.failure(SSHKitError(code: SSHKitErrorCode.unavailable.rawValue, message: "SFTP opened without a client object.")))
                }
                return
            }

            callbackQueue.async {
                let session = self.session
                completion(.success(SFTPClient(client: client) {
                    session.disconnect { _ in }
                }))
            }
        }
    }

    public func openSFTP() async throws -> SFTPClient {
        try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                openSFTP(callbackQueue: .global()) { result in
                    continuation.resume(with: result)
                }
            }
        } onCancel: {
            close(callbackQueue: .global()) { _ in
            }
        }
    }

    public func openDirectTCPChannel(
        host: String,
        port: UInt16,
        callbackQueue: DispatchQueue = .main,
        completion: @escaping (Result<SSHTunnelChannel, SSHKitError>) -> Void,
    ) {
        precondition(host.isEmpty == false, "Direct TCP channel host must not be empty.")
        precondition(port > 0, "Direct TCP channel port must be greater than zero.")

        session.openDirectTCPChannel(toHost: host, port: port) { channel, error in
            if let error = error as NSError? {
                callbackQueue.async {
                    completion(.failure(SSHKitError(error)))
                }
                return
            }

            guard let channel else {
                callbackQueue.async {
                    completion(.failure(SSHKitError(code: SSHKitErrorCode.unavailable.rawValue, message: "Direct TCP channel opened without a channel object.")))
                }
                return
            }

            callbackQueue.async {
                completion(.success(SSHTunnelChannel(channel: channel)))
            }
        }
    }

    public func openDirectTCPChannel(host: String, port: UInt16) async throws -> SSHTunnelChannel {
        try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                openDirectTCPChannel(host: host, port: port, callbackQueue: .global()) { result in
                    continuation.resume(with: result)
                }
            }
        } onCancel: {
            close(callbackQueue: .global()) { _ in
            }
        }
    }

    public func startLocalForward(
        localHost: String = "127.0.0.1",
        localPort: UInt16 = 0,
        remoteHost: String,
        remotePort: UInt16,
        callbackQueue: DispatchQueue = .main,
        completion: @escaping (Result<SSHPortForward, SSHKitError>) -> Void,
    ) {
        precondition(localHost.isEmpty == false, "Local forward bind host must not be empty.")
        precondition(remoteHost.isEmpty == false, "Local forward target host must not be empty.")
        precondition(remotePort > 0, "Local forward target port must be greater than zero.")

        session.startLocalForward(
            fromHost: localHost,
            port: localPort,
            toHost: remoteHost,
            targetPort: remotePort,
        ) { forward, error in
            if let error = error as NSError? {
                callbackQueue.async {
                    completion(.failure(SSHKitError(error)))
                }
                return
            }

            guard let forward else {
                callbackQueue.async {
                    completion(.failure(SSHKitError(code: SSHKitErrorCode.unavailable.rawValue, message: "Local forward started without a forward object.")))
                }
                return
            }

            callbackQueue.async {
                completion(.success(SSHPortForward(forward: forward)))
            }
        }
    }

    public func startLocalForward(
        localHost: String = "127.0.0.1",
        localPort: UInt16 = 0,
        remoteHost: String,
        remotePort: UInt16,
    ) async throws -> SSHPortForward {
        try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                startLocalForward(localHost: localHost, localPort: localPort, remoteHost: remoteHost, remotePort: remotePort, callbackQueue: .global()) { result in
                    continuation.resume(with: result)
                }
            }
        } onCancel: {
            close(callbackQueue: .global()) { _ in
            }
        }
    }

    public func openShell(
        terminalType: String = "xterm-256color",
        columns: UInt16 = 80,
        rows: UInt16 = 24,
        eventHandler: @escaping @Sendable (SSHShellEvent) -> Void,
    ) async throws -> SSHShell {
        try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                openShell(
                    terminalType: terminalType,
                    columns: columns,
                    rows: rows,
                    callbackQueue: .global(),
                    eventHandler: eventHandler,
                ) { result in
                    continuation.resume(with: result)
                }
            }
        } onCancel: {
            close(callbackQueue: .global()) { _ in
            }
        }
    }

    public func execute(_ command: String) async throws -> SSHCommandResult {
        try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                execute(command, callbackQueue: .global()) { result in
                    continuation.resume(with: result)
                }
            }
        } onCancel: {
            close(callbackQueue: .global()) { _ in
            }
        }
    }

    public func close() async throws {
        try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                close(callbackQueue: .global()) { result in
                    continuation.resume(with: result)
                }
            }
        } onCancel: {
            close(callbackQueue: .global()) { _ in
            }
        }
    }
}
