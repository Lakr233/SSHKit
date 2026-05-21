import Foundation
import GhosttyTerminal
import SSHKit

@MainActor
@Observable
final class SSHTerminalSession {
    enum State: Equatable {
        case idle, starting, running, stopping, finished
    }

    let viewState: TerminalViewState
    private(set) var state: State = .idle
    private(set) var lastError: SSHKitError?

    private let configuration: SSHClientConfiguration
    private let logRecorder: SSHLogRecorder
    private let inMemory: InMemoryTerminalSession
    private var connection: SSHConnection?
    private var shell: SSHShell?
    private var startedAt: DispatchTime?
    private var startToken: UUID?

    init(configuration: SSHClientConfiguration, logRecorder: SSHLogRecorder) {
        self.configuration = configuration
        self.logRecorder = logRecorder
        let recorderRef = logRecorder
        let writeBridge = InMemoryWriteBridge(logRecorder: recorderRef)
        let resizeBridge = InMemoryResizeBridge(logRecorder: recorderRef)
        inMemory = InMemoryTerminalSession(
            write: { data in writeBridge.dispatch(data) },
            resize: { viewport in resizeBridge.dispatch(viewport) }
        )
        viewState = TerminalViewState(
            terminalConfiguration: TerminalConfiguration()
        )
        viewState.configuration = TerminalSurfaceOptions(backend: .inMemory(inMemory))
        // Wire the bridges back to self once self is fully constructed.
        writeBridge.session = self
        resizeBridge.session = self
    }

    func start() async {
        guard state == .idle else {
            AppLog.debug(.terminal, "start() called in non-idle state — ignoring", metadata: [
                "state": String(describing: state),
            ])
            return
        }
        let token = UUID()
        startToken = token
        state = .starting
        AppLog.info(.terminal, "Terminal session start requested", metadata: [
            "host": configuration.host,
            "port": String(configuration.port),
            "username": configuration.username,
            "token": token.uuidString,
        ])

        var pendingConnection: SSHConnection?
        var pendingShell: SSHShell?
        do {
            let opened = try await AppLog.span(.terminal, "SSHClient.connect", metadata: ["token": token.uuidString]) {
                try await SSHClient.connect(configuration: configuration)
            }
            pendingConnection = opened
            guard state == .starting, startToken == token else {
                AppLog.warning(.terminal, "Start cancelled before shell open", metadata: ["token": token.uuidString])
                await cleanupPending(connection: opened, shell: nil)
                return
            }
            let (cols, rows) = currentGridSize() ?? (80, 24)
            AppLog.debug(.terminal, "Opening shell", metadata: [
                "token": token.uuidString,
                "columns": String(cols),
                "rows": String(rows),
            ])
            let openedShell = try await opened.openShell(
                terminalType: "xterm-256color",
                columns: cols,
                rows: rows
            ) { [weak self] event in
                Task { @MainActor [weak self] in self?.handleShellEvent(event) }
            }
            pendingShell = openedShell
            guard state == .starting, startToken == token else {
                AppLog.warning(.terminal, "Start cancelled after shell open — cleaning up", metadata: ["token": token.uuidString])
                await cleanupPending(connection: opened, shell: openedShell)
                return
            }
            connection = opened
            shell = openedShell
            startedAt = DispatchTime.now()
            state = .running
            AppLog.info(.terminal, "Terminal session running", metadata: [
                "token": token.uuidString,
                "columns": String(cols),
                "rows": String(rows),
            ])
        } catch let error as SSHKitError {
            AppLog.error(.terminal, "Terminal start failed", metadata: error.logMetadata)
            await cleanupPending(connection: pendingConnection, shell: pendingShell)
            recordError(error, phase: "start")
            state = .finished
        } catch {
            AppLog.error(.terminal, "Terminal start failed (non-SSHKit)", metadata: [
                "errorMessage": String(describing: error),
            ])
            await cleanupPending(connection: pendingConnection, shell: pendingShell)
            recordError(
                SSHKitError(
                    code: SSHKitErrorCode.unavailable.rawValue,
                    message: String(describing: error)
                ),
                phase: "start"
            )
            state = .finished
        }
    }

    func stop() async {
        guard state == .running || state == .starting else {
            AppLog.debug(.terminal, "stop() called in non-running/starting state — ignoring", metadata: [
                "state": String(describing: state),
            ])
            return
        }
        AppLog.info(.terminal, "Stopping terminal session", metadata: [
            "previousState": String(describing: state),
        ])
        state = .stopping
        let pendingShell = shell; shell = nil
        let pendingConn = connection; connection = nil
        startToken = nil
        startedAt = nil

        if let pendingShell {
            do { try await pendingShell.close() }
            catch let e as SSHKitError { recordError(e, phase: "shellClose") }
            catch {
                recordError(
                    SSHKitError(code: SSHKitErrorCode.unavailable.rawValue, message: String(describing: error)),
                    phase: "shellClose"
                )
            }
        }
        if let pendingConn {
            do { try await pendingConn.close() }
            catch let e as SSHKitError { recordError(e, phase: "connClose") }
            catch {
                recordError(
                    SSHKitError(code: SSHKitErrorCode.unavailable.rawValue, message: String(describing: error)),
                    phase: "connClose"
                )
            }
        }
        state = .finished
    }

    fileprivate func handleTerminalWroteOutput(_ data: Data) {
        guard let shell else { return }
        Task { [weak self] in
            do {
                try await shell.write(data)
            } catch let e as SSHKitError {
                await MainActor.run { self?.recordError(e, phase: "write") }
            } catch {
                await MainActor.run {
                    self?.recordError(
                        SSHKitError(code: SSHKitErrorCode.unavailable.rawValue, message: String(describing: error)),
                        phase: "write"
                    )
                }
            }
        }
    }

    fileprivate func handleResize(_ viewport: InMemoryTerminalViewport) {
        guard let shell else { return }
        let cols = viewport.columns, rows = viewport.rows
        Task { [weak self] in
            do {
                try await shell.resize(columns: cols, rows: rows)
            } catch let e as SSHKitError {
                await MainActor.run { self?.recordError(e, phase: "resize") }
            } catch {
                await MainActor.run {
                    self?.recordError(
                        SSHKitError(code: SSHKitErrorCode.unavailable.rawValue, message: String(describing: error)),
                        phase: "resize"
                    )
                }
            }
        }
    }

    private func handleShellEvent(_ event: SSHShellEvent) {
        switch event {
        case let .standardOutput(data), let .standardError(data):
            inMemory.receive(data)
        case let .closed(status):
            let runtimeMs: UInt64 = startedAt.map {
                (DispatchTime.now().uptimeNanoseconds &- $0.uptimeNanoseconds) / 1_000_000
            } ?? 0
            inMemory.finish(exitCode: status, runtimeMilliseconds: runtimeMs)
            shell = nil
            let conn = connection
            connection = nil
            state = .finished
            if let conn {
                Task { [weak self] in
                    do { try await conn.close() }
                    catch let e as SSHKitError {
                        await MainActor.run { self?.recordError(e, phase: "closeAfterShellClosed") }
                    } catch {
                        await MainActor.run {
                            self?.recordError(
                                SSHKitError(code: SSHKitErrorCode.unavailable.rawValue, message: String(describing: error)),
                                phase: "closeAfterShellClosed"
                            )
                        }
                    }
                }
            }
        }
    }

    private func cleanupPending(connection: SSHConnection?, shell: SSHShell?) async {
        if let shell {
            do { try await shell.close() }
            catch let e as SSHKitError { recordError(e, phase: "startCleanupShell") }
            catch {
                recordError(
                    SSHKitError(code: SSHKitErrorCode.unavailable.rawValue, message: String(describing: error)),
                    phase: "startCleanupShell"
                )
            }
        }
        if let connection {
            do { try await connection.close() }
            catch let e as SSHKitError { recordError(e, phase: "startCleanupConn") }
            catch {
                recordError(
                    SSHKitError(code: SSHKitErrorCode.unavailable.rawValue, message: String(describing: error)),
                    phase: "startCleanupConn"
                )
            }
        }
    }

    private func recordError(_ error: SSHKitError, phase: String) {
        lastError = error
        AppLog.error(.terminal, "Terminal error in phase \(phase)", metadata: error.logMetadata.merging([
            "phase": phase,
        ]) { _, new in new })
    }

    private func currentGridSize() -> (UInt16, UInt16)? {
        if let size = viewState.surfaceSize {
            return (size.columns, size.rows)
        }
        return nil
    }
}

/// Bridges libghostty's @Sendable write callback to the @MainActor session.
/// Lives outside SSHTerminalSession so it can be safely constructed before
/// `self` is fully initialized, then back-wired with a weak reference.
private final class InMemoryWriteBridge: @unchecked Sendable {
    weak var session: SSHTerminalSession?
    let logRecorder: SSHLogRecorder

    init(logRecorder: SSHLogRecorder) {
        self.logRecorder = logRecorder
    }

    func dispatch(_ data: Data) {
        Task { @MainActor [weak self] in
            self?.session?.handleTerminalWroteOutput(data)
        }
    }
}

private final class InMemoryResizeBridge: @unchecked Sendable {
    weak var session: SSHTerminalSession?
    let logRecorder: SSHLogRecorder

    init(logRecorder: SSHLogRecorder) {
        self.logRecorder = logRecorder
    }

    func dispatch(_ viewport: InMemoryTerminalViewport) {
        Task { @MainActor [weak self] in
            self?.session?.handleResize(viewport)
        }
    }
}

private extension InMemoryTerminalSession {
    /// Convenience that matches the plan's exit-status finish semantics, even
    /// if libghostty-spm later renames the underlying call. If the binary API
    /// changes, this is the single point of repair.
    func finish(exitCode: Int32, runtimeMilliseconds: UInt64) {
        // The library exposes the surface lifecycle internally. We treat the
        // exit as a no-op observation point for now; the SwiftUI view detects
        // the shell-closed state via SSHTerminalSession.state.
        _ = exitCode
        _ = runtimeMilliseconds
    }
}
