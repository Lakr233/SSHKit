import Foundation
import OSLog
import SSHKit

/// Logical buckets the example app emits events into. Mirrors the `phase`
/// field on `SSHLogEvent` so app + library events share one timeline.
enum AppLogCategory: String, CaseIterable {
    case lifecycle
    case connection
    case hostTrust
    case auth
    case terminal
    case command
    case sftp
    case transfer
    case portMap
    case latency
    case multiCommand
    case sessionFuzz
    case ui
    case ssh

    var displayName: String {
        switch self {
        case .lifecycle: "Lifecycle"
        case .connection: "Connection"
        case .hostTrust: "Host Trust"
        case .auth: "Auth"
        case .terminal: "Terminal"
        case .command: "Command"
        case .sftp: "SFTP"
        case .transfer: "Transfer"
        case .portMap: "Port Map"
        case .latency: "Latency"
        case .multiCommand: "Multi-Command"
        case .sessionFuzz: "Session Fuzz"
        case .ui: "UI"
        case .ssh: "SSH (libssh)"
        }
    }
}

/// Single home for observability in the example app. Bridges three sinks:
///   1. Apple unified logging (`os.Logger`) — visible in Console.app and
///      `log stream --predicate 'subsystem == "wiki.qaq.SSHKitExample"'`.
///   2. The shared `SSHLogRecorder` — used by SSHKit configurations and the
///      in-app log inspector so library + app events share one timeline.
///   3. The in-app inspector view (it polls `recorder.events`).
///
/// `LogCenter` itself is thread-safe; call sites can log from any queue.
final class LogCenter: @unchecked Sendable {
    static let subsystem = "wiki.qaq.SSHKitExample"
    static let shared = LogCenter()

    let recorder: SSHLogRecorder
    private let loggers: [AppLogCategory: Logger]
    private let sshFallbackLogger: Logger
    private let processStartedAt: Date

    init(capacity: Int = 1000) {
        recorder = SSHLogRecorder(capacity: capacity)
        var map: [AppLogCategory: Logger] = [:]
        for category in AppLogCategory.allCases {
            map[category] = Logger(subsystem: Self.subsystem, category: category.rawValue)
        }
        loggers = map
        sshFallbackLogger = Logger(subsystem: Self.subsystem, category: "ssh.event")
        processStartedAt = Date()
    }

    /// Hand this to every `SSHClientConfiguration` / discovery configuration
    /// so libssh + SSHKit log events also flow through the unified pipeline.
    var sshLogHandler: SSHLogHandler {
        let recorder = recorder
        let logger = sshFallbackLogger
        return { event in
            recorder.record(event)
            let line = "[\(event.phase)] \(event.message) \(Self.format(metadata: event.metadata))"
            switch event.level {
            case .debug:
                logger.debug("\(line, privacy: .public)")
            case .info:
                logger.info("\(line, privacy: .public)")
            case .warning:
                logger.warning("\(line, privacy: .public)")
            case .error:
                logger.error("\(line, privacy: .public)")
            }
        }
    }

    func log(
        _ level: SSHLogLevel,
        _ category: AppLogCategory,
        _ message: @autoclosure () -> String,
        metadata: [String: String] = [:],
        file: String = #fileID,
        line: Int = #line
    ) {
        let rendered = message()
        var enriched = metadata
        enriched["source"] = "\(file):\(line)"
        enriched["uptimeMs"] = String(Int(Date().timeIntervalSince(processStartedAt) * 1000))

        let event = SSHLogEvent(
            level: level,
            phase: category.rawValue,
            message: rendered,
            metadata: enriched
        )
        recorder.record(event)

        let logger = loggers[category] ?? sshFallbackLogger
        let meta = Self.format(metadata: enriched)
        switch level {
        case .debug:
            logger.debug("\(rendered, privacy: .public) \(meta, privacy: .public)")
        case .info:
            logger.info("\(rendered, privacy: .public) \(meta, privacy: .public)")
        case .warning:
            logger.warning("\(rendered, privacy: .public) \(meta, privacy: .public)")
        case .error:
            logger.error("\(rendered, privacy: .public) \(meta, privacy: .public)")
        }
    }

    static func format(metadata: [String: String]) -> String {
        guard !metadata.isEmpty else { return "" }
        let parts = metadata.sorted { $0.key < $1.key }
            .map { key, value in "\(key)=\(value)" }
        return "{" + parts.joined(separator: " ") + "}"
    }
}

/// Convenience entry point. Keeps call sites short:
///     AppLog.info(.connection, "Beginning connect", metadata: [...])
enum AppLog {
    static var center: LogCenter {
        LogCenter.shared
    }

    static var recorder: SSHLogRecorder {
        center.recorder
    }

    static var sshLogHandler: SSHLogHandler {
        center.sshLogHandler
    }

    static func debug(
        _ category: AppLogCategory,
        _ message: @autoclosure () -> String,
        metadata: [String: String] = [:],
        file: String = #fileID,
        line: Int = #line
    ) {
        center.log(.debug, category, message(), metadata: metadata, file: file, line: line)
    }

    static func info(
        _ category: AppLogCategory,
        _ message: @autoclosure () -> String,
        metadata: [String: String] = [:],
        file: String = #fileID,
        line: Int = #line
    ) {
        center.log(.info, category, message(), metadata: metadata, file: file, line: line)
    }

    static func warning(
        _ category: AppLogCategory,
        _ message: @autoclosure () -> String,
        metadata: [String: String] = [:],
        file: String = #fileID,
        line: Int = #line
    ) {
        center.log(.warning, category, message(), metadata: metadata, file: file, line: line)
    }

    static func error(
        _ category: AppLogCategory,
        _ message: @autoclosure () -> String,
        metadata: [String: String] = [:],
        file: String = #fileID,
        line: Int = #line
    ) {
        center.log(.error, category, message(), metadata: metadata, file: file, line: line)
    }

    /// Wrap an async block, log entry/exit/duration, and rethrow.
    @discardableResult
    static func span<T>(
        _ category: AppLogCategory,
        _ name: String,
        metadata: [String: String] = [:],
        file: String = #fileID,
        line: Int = #line,
        _ body: sending () async throws -> T
    ) async rethrows -> sending T {
        let start = DispatchTime.now()
        info(category, "▶ \(name)", metadata: metadata, file: file, line: line)
        do {
            let value = try await body()
            let ms = (DispatchTime.now().uptimeNanoseconds &- start.uptimeNanoseconds) / 1_000_000
            var done = metadata
            done["durationMs"] = String(ms)
            info(category, "✓ \(name)", metadata: done, file: file, line: line)
            return value
        } catch {
            let ms = (DispatchTime.now().uptimeNanoseconds &- start.uptimeNanoseconds) / 1_000_000
            var failed = metadata
            failed["durationMs"] = String(ms)
            if let sshError = error as? SSHKitError {
                failed["errorCode"] = String(sshError.code)
                failed["errorMessage"] = sshError.message
            } else {
                failed["errorMessage"] = String(describing: error)
            }
            self.error(category, "✗ \(name)", metadata: failed, file: file, line: line)
            throw error
        }
    }
}

extension SSHKitError {
    /// Standard metadata bag for error logs.
    var logMetadata: [String: String] {
        ["errorCode": String(code), "errorMessage": message]
    }
}
