import Foundation
import SSHKitObjC

public enum SSHLogLevel: Int, Sendable {
    case debug
    case info
    case warning
    case error
}

public struct SSHLogEvent: Equatable, Sendable {
    public var level: SSHLogLevel
    public var phase: String
    public var message: String
    public var metadata: [String: String]
    public var timestamp: Date

    public init(
        level: SSHLogLevel,
        phase: String,
        message: String,
        metadata: [String: String] = [:],
        timestamp: Date = Date()
    ) {
        self.level = level
        self.phase = phase
        self.message = message
        self.metadata = metadata
        self.timestamp = timestamp
    }

    init(_ event: SSHKitObjC.SSHKitLogEvent) {
        level = SSHLogLevel(rawValue: event.level.rawValue) ?? .debug
        phase = event.phase
        message = event.message
        metadata = event.metadata
        timestamp = event.timestamp
    }

    public var redacted: SSHLogEvent {
        var redactedMetadata: [String: String] = [:]
        for (key, value) in metadata {
            redactedMetadata[key] = Self.isSensitive(key) ? "<redacted>" : value
        }
        return SSHLogEvent(
            level: level,
            phase: phase,
            message: message,
            metadata: redactedMetadata,
            timestamp: timestamp
        )
    }

    private static func isSensitive(_ key: String) -> Bool {
        let lowered = key.lowercased()
        return lowered.contains("password") ||
            lowered.contains("passphrase") ||
            lowered.contains("secret") ||
            lowered.contains("token") ||
            lowered.contains("privatekey")
    }
}

public typealias SSHLogHandler = @Sendable (SSHLogEvent) -> Void

public final class SSHLogRecorder: @unchecked Sendable {
    private let lock = NSLock()
    private let capacity: Int
    private var storage: [SSHLogEvent] = []

    public init(capacity: Int = 200) {
        precondition(capacity > 0, "SSHLogRecorder capacity must be greater than zero.")
        self.capacity = capacity
    }

    public func record(_ event: SSHLogEvent) {
        lock.lock()
        storage.append(event.redacted)
        if storage.count > capacity {
            storage.removeFirst(storage.count - capacity)
        }
        lock.unlock()
    }

    public var events: [SSHLogEvent] {
        lock.lock()
        let events = storage
        lock.unlock()
        return events
    }
}

public struct SSHDiagnosticReport: Equatable, Sendable {
    public var phase: String
    public var host: String
    public var port: UInt16
    public var username: String
    public var authentication: String
    public var hostKeyPolicy: String
    public var metadata: [String: String]
    public var recentEvents: [SSHLogEvent]
    public var generatedAt: Date

    public init(
        phase: String,
        host: String,
        port: UInt16,
        username: String,
        authentication: String,
        hostKeyPolicy: String,
        metadata: [String: String] = [:],
        recentEvents: [SSHLogEvent] = [],
        generatedAt: Date = Date()
    ) {
        self.phase = phase
        self.host = host
        self.port = port
        self.username = username
        self.authentication = authentication
        self.hostKeyPolicy = hostKeyPolicy
        self.metadata = SSHLogEvent(
            level: .debug,
            phase: phase,
            message: "diagnostic metadata",
            metadata: metadata,
            timestamp: generatedAt
        ).redacted.metadata
        self.recentEvents = recentEvents.map(\.redacted)
        self.generatedAt = generatedAt
    }
}
