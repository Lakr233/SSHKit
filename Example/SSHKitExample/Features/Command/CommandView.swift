import SSHKit
import SwiftUI

struct CommandView: View {
    @Environment(ConnectionStore.self) private var store

    enum Mode: String, Hashable, CaseIterable, Identifiable {
        case collected, streamed
        var id: String {
            rawValue
        }

        var title: String {
            switch self {
            case .collected: "Collected"
            case .streamed: "Streamed"
            }
        }
    }

    @State private var commandText: String = "uname -a"
    @State private var mode: Mode = .collected
    @State private var stdoutText: String = ""
    @State private var stderrText: String = ""
    @State private var statusLine: String = ""
    @State private var isRunning: Bool = false
    @State private var task: Task<Void, Never>?

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                TextField("command", text: $commandText, axis: .vertical)
                    .textFieldStyle(.roundedBorder)
                    .lineLimit(1 ... 3)
                    .autocorrectionDisabled()
                    .accessibilityIdentifier("SSHKitExample.Command.Field")
                Picker("Mode", selection: $mode) {
                    ForEach(Mode.allCases) { mode in
                        Text(mode.title).tag(mode)
                    }
                }
                .pickerStyle(.segmented)
                .frame(width: 200)
                .disabled(isRunning)
                Button(isRunning ? "Cancel" : "Run") {
                    if isRunning {
                        task?.cancel()
                    } else {
                        runCommand()
                    }
                }
                .keyboardShortcut(.return, modifiers: [.command])
                .accessibilityIdentifier("SSHKitExample.Command.Run")
                .disabled(store.pool == nil || commandText.trimmingCharacters(in: .whitespaces).isEmpty)
            }
            GroupBox("stdout") {
                ScrollView {
                    Text(stdoutText.isEmpty ? "—" : stdoutText)
                        .font(.system(.callout, design: .monospaced))
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .textSelection(.enabled)
                }
                .frame(maxWidth: .infinity, alignment: .leading)
            }
            GroupBox("stderr") {
                ScrollView {
                    Text(stderrText.isEmpty ? "—" : stderrText)
                        .font(.system(.callout, design: .monospaced))
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .textSelection(.enabled)
                }
                .frame(maxHeight: 140)
            }
            if !statusLine.isEmpty {
                Text(statusLine)
                    .font(.footnote)
                    .foregroundStyle(.secondary)
            }
        }
        .padding()
        .navigationTitle("Command")
    }

    private func runCommand() {
        guard let pool = store.pool else {
            AppLog.warning(.command, "Run pressed without an active pool")
            return
        }
        let command = commandText
        let runMode = mode
        AppLog.info(.command, "Run command requested", metadata: [
            "mode": runMode.rawValue,
            "commandLength": String(command.count),
            "commandPreview": String(command.prefix(80)),
        ])
        stdoutText = ""
        stderrText = ""
        statusLine = "Running…"
        isRunning = true
        task = Task {
            defer {
                Task { @MainActor in
                    isRunning = false
                    task = nil
                    AppLog.debug(.command, "Run task finished", metadata: ["mode": runMode.rawValue])
                }
            }
            switch runMode {
            case .collected:
                await runCollected(pool: pool, command: command)
            case .streamed:
                await runStreamed(pool: pool, command: command)
            }
        }
    }

    @MainActor
    private func runCollected(pool: ConnectionPool, command: String) async {
        do {
            let result = try await AppLog.span(.command, "execute(collected)", metadata: [
                "commandPreview": String(command.prefix(80)),
            ]) {
                try await pool.run { connection in
                    try await connection.execute(command)
                }
            }
            stdoutText = Self.decodeStrict(result.standardOutput, label: "stdout")
            stderrText = Self.decodeStrict(result.standardError, label: "stderr")
            statusLine = "Exit \(result.exitStatus)" + (result.exitSignal.map { ", signal \($0)" } ?? "")
            AppLog.info(.command, "Collected execution finished", metadata: [
                "exitStatus": String(result.exitStatus),
                "exitSignal": result.exitSignal ?? "",
                "stdoutBytes": String(result.standardOutput.count),
                "stderrBytes": String(result.standardError.count),
            ])
        } catch let error as SSHKitError {
            AppLog.error(.command, "Collected execution failed", metadata: error.logMetadata)
            statusLine = "Error: \(error.message)"
        } catch {
            AppLog.error(.command, "Collected execution failed (non-SSHKit)", metadata: [
                "errorMessage": error.localizedDescription,
            ])
            statusLine = "Error: \(error.localizedDescription)"
        }
    }

    private func runStreamed(pool: ConnectionPool, command: String) async {
        let preview = ["commandPreview": String(command.prefix(80))]
        do {
            try await AppLog.span(.command, "execute(streamed)", metadata: preview) {
                try await pool.run { connection in
                    let cmd = try await connection.openCommand(command)
                    var stdoutDecoder = StreamingUTF8Decoder()
                    var stderrDecoder = StreamingUTF8Decoder()
                    var stdoutBytes: UInt64 = 0
                    var stderrBytes: UInt64 = 0
                    for await event in cmd.events {
                        switch event {
                        case let .standardOutput(data):
                            stdoutBytes &+= UInt64(data.count)
                            let chunk = stdoutDecoder.push(data)
                            if !chunk.isEmpty {
                                await MainActor.run { stdoutText.append(chunk) }
                            }
                        case let .standardError(data):
                            stderrBytes &+= UInt64(data.count)
                            let chunk = stderrDecoder.push(data)
                            if !chunk.isEmpty {
                                await MainActor.run { stderrText.append(chunk) }
                            }
                        case let .closed(status, signal):
                            let outTail = stdoutDecoder.flush()
                            let errTail = stderrDecoder.flush()
                            AppLog.info(.command, "Streamed command closed", metadata: [
                                "exitStatus": String(status),
                                "exitSignal": signal ?? "",
                                "stdoutBytes": String(stdoutBytes),
                                "stderrBytes": String(stderrBytes),
                                "stdoutResidualBytes": String(outTail.residual.count),
                                "stderrResidualBytes": String(errTail.residual.count),
                            ])
                            await MainActor.run {
                                if !outTail.text.isEmpty { stdoutText.append(outTail.text) }
                                if !errTail.text.isEmpty { stderrText.append(errTail.text) }
                                if !outTail.residual.isEmpty {
                                    stdoutText.append("\n<invalid UTF-8: \(outTail.residual.count) bytes>")
                                }
                                if !errTail.residual.isEmpty {
                                    stderrText.append("\n<invalid UTF-8: \(errTail.residual.count) bytes>")
                                }
                                statusLine = "Exit \(status)" + (signal.map { ", signal \($0)" } ?? "")
                            }
                        }
                    }
                }
            }
        } catch let error as SSHKitError {
            AppLog.error(.command, "Streamed command failed", metadata: error.logMetadata)
            await MainActor.run { statusLine = "Error: \(error.message)" }
        } catch {
            AppLog.error(.command, "Streamed command failed (non-SSHKit)", metadata: [
                "errorMessage": error.localizedDescription,
            ])
            await MainActor.run { statusLine = "Error: \(error.localizedDescription)" }
        }
    }

    private static func decodeStrict(_ data: Data, label: String) -> String {
        if data.isEmpty { return "" }
        if let s = String(data: data, encoding: .utf8) { return s }
        return "<invalid UTF-8 in \(label): \(data.count) bytes>"
    }
}
