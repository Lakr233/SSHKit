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

    enum OutputStream: String, Hashable, CaseIterable, Identifiable {
        case stdout, stderr
        var id: String {
            rawValue
        }

        var title: String {
            rawValue
        }

        var systemImage: String {
            switch self {
            case .stdout: "text.alignleft"
            case .stderr: "exclamationmark.triangle"
            }
        }
    }

    @State private var commandText: String = "uname -a"
    @State private var mode: Mode = .collected
    @State private var stdoutText: String = ""
    @State private var stderrText: String = ""
    @State private var statusLine: String = ""
    @State private var exitStatus: Int32?
    @State private var hasError: Bool = false
    @State private var isRunning: Bool = false
    @State private var task: Task<Void, Never>?
    @State private var selectedStream: OutputStream = .stdout

    var body: some View {
        VStack(spacing: 0) {
            composer
            Divider()
            outputArea
            if !statusLine.isEmpty {
                Divider()
                statusBar
            }
        }
        .navigationTitle("Command")
        #if os(iOS)
            .navigationBarTitleDisplayMode(.inline)
        #endif
            .toolbar {
                ToolbarItem(placement: .principal) {
                    modePicker
                }
                ToolbarItem(placement: .primaryAction) {
                    outputPicker
                }
                ToolbarItem(placement: .primaryAction) {
                    runButton
                }
            }
    }

    private var composer: some View {
        VStack(alignment: .leading, spacing: 12) {
            TextField("command", text: $commandText, axis: .vertical)
                .textFieldStyle(.plain)
                .font(.system(.body, design: .monospaced))
                .lineLimit(1 ... 5)
                .autocorrectionDisabled()
            #if os(iOS)
                .textInputAutocapitalization(.never)
            #endif
                .padding(.horizontal, 12)
                .padding(.vertical, 10)
                .background(
                    RoundedRectangle(cornerRadius: 10, style: .continuous)
                        .fill(.quaternary.opacity(0.5)),
                )
                .accessibilityIdentifier("SSHKitExample.Command.Field")
        }
        .padding()
    }

    private var modePicker: some View {
        Picker("Mode", selection: $mode) {
            ForEach(Mode.allCases) { mode in
                Text(mode.title).tag(mode)
            }
        }
        .pickerStyle(.segmented)
        .disabled(isRunning)
    }

    private var outputPicker: some View {
        Picker("Output", selection: $selectedStream) {
            ForEach(OutputStream.allCases) { stream in
                Label(stream.title, systemImage: stream.systemImage).tag(stream)
            }
        }
        .pickerStyle(.segmented)
    }

    private var outputArea: some View {
        VStack(spacing: 0) {
            ScrollView {
                let body = selectedStream == .stdout ? stdoutText : stderrText
                if body.isEmpty {
                    emptyOutput
                        .frame(maxWidth: .infinity, maxHeight: .infinity)
                        .padding(.vertical, 40)
                } else {
                    Text(body)
                        .font(.system(.callout, design: .monospaced))
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .textSelection(.enabled)
                        .padding(.horizontal)
                        .padding(.bottom, 12)
                }
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    private var emptyOutput: some View {
        VStack(spacing: 8) {
            Image(systemName: isRunning ? "hourglass" : selectedStream.systemImage)
                .font(.system(size: 28, weight: .regular))
                .foregroundStyle(.tertiary)
                .symbolEffect(.pulse, isActive: isRunning)
            Text(isRunning ? "Running…" : "No \(selectedStream.title) yet")
                .font(.callout)
                .foregroundStyle(.secondary)
        }
    }

    private var statusBar: some View {
        HStack(spacing: 8) {
            Image(systemName: statusIcon)
                .foregroundStyle(statusTint)
            Text(statusLine)
                .font(.footnote.monospaced())
                .foregroundStyle(.secondary)
                .lineLimit(2)
            Spacer(minLength: 0)
        }
        .padding(.horizontal)
        .padding(.vertical, 10)
        .background(.bar)
    }

    private var statusIcon: String {
        if hasError { return "xmark.octagon.fill" }
        if let exit = exitStatus { return exit == 0 ? "checkmark.circle.fill" : "exclamationmark.circle.fill" }
        return "ellipsis.circle"
    }

    private var statusTint: Color {
        if hasError { return .red }
        if let exit = exitStatus { return exit == 0 ? .green : .orange }
        return .secondary
    }

    private var runButton: some View {
        Button {
            if isRunning {
                task?.cancel()
            } else {
                runCommand()
            }
        } label: {
            Label(isRunning ? "Cancel" : "Run",
                  systemImage: isRunning ? "stop.fill" : "play.fill")
        }
        .keyboardShortcut(.return, modifiers: [.command])
        .accessibilityIdentifier("SSHKitExample.Command.Run")
        .disabled(!isRunning && (store.pool == nil || commandText.trimmingCharacters(in: .whitespaces).isEmpty))
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
        exitStatus = nil
        hasError = false
        selectedStream = .stdout
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
            exitStatus = result.exitStatus
            statusLine = Self.statusLine(exitStatus: result.exitStatus, exitSignal: result.exitSignal)
            if !stderrText.isEmpty, stdoutText.isEmpty {
                selectedStream = .stderr
            }
            AppLog.info(.command, "Collected execution finished", metadata: [
                "exitStatus": String(result.exitStatus),
                "exitSignal": result.exitSignal ?? "",
                "stdoutBytes": String(result.standardOutput.count),
                "stderrBytes": String(result.standardError.count),
            ])
        } catch {
            hasError = true
            statusLine = "Error: \(AppLog.report(error, as: .command, message: "Collected execution failed"))"
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
                                exitStatus = status
                                statusLine = Self.statusLine(exitStatus: status, exitSignal: signal)
                                if !stderrText.isEmpty, stdoutText.isEmpty {
                                    selectedStream = .stderr
                                }
                            }
                        }
                    }
                }
            }
        } catch {
            let message = AppLog.report(error, as: .command, message: "Streamed command failed")
            await MainActor.run {
                hasError = true
                statusLine = "Error: \(message)"
            }
        }
    }

    private static func statusLine(exitStatus: Int32, exitSignal: String?) -> String {
        "Exit \(exitStatus)" + (exitSignal.map { ", signal \($0)" } ?? "")
    }

    private static func decodeStrict(_ data: Data, label: String) -> String {
        if data.isEmpty { return "" }
        if let s = String(data: data, encoding: .utf8) { return s }
        return "<invalid UTF-8 in \(label): \(data.count) bytes>"
    }
}
