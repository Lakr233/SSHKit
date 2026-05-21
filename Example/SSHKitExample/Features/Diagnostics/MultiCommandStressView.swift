import SSHKit
import SwiftUI

struct MultiCommandStressView: View {
    @Environment(ConnectionStore.self) private var store

    @State private var concurrency: Int = 4
    @State private var command: String = "whoami && cat /etc/alpine-release"
    @State private var transcript: String = ""
    @State private var isRunning: Bool = false
    @State private var task: Task<Void, Never>?

    var body: some View {
        VStack(spacing: 0) {
            composer
            Divider()
            transcriptArea
        }
        .navigationTitle("Multi-Command Stress")
        #if os(iOS)
            .navigationBarTitleDisplayMode(.inline)
        #endif
            .toolbar {
                ToolbarItem(placement: .primaryAction) {
                    Button {
                        if isRunning { task?.cancel() } else { runStress() }
                    } label: {
                        Label(isRunning ? "Cancel" : "Run",
                              systemImage: isRunning ? "stop.fill" : "play.fill")
                    }
                    .keyboardShortcut(.return, modifiers: [.command])
                    .accessibilityIdentifier("SSHKitExample.MultiCmd.Run")
                    .disabled(!isRunning && (store.pool == nil || command.trimmingCharacters(in: .whitespaces).isEmpty))
                }
            }
    }

    private var composer: some View {
        VStack(alignment: .leading, spacing: 12) {
            TextField("command", text: $command, axis: .vertical)
                .textFieldStyle(.plain)
                .font(.system(.body, design: .monospaced))
                .lineLimit(1 ... 3)
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
            Stepper(value: $concurrency, in: 1 ... 32) {
                LabeledContent("Concurrent workers") {
                    Text("\(concurrency)").font(.body.monospaced())
                }
            }
            .disabled(isRunning)
        }
        .padding()
    }

    private var transcriptArea: some View {
        ScrollView {
            if transcript.isEmpty {
                VStack(spacing: 8) {
                    Image(systemName: isRunning ? "hourglass" : "rectangle.stack")
                        .font(.system(size: 28, weight: .regular))
                        .foregroundStyle(.tertiary)
                        .symbolEffect(.pulse, isActive: isRunning)
                    Text(isRunning ? "Running…" : "No output yet")
                        .font(.callout)
                        .foregroundStyle(.secondary)
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
                .padding(.vertical, 60)
            } else {
                Text(transcript)
                    .font(.system(.callout, design: .monospaced))
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .textSelection(.enabled)
                    .padding()
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    private func runStress() {
        guard let pool = store.pool else {
            AppLog.warning(.multiCommand, "runStress without an active pool")
            return
        }
        let cmd = command
        let count = concurrency
        AppLog.info(.multiCommand, "Starting concurrent stress run", metadata: [
            "concurrency": String(count),
            "commandPreview": String(cmd.prefix(80)),
        ])
        transcript = ""
        isRunning = true
        let started = DispatchTime.now()
        task = Task {
            defer {
                let ms = (DispatchTime.now().uptimeNanoseconds &- started.uptimeNanoseconds) / 1_000_000
                AppLog.info(.multiCommand, "Stress run finished", metadata: [
                    "concurrency": String(count),
                    "durationMs": String(ms),
                ])
                Task { @MainActor in isRunning = false; task = nil }
            }
            await withTaskGroup(of: String.self) { group in
                for i in 0 ..< count {
                    group.addTask {
                        AppLog.debug(.multiCommand, "Worker started", metadata: ["worker": String(i)])
                        do {
                            let result = try await pool.run { conn in
                                try await conn.execute(cmd)
                            }
                            AppLog.info(.multiCommand, "Worker finished", metadata: [
                                "worker": String(i),
                                "exitStatus": String(result.exitStatus),
                                "stdoutBytes": String(result.standardOutput.count),
                            ])
                            let out = String(data: result.standardOutput, encoding: .utf8) ?? "<bin>"
                            return "[#\(i) exit=\(result.exitStatus)]\n\(out)"
                        } catch {
                            let message = AppLog.report(error, as: .multiCommand, message: "Worker failed", metadata: ["worker": String(i)])
                            return "[#\(i) error] \(message)"
                        }
                    }
                }
                for await line in group {
                    await MainActor.run { transcript.append(line + "\n---\n") }
                }
            }
        }
    }
}
