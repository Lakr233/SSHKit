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
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Stepper("Concurrent: \(concurrency)", value: $concurrency, in: 1 ... 32)
                    .frame(maxWidth: 220)
                TextField("command", text: $command)
                    .textFieldStyle(.roundedBorder)
                    .autocorrectionDisabled()
                Button(isRunning ? "Cancel" : "Run") {
                    if isRunning { task?.cancel() } else { runStress() }
                }
                .keyboardShortcut(.return, modifiers: [.command])
                .disabled(store.pool == nil)
                .accessibilityIdentifier("SSHKitExample.MultiCmd.Run")
            }
            ScrollView {
                Text(transcript.isEmpty ? "—" : transcript)
                    .font(.system(.callout, design: .monospaced))
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .textSelection(.enabled)
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        }
        .padding()
        .navigationTitle("Multi-Command Stress")
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
                        } catch let e as SSHKitError {
                            AppLog.error(.multiCommand, "Worker failed",
                                         metadata: ["worker": String(i)].merging(e.logMetadata) { _, new in new })
                            return "[#\(i) error] \(e.message)"
                        } catch {
                            AppLog.error(.multiCommand, "Worker failed (non-SSHKit)", metadata: [
                                "worker": String(i),
                                "errorMessage": error.localizedDescription,
                            ])
                            return "[#\(i) error] \(error.localizedDescription)"
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
