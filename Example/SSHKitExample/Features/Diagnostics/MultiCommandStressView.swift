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
        guard let pool = store.pool else { return }
        let cmd = command
        let count = concurrency
        transcript = ""
        isRunning = true
        task = Task {
            defer { Task { @MainActor in isRunning = false; task = nil } }
            await withTaskGroup(of: String.self) { group in
                for i in 0 ..< count {
                    group.addTask {
                        do {
                            let result = try await pool.run { conn in
                                try await conn.execute(cmd)
                            }
                            let out = String(data: result.standardOutput, encoding: .utf8) ?? "<bin>"
                            return "[#\(i) exit=\(result.exitStatus)]\n\(out)"
                        } catch let e as SSHKitError {
                            return "[#\(i) error] \(e.message)"
                        } catch {
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
