import SSHKit
import SwiftUI

struct MultiCommandStressView: View {
    @Environment(ConnectionStore.self) private var store
    @Environment(\.colorScheme) private var colorScheme

    @State private var concurrency: Int = 4
    @State private var command: String = "whoami && cat /etc/alpine-release"
    @State private var isRunning: Bool = false
    @State private var task: Task<Void, Never>?
    @State private var terminal = DiagnosticsTerminal()

    var body: some View {
        FocusedTerminalSurfaceView(context: terminal.viewState)
            .onChange(of: colorScheme, initial: true) {
                terminal.viewState.adopt(colorScheme: colorScheme)
            }
            .navigationTitle("Multi-Command Stress")
        #if os(iOS)
            .navigationBarTitleDisplayMode(.inline)
        #endif
            .toolbar {
                ToolbarItem(placement: .primaryAction) {
                    optionsMenu
                }
                ToolbarItem(placement: .primaryAction) {
                    runButton
                }
            }
    }

    private var runButton: some View {
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

    private var optionsMenu: some View {
        Menu {
            Section("Command") {
                TextField("Command", text: $command, prompt: Text("whoami"))
                    .textFieldStyle(.automatic)
                    .disabled(isRunning)
            }
            Section("Concurrency") {
                Stepper("Workers: \(concurrency)", value: $concurrency, in: 1 ... 32)
                    .disabled(isRunning)
            }
            Section {
                Button("Clear output", systemImage: "trash") {
                    terminal.clear()
                }
            }
        } label: {
            Label("Options", systemImage: "slider.horizontal.3")
        }
        .accessibilityIdentifier("SSHKitExample.MultiCmd.Options")
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
        terminal.clear()
        terminal.writeLine("\u{1B}[1mStarting \(count) workers — \(cmd)\u{1B}[0m")
        isRunning = true
        let started = DispatchTime.now()
        task = Task {
            defer {
                let ms = (DispatchTime.now().uptimeNanoseconds &- started.uptimeNanoseconds) / 1_000_000
                AppLog.info(.multiCommand, "Stress run finished", metadata: [
                    "concurrency": String(count),
                    "durationMs": String(ms),
                ])
                Task { @MainActor in
                    terminal.writeLine("\u{1B}[2mFinished in \(ms) ms\u{1B}[0m")
                    isRunning = false
                    task = nil
                }
            }
            await withTaskGroup(of: Void.self) { group in
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
                            let header = "\u{1B}[36m[#\(i) exit=\(result.exitStatus)]\u{1B}[0m"
                            await MainActor.run {
                                terminal.writeLine(header)
                                terminal.write(out.hasSuffix("\n") ? out : out + "\n")
                            }
                        } catch {
                            let message = AppLog.report(error, as: .multiCommand, message: "Worker failed", metadata: ["worker": String(i)])
                            let line = "\u{1B}[31m[#\(i) error]\u{1B}[0m \(message)"
                            await MainActor.run { terminal.writeLine(line) }
                        }
                    }
                }
                await group.waitForAll()
            }
        }
    }
}
