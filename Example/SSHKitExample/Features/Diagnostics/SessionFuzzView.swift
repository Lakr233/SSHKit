import SSHKit
import SwiftUI

struct SessionFuzzView: View {
    @Environment(ConnectionStore.self) private var store
    @Environment(\.colorScheme) private var colorScheme

    @State private var workers: Int = 3
    @State private var isRunning: Bool = false
    @State private var task: Task<Void, Never>?
    @State private var iterationCount: Int = 0
    @State private var terminal = DiagnosticsTerminal()

    var body: some View {
        FocusedTerminalSurfaceView(context: terminal.viewState)
            .onChange(of: colorScheme, initial: true) {
                terminal.viewState.adopt(colorScheme: colorScheme)
            }
            .navigationTitle("Session Fuzz")
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
            .onDisappear { task?.cancel() }
    }

    private var runButton: some View {
        Button {
            if isRunning { task?.cancel() } else { runFuzz() }
        } label: {
            Label(isRunning ? "Stop" : "Start",
                  systemImage: isRunning ? "stop.fill" : "play.fill")
        }
        .accessibilityIdentifier("SSHKitExample.Fuzz.Toggle")
        .disabled(!isRunning && store.pool == nil)
    }

    private var optionsMenu: some View {
        Menu {
            Section("Workers") {
                Stepper("Workers: \(workers)", value: $workers, in: 1 ... 16)
                    .disabled(isRunning)
            }
            Section("Stats") {
                Text("Iterations: \(iterationCount)")
            }
            Section {
                Button("Clear output", systemImage: "trash") {
                    terminal.clear()
                }
            }
        } label: {
            Label("Options", systemImage: "slider.horizontal.3")
        }
        .accessibilityIdentifier("SSHKitExample.Fuzz.Options")
    }

    private func runFuzz() {
        guard let pool = store.pool else {
            AppLog.warning(.sessionFuzz, "runFuzz without an active pool")
            return
        }
        let n = workers
        AppLog.info(.sessionFuzz, "Fuzz starting", metadata: ["workers": String(n)])
        terminal.clear()
        terminal.writeLine("\u{1B}[1mFuzzing with \(n) workers\u{1B}[0m")
        iterationCount = 0
        isRunning = true
        task = Task {
            defer {
                Task { @MainActor in
                    AppLog.info(.sessionFuzz, "Fuzz stopped", metadata: [
                        "workers": String(n),
                        "iterations": String(iterationCount),
                    ])
                    terminal.writeLine("\u{1B}[2mStopped after \(iterationCount) iterations\u{1B}[0m")
                    isRunning = false
                    task = nil
                }
            }
            await withTaskGroup(of: Void.self) { group in
                for worker in 0 ..< n {
                    group.addTask {
                        var iter = 0
                        while !Task.isCancelled {
                            iter += 1
                            let currentIteration = iter
                            do {
                                let result = try await pool.run { conn in
                                    try await conn.execute("date +%T && echo worker=\(worker) iter=\(currentIteration)")
                                }
                                let head = String(
                                    data: result.standardOutput.prefix(64),
                                    encoding: .utf8
                                )?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
                                let line = "\u{1B}[36m[w\(worker) i\(currentIteration)]\u{1B}[0m \(head)"
                                await MainActor.run {
                                    iterationCount += 1
                                    terminal.writeLine(line)
                                }
                            } catch {
                                let message = AppLog.report(error, as: .sessionFuzz, message: "Iteration failed", metadata: [
                                    "worker": String(worker),
                                    "iter": String(currentIteration),
                                ])
                                let line = "\u{1B}[31m[w\(worker) i\(currentIteration) ERR]\u{1B}[0m \(message)"
                                await MainActor.run { terminal.writeLine(line) }
                            }
                            try? await Task.sleep(nanoseconds: 100_000_000)
                        }
                    }
                }
                await group.waitForAll()
            }
        }
    }
}
