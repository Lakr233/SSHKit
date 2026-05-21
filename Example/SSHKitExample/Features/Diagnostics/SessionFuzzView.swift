import SSHKit
import SwiftUI

struct SessionFuzzView: View {
    @Environment(ConnectionStore.self) private var store

    @State private var workers: Int = 3
    @State private var transcript: String = ""
    @State private var isRunning: Bool = false
    @State private var task: Task<Void, Never>?
    @State private var iterationCount: Int = 0

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Stepper("Workers: \(workers)", value: $workers, in: 1 ... 16)
                    .frame(maxWidth: 220)
                Spacer()
                Text("Iterations: \(iterationCount)")
                    .font(.callout.monospaced())
                Button(isRunning ? "Stop" : "Start") {
                    if isRunning { task?.cancel() } else { runFuzz() }
                }
                .accessibilityIdentifier("SSHKitExample.Fuzz.Toggle")
                .disabled(store.pool == nil)
            }
            ScrollView {
                Text(transcript.isEmpty ? "—" : transcript)
                    .font(.system(.callout, design: .monospaced))
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .textSelection(.enabled)
            }
        }
        .padding()
        .navigationTitle("Session Fuzz")
        .onDisappear { task?.cancel() }
    }

    private func runFuzz() {
        guard let pool = store.pool else {
            AppLog.warning(.sessionFuzz, "runFuzz without an active pool")
            return
        }
        let n = workers
        AppLog.info(.sessionFuzz, "Fuzz starting", metadata: ["workers": String(n)])
        transcript = ""
        iterationCount = 0
        isRunning = true
        task = Task {
            defer {
                Task { @MainActor in
                    AppLog.info(.sessionFuzz, "Fuzz stopped", metadata: [
                        "workers": String(n),
                        "iterations": String(iterationCount),
                    ])
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
                                await MainActor.run {
                                    iterationCount += 1
                                    let head = String(
                                        data: result.standardOutput.prefix(64),
                                        encoding: .utf8
                                    ) ?? ""
                                    transcript = String(("[w\(worker) i\(currentIteration)] " + head + "\n" + transcript).prefix(8000))
                                }
                            } catch let e as SSHKitError {
                                AppLog.error(.sessionFuzz, "Iteration failed",
                                             metadata: ["worker": String(worker), "iter": String(currentIteration)].merging(e.logMetadata) { _, new in new })
                                await MainActor.run {
                                    transcript = String(("[w\(worker) i\(currentIteration) ERR] " + e.message + "\n" + transcript).prefix(8000))
                                }
                            } catch {
                                AppLog.error(.sessionFuzz, "Iteration failed (non-SSHKit)", metadata: [
                                    "worker": String(worker),
                                    "iter": String(currentIteration),
                                    "errorMessage": error.localizedDescription,
                                ])
                                await MainActor.run {
                                    transcript = String(("[w\(worker) i\(currentIteration) ERR] " + error.localizedDescription + "\n" + transcript).prefix(8000))
                                }
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
