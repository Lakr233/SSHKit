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
        VStack(spacing: 0) {
            controlBar
            Divider()
            transcriptArea
        }
        .navigationTitle("Session Fuzz")
        #if os(iOS)
            .navigationBarTitleDisplayMode(.inline)
        #endif
            .toolbar {
                ToolbarItem(placement: .primaryAction) {
                    Button {
                        if isRunning { task?.cancel() } else { runFuzz() }
                    } label: {
                        Label(isRunning ? "Stop" : "Start",
                              systemImage: isRunning ? "stop.fill" : "play.fill")
                    }
                    .accessibilityIdentifier("SSHKitExample.Fuzz.Toggle")
                    .disabled(!isRunning && store.pool == nil)
                }
            }
            .onDisappear { task?.cancel() }
    }

    private var controlBar: some View {
        HStack(spacing: 16) {
            Stepper(value: $workers, in: 1 ... 16) {
                LabeledContent("Workers") {
                    Text("\(workers)").font(.body.monospaced())
                }
            }
            .fixedSize()
            Spacer()
            LabeledContent("Iterations") {
                Text("\(iterationCount)").font(.body.monospaced())
            }
            .fixedSize()
        }
        .padding()
    }

    private var transcriptArea: some View {
        ScrollView {
            if transcript.isEmpty {
                VStack(spacing: 8) {
                    Image(systemName: isRunning ? "hourglass" : "dice")
                        .font(.system(size: 28, weight: .regular))
                        .foregroundStyle(.tertiary)
                        .symbolEffect(.pulse, isActive: isRunning)
                    Text(isRunning ? "Running…" : "Press Start to fuzz")
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
                                        encoding: .utf8,
                                    ) ?? ""
                                    transcript = String(("[w\(worker) i\(currentIteration)] " + head + "\n" + transcript).prefix(8000))
                                }
                            } catch {
                                let message = AppLog.report(error, as: .sessionFuzz, message: "Iteration failed", metadata: [
                                    "worker": String(worker),
                                    "iter": String(currentIteration),
                                ])
                                await MainActor.run {
                                    transcript = String(("[w\(worker) i\(currentIteration) ERR] " + message + "\n" + transcript).prefix(8000))
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
