import SSHKit
import SwiftUI

struct LatencyView: View {
    @Environment(ConnectionStore.self) private var store
    @Environment(\.colorScheme) private var colorScheme

    @State private var isMeasuring: Bool = false
    @State private var sampleCount: Int = 0
    @State private var terminal = DiagnosticsTerminal()

    var body: some View {
        FocusedTerminalSurfaceView(context: terminal.viewState)
            .onChange(of: colorScheme, initial: true) {
                terminal.viewState.adopt(colorScheme: colorScheme)
            }
            .navigationTitle("Latency Probe")
        #if os(iOS)
            .navigationBarTitleDisplayMode(.inline)
        #endif
            .toolbar {
                ToolbarItem(placement: .primaryAction) {
                    optionsMenu
                }
                ToolbarItem(placement: .primaryAction) {
                    measureButton
                }
            }
    }

    private var measureButton: some View {
        Button {
            Task { await measure() }
        } label: {
            if isMeasuring {
                ProgressView().controlSize(.small)
            } else {
                Label("Measure", systemImage: "gauge.with.dots.needle.50percent")
            }
        }
        .keyboardShortcut(.return, modifiers: [.command])
        .disabled(store.configuration == nil || isMeasuring)
        .accessibilityIdentifier("SSHKitExample.Latency.Measure")
    }

    private var optionsMenu: some View {
        Menu {
            Section("Samples") {
                Text("Completed: \(sampleCount)")
            }
            Section {
                Button("Clear output", systemImage: "trash") {
                    terminal.clear()
                    sampleCount = 0
                }
            }
        } label: {
            Label("Options", systemImage: "slider.horizontal.3")
        }
        .accessibilityIdentifier("SSHKitExample.Latency.Options")
    }

    private func measure() async {
        guard let config = store.configuration else {
            AppLog.warning(.latency, "Measure tapped without a configuration")
            return
        }
        let meta: [String: String] = ["host": config.host, "port": String(config.port)]
        AppLog.info(.latency, "Measuring latency", metadata: meta)
        isMeasuring = true
        defer { isMeasuring = false }
        let header = "\u{1B}[1m→ \(config.host):\(config.port)\u{1B}[0m  \(timestamp())"
        terminal.writeLine(header)
        do {
            let result = try await AppLog.span(.latency, "SSHPortLatencyProbe.measure", metadata: meta) {
                try await SSHPortLatencyProbe.measure(configuration: config)
            }
            AppLog.info(.latency, "Latency report", metadata: meta + [
                "connectMs": String(Int(result.connectDuration * 1000)),
                "sshServiceMs": String(Int(result.sshServiceDuration * 1000)),
                "totalMs": String(Int(result.totalDuration * 1000)),
            ])
            terminal.writeLine("  connect      \(format(result.connectDuration))")
            terminal.writeLine("  ssh service  \(format(result.sshServiceDuration))")
            terminal.writeLine("  \u{1B}[1mtotal        \(format(result.totalDuration))\u{1B}[0m")
            terminal.writeLine()
            sampleCount += 1
        } catch let sshError as SSHKitError {
            AppLog.error(.latency, "Latency probe failed", metadata: meta + sshError.logMetadata)
            terminal.writeLine("  \u{1B}[31merror\u{1B}[0m \(sshError.message)")
            terminal.writeLine()
        } catch {
            let message = AppLog.report(error, as: .latency, message: "Latency probe failed", metadata: meta)
            terminal.writeLine("  \u{1B}[31merror\u{1B}[0m \(message)")
            terminal.writeLine()
        }
    }

    private func format(_ interval: TimeInterval) -> String {
        String(format: "%6.0f ms", interval * 1000)
    }

    private func timestamp() -> String {
        let formatter = DateFormatter()
        formatter.dateFormat = "HH:mm:ss"
        return "\u{1B}[2m\(formatter.string(from: Date()))\u{1B}[0m"
    }
}
