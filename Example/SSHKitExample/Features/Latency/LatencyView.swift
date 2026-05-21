import SSHKit
import SwiftUI

struct LatencyView: View {
    @Environment(ConnectionStore.self) private var store

    @State private var report: SSHPortLatencyReport?
    @State private var isMeasuring: Bool = false
    @State private var error: SSHKitError?

    var body: some View {
        Form {
            Section {
                Button {
                    Task { await measure() }
                } label: {
                    if isMeasuring {
                        ProgressView()
                    } else {
                        Label("Measure latency", systemImage: "gauge.with.dots.needle.50percent")
                    }
                }
                .disabled(store.configuration == nil || isMeasuring)
                .accessibilityIdentifier("SSHKitExample.Latency.Measure")
            }
            if let report {
                Section("Latest report") {
                    LabeledContent("Host") { Text("\(report.host):\(report.port)") }
                    LabeledContent("Connect") { Text(format(report.connectDuration)) }
                    LabeledContent("SSH service") { Text(format(report.sshServiceDuration)) }
                    LabeledContent("Total") { Text(format(report.totalDuration)) }
                }
            }
            if let error {
                Section("Error") {
                    Text(error.message)
                        .foregroundStyle(.red)
                }
            }
        }
        .formStyle(.grouped)
        .navigationTitle("Latency Probe")
    }

    private func format(_ interval: TimeInterval) -> String {
        String(format: "%.0f ms", interval * 1000)
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
        error = nil
        do {
            let result = try await AppLog.span(.latency, "SSHPortLatencyProbe.measure", metadata: meta) {
                try await SSHPortLatencyProbe.measure(configuration: config)
            }
            report = result
            AppLog.info(.latency, "Latency report", metadata: meta.merging([
                "connectMs": String(Int(result.connectDuration * 1000)),
                "sshServiceMs": String(Int(result.sshServiceDuration * 1000)),
                "totalMs": String(Int(result.totalDuration * 1000)),
            ]) { _, new in new })
        } catch let e as SSHKitError {
            AppLog.error(.latency, "Latency probe failed", metadata: meta.merging(e.logMetadata) { _, new in new })
            error = e
        } catch {
            AppLog.error(.latency, "Latency probe failed (non-SSHKit)", metadata: meta.merging([
                "errorMessage": error.localizedDescription,
            ]) { _, new in new })
            self.error = SSHKitError(
                code: SSHKitErrorCode.unavailable.rawValue,
                message: error.localizedDescription
            )
        }
    }
}
