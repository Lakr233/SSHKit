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
        guard let config = store.configuration else { return }
        isMeasuring = true
        defer { isMeasuring = false }
        error = nil
        do {
            report = try await SSHPortLatencyProbe.measure(configuration: config)
        } catch let e as SSHKitError {
            error = e
        } catch {
            self.error = SSHKitError(
                code: SSHKitErrorCode.unavailable.rawValue,
                message: error.localizedDescription,
            )
        }
    }
}
