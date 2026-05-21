import SSHKit
import SwiftUI

struct LatencyView: View {
    @Environment(ConnectionStore.self) private var store

    @State private var report: SSHPortLatencyReport?
    @State private var isMeasuring: Bool = false
    @State private var error: SSHKitError?

    var body: some View {
        Form {
            if report == nil, error == nil {
                Section {
                    VStack(spacing: 10) {
                        Image(systemName: "gauge.with.dots.needle.50percent")
                            .font(.system(size: 32, weight: .regular))
                            .foregroundStyle(.tertiary)
                        Text(isMeasuring ? "Measuring…" : "No measurement yet")
                            .font(.callout)
                            .foregroundStyle(.secondary)
                    }
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 20)
                    .listRowBackground(Color.clear)
                }
            }
            if let report {
                Section("Latest report") {
                    LabeledContent("Host") { Text("\(report.host):\(report.port)").monospaced() }
                    LabeledContent("Connect") { Text(format(report.connectDuration)).monospaced() }
                    LabeledContent("SSH service") { Text(format(report.sshServiceDuration)).monospaced() }
                    LabeledContent("Total") { Text(format(report.totalDuration)).monospaced().bold() }
                }
            }
            if let error {
                Section("Error") {
                    Label {
                        Text(error.message)
                    } icon: {
                        Image(systemName: "xmark.octagon.fill")
                    }
                    .foregroundStyle(.red)
                }
            }
        }
        .formStyle(.grouped)
        .navigationTitle("Latency Probe")
        #if os(iOS)
            .navigationBarTitleDisplayMode(.inline)
        #endif
            .toolbar {
                ToolbarItem(placement: .primaryAction) {
                    Button {
                        Task { await measure() }
                    } label: {
                        if isMeasuring {
                            ProgressView().controlSize(.small)
                        } else {
                            Label("Measure", systemImage: "gauge.with.dots.needle.50percent")
                        }
                    }
                    .disabled(store.configuration == nil || isMeasuring)
                    .accessibilityIdentifier("SSHKitExample.Latency.Measure")
                }
            }
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
            AppLog.info(.latency, "Latency report", metadata: meta + [
                "connectMs": String(Int(result.connectDuration * 1000)),
                "sshServiceMs": String(Int(result.sshServiceDuration * 1000)),
                "totalMs": String(Int(result.totalDuration * 1000)),
            ])
        } catch let sshError as SSHKitError {
            AppLog.error(.latency, "Latency probe failed", metadata: meta + sshError.logMetadata)
            error = sshError
        } catch {
            let message = AppLog.report(error, as: .latency, message: "Latency probe failed", metadata: meta)
            self.error = SSHKitError(code: SSHKitErrorCode.unavailable.rawValue, message: message)
        }
    }
}
