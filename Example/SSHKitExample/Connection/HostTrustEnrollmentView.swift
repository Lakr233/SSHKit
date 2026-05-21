import SwiftUI

struct HostTrustEnrollmentView: View {
    @Environment(ConnectionStore.self) private var store

    let pending: PendingEnrollment

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            VStack(alignment: .leading, spacing: 8) {
                Label("Verify host key", systemImage: "key.fill")
                    .font(.title2.bold())
                Text("First connect to \(pending.host):\(String(pending.port)). Confirm the server fingerprint below before any credentials are sent.")
                    .foregroundStyle(.secondary)
            }
            GroupBox("Server fingerprint") {
                Text(pending.fingerprint.rawValue)
                    .font(.system(.callout, design: .monospaced))
                    .textSelection(.enabled)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(.vertical, 4)
            }
            HStack(spacing: 12) {
                Button(role: .cancel) {
                    store.denyEnrollment()
                } label: {
                    Text("Deny")
                        .frame(maxWidth: .infinity)
                }
                .buttonStyle(.bordered)
                Button {
                    store.approveEnrollment(pending)
                } label: {
                    Text("Trust & Connect")
                        .frame(maxWidth: .infinity)
                }
                .buttonStyle(.borderedProminent)
                .accessibilityIdentifier("SSHKitExample.Enrollment.Approve")
            }
        }
        .padding(20)
        #if os(macOS)
            .frame(minWidth: 480)
        #endif
    }
}
