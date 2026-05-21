import SwiftUI

struct HostTrustEnrollmentView: View {
    @Environment(ConnectionStore.self) private var store

    let pending: PendingEnrollment
    @State private var isConnecting = false

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
                .disabled(isConnecting)
                Button {
                    Task { await approve() }
                } label: {
                    if isConnecting {
                        ProgressView()
                            .frame(maxWidth: .infinity)
                    } else {
                        Text("Trust & Connect")
                            .frame(maxWidth: .infinity)
                    }
                }
                .buttonStyle(.borderedProminent)
                .disabled(isConnecting)
                .accessibilityIdentifier("SSHKitExample.Enrollment.Approve")
            }
        }
        .padding(20)
        #if os(macOS)
            .frame(minWidth: 480)
        #endif
            .alert(
                "Connection error",
                isPresented: bindingForError,
                presenting: store.lastError
            ) { _ in
                Button("OK", role: .cancel) { store.lastError = nil }
            } message: { error in
                Text(error.message)
            }
    }

    private var bindingForError: Binding<Bool> {
        Binding(
            get: { store.lastError != nil },
            set: { newValue in if !newValue { store.lastError = nil } }
        )
    }

    private func approve() async {
        AppLog.info(.ui, "Host trust enrollment — Approve tapped", metadata: [
            "host": pending.host,
            "port": String(pending.port),
            "fingerprint": pending.fingerprint.rawValue,
        ])
        isConnecting = true
        defer { isConnecting = false }
        await store.approveEnrollment(pending)
    }
}
