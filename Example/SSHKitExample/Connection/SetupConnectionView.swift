import SSHKit
import SwiftUI

struct SetupConnectionView: View {
    @Environment(ConnectionStore.self) private var store
    @Environment(\.dismiss) private var dismiss

    @State private var host: String = "127.0.0.1"
    @State private var portString: String = "7422"
    @State private var username: String = "root"
    @State private var password: String = ""
    @State private var isConnecting: Bool = false

    var body: some View {
        Form {
            Section("Server") {
                LabeledContent("Host") {
                    TextField("127.0.0.1", text: $host)
                        .textContentType(.URL)
                        .autocorrectionDisabled()
                    #if os(iOS)
                        .keyboardType(.URL)
                        .textInputAutocapitalization(.never)
                    #endif
                }
                LabeledContent("Port") {
                    TextField("22", text: $portString)
                    #if os(iOS)
                        .keyboardType(.numberPad)
                    #endif
                }
            }
            Section("Credentials") {
                LabeledContent("Username") {
                    TextField("root", text: $username)
                        .autocorrectionDisabled()
                    #if os(iOS)
                        .textInputAutocapitalization(.never)
                    #endif
                }
                LabeledContent("Password") {
                    SecureField("password", text: $password)
                }
            }
            Section {
                Button {
                    Task { await connect() }
                } label: {
                    if isConnecting {
                        ProgressView()
                    } else {
                        Text("Discover & Connect")
                    }
                }
                .disabled(isConnecting || host.isEmpty || username.isEmpty || password.isEmpty || port == nil)
                .accessibilityIdentifier("SSHKitExample.Setup.Connect")
            } footer: {
                Text("First connect discovers the host key. You'll approve the fingerprint before any credentials are sent.")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
            }
        }
        .formStyle(.grouped)
        .navigationTitle("Connect to SSH")
        #if os(macOS)
            .frame(minWidth: 420, minHeight: 360)
        #endif
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { dismiss() }
                }
            }
    }

    private var port: UInt16? {
        UInt16(portString)
    }

    private func connect() async {
        guard let port else { return }
        isConnecting = true
        defer { isConnecting = false }
        await store.beginConnect(
            host: host,
            port: port,
            username: username,
            authentication: .password(password),
        )
    }
}
