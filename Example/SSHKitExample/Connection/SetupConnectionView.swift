import SSHKit
import SwiftUI

struct SetupConnectionView: View {
    @Environment(ConnectionStore.self) private var store
    @Environment(\.dismiss) private var dismiss

    @AppStorage("SSHKitExample.Setup.host") private var host: String = "127.0.0.1"
    @AppStorage("SSHKitExample.Setup.port") private var portString: String = "7422"
    @AppStorage("SSHKitExample.Setup.username") private var username: String = "root"
    @AppStorage("SSHKitExample.Setup.password") private var password: String = ""
    @State private var isConnecting: Bool = false

    var body: some View {
        Form {
            Section("Server") {
                TextField("Host", text: $host, prompt: Text("127.0.0.1"))
                    .textContentType(.URL)
                    .autocorrectionDisabled()
                #if os(iOS)
                    .keyboardType(.URL)
                    .textInputAutocapitalization(.never)
                #endif
                TextField("Port", text: $portString, prompt: Text("22"))
                #if os(iOS)
                    .keyboardType(.numberPad)
                #endif
            }
            Section("Credentials") {
                TextField("Username", text: $username, prompt: Text("root"))
                    .autocorrectionDisabled()
                #if os(iOS)
                    .textInputAutocapitalization(.never)
                #endif
                SecureField("Password", text: $password, prompt: Text("password"))
            } footer: {
                VStack(alignment: .leading, spacing: 4) {
                    Text("First connect discovers the host key. You'll approve the fingerprint before any credentials are sent.")
                    Text("Demo only: host, port, username, and password persist in plain text via UserDefaults — never enter production credentials.")
                }
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
                ToolbarItem(placement: .confirmationAction) {
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
