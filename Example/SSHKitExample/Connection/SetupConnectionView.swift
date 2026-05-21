import SSHKit
import SwiftUI

struct SetupConnectionView: View {
    @Environment(ConnectionStore.self) private var store

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
            Section {
                TextField("Username", text: $username, prompt: Text("root"))
                    .autocorrectionDisabled()
                #if os(iOS)
                    .textInputAutocapitalization(.never)
                #endif
                SecureField("Password", text: $password, prompt: Text("password"))
            } header: {
                Text("Credentials")
            } footer: {
                VStack(alignment: .leading, spacing: 4) {
                    Text("Host-key approval happens before the password is sent.")
                    Text("Demo only: host, port, username, and password persist in plain text via UserDefaults.")
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
                if store.configuration != nil {
                    ToolbarItem(placement: .destructiveAction) {
                        Button("Disconnect", role: .destructive) {
                            store.disconnect()
                        }
                        .accessibilityIdentifier("SSHKitExample.Setup.Disconnect")
                    }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button {
                        Task { await connect() }
                    } label: {
                        Text(connectButtonTitle)
                    }
                    .disabled(isConnecting || host.isEmpty || username.isEmpty || password.isEmpty || port == nil)
                    .accessibilityIdentifier("SSHKitExample.Setup.Connect")
                }
            }
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

    private var port: UInt16? {
        UInt16(portString)
    }

    private var connectButtonTitle: String {
        if isConnecting {
            "Connecting…"
        } else if store.configuration != nil {
            "Reconnect"
        } else {
            "Discover & Connect"
        }
    }

    private var bindingForError: Binding<Bool> {
        Binding(
            get: { store.lastError != nil },
            set: { newValue in if !newValue { store.lastError = nil } }
        )
    }

    private func connect() async {
        guard let port else {
            AppLog.warning(.ui, "SetupConnectionView.connect aborted: invalid port", metadata: [
                "portInput": portString,
            ])
            return
        }
        AppLog.info(.ui, "SetupConnectionView submitted", metadata: [
            "host": host,
            "port": String(port),
            "username": username,
        ])
        isConnecting = true
        defer { isConnecting = false }
        await store.beginConnect(
            host: host,
            port: port,
            username: username,
            authentication: .password(password)
        )
    }
}
