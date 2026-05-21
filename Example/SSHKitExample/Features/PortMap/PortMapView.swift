import SSHKit
import SwiftUI

struct PortMapView: View {
    @Environment(ConnectionStore.self) private var store

    enum Mode: String, CaseIterable, Identifiable {
        case local, remote, dynamic
        var id: String {
            rawValue
        }

        var title: String {
            switch self {
            case .local: "Local"
            case .remote: "Remote"
            case .dynamic: "Dynamic (SOCKS5)"
            }
        }
    }

    @State private var mode: Mode = .local
    @State private var localHost: String = "127.0.0.1"
    @State private var localPortString: String = "0"
    @State private var remoteHost: String = "127.0.0.1"
    @State private var remotePortString: String = "22"
    @State private var activeForward: ForwardEntry?
    @State private var status: String = ""
    @State private var task: Task<Void, Never>?

    var body: some View {
        Form {
            Section("Mode") {
                Picker("Forward type", selection: $mode) {
                    ForEach(Mode.allCases) { Text($0.title).tag($0) }
                }
                .pickerStyle(.segmented)
            }
            Section("Endpoints") {
                LabeledContent("Local bind") {
                    HStack {
                        TextField("127.0.0.1", text: $localHost)
                        TextField("0", text: $localPortString)
                            .frame(width: 80)
                    }
                }
                if mode != .dynamic {
                    LabeledContent("Remote target") {
                        HStack {
                            TextField("127.0.0.1", text: $remoteHost)
                            TextField("22", text: $remotePortString)
                                .frame(width: 80)
                        }
                    }
                }
            }
            Section {
                Button {
                    if activeForward == nil { openForward() } else { closeForward() }
                } label: {
                    Label(activeForward == nil ? "Open forward" : "Close forward",
                          systemImage: activeForward == nil ? "arrow.right.arrow.left" : "stop.circle")
                }
                .accessibilityIdentifier("SSHKitExample.PortMap.Toggle")
                .disabled(store.pool == nil)
            }
            if let active = activeForward {
                Section("Active") {
                    Text("\(active.kind.title) — bound \(active.boundHost):\(active.boundPort)")
                        .font(.callout.monospaced())
                }
            }
            if !status.isEmpty {
                Section { Text(status).font(.footnote).foregroundStyle(.secondary) }
            }
        }
        .formStyle(.grouped)
        .navigationTitle("Port Map")
    }

    private var localPort: UInt16 {
        UInt16(localPortString) ?? 0
    }

    private var remotePort: UInt16 {
        UInt16(remotePortString) ?? 0
    }

    private func openForward() {
        guard let pool = store.pool else { return }
        let kind = mode
        let lHost = localHost
        let lPort = localPort
        let rHost = remoteHost
        let rPort = remotePort
        status = "Opening…"
        task = Task.detached {
            do {
                try await pool.run { connection in
                    let forward: SSHPortForward = switch kind {
                    case .local:
                        try await connection.startLocalForward(
                            localHost: lHost,
                            localPort: lPort,
                            remoteHost: rHost,
                            remotePort: rPort,
                        )
                    case .remote:
                        try await connection.startRemoteForward(
                            remoteHost: lHost,
                            remotePort: lPort,
                            localHost: rHost,
                            localPort: rPort,
                        )
                    case .dynamic:
                        try await connection.startDynamicForward(
                            localHost: lHost,
                            localPort: lPort,
                        )
                    }
                    await MainActor.run {
                        activeForward = ForwardEntry(
                            kind: kind,
                            forward: forward,
                            boundHost: forward.boundHost,
                            boundPort: forward.boundPort,
                        )
                        status = "Forward opened. Tip: keep this screen alive while the tunnel is in use."
                    }
                    // Stay inside the withConnection scope until the user closes.
                    while await !shouldClose() {
                        try await Task.sleep(nanoseconds: 250_000_000)
                    }
                    try? await forward.close()
                }
            } catch let error as SSHKitError {
                await MainActor.run { status = "Error: \(error.message)" }
            } catch {
                await MainActor.run { status = "Error: \(error.localizedDescription)" }
            }
            await MainActor.run {
                activeForward = nil
                task = nil
            }
        }
    }

    private func closeForward() {
        task?.cancel()
        status = "Closing…"
    }

    @MainActor
    private func shouldClose() -> Bool {
        activeForward == nil || Task.isCancelled
    }

    struct ForwardEntry: Identifiable {
        let id = UUID()
        let kind: Mode
        let forward: SSHPortForward
        let boundHost: String
        let boundPort: UInt16
    }
}
