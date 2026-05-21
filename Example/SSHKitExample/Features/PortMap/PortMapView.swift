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
            Section("Local bind") {
                LabeledContent("Host") {
                    TextField("Host", text: $localHost, prompt: Text("127.0.0.1"))
                        .labelsHidden()
                        .multilineTextAlignment(.trailing)
                        .textFieldStyle(.plain)
                        .autocorrectionDisabled()
                    #if os(iOS)
                        .textInputAutocapitalization(.never)
                    #endif
                }
                LabeledContent("Port") {
                    TextField("Port", text: $localPortString, prompt: Text("0"))
                        .labelsHidden()
                        .multilineTextAlignment(.trailing)
                        .textFieldStyle(.plain)
                    #if os(iOS)
                        .keyboardType(.numberPad)
                    #endif
                }
            }
            if mode != .dynamic {
                Section("Remote target") {
                    LabeledContent("Host") {
                        TextField("Host", text: $remoteHost, prompt: Text("127.0.0.1"))
                            .labelsHidden()
                            .multilineTextAlignment(.trailing)
                            .textFieldStyle(.plain)
                            .autocorrectionDisabled()
                        #if os(iOS)
                            .textInputAutocapitalization(.never)
                        #endif
                    }
                    LabeledContent("Port") {
                        TextField("Port", text: $remotePortString, prompt: Text("22"))
                            .labelsHidden()
                            .multilineTextAlignment(.trailing)
                            .textFieldStyle(.plain)
                        #if os(iOS)
                            .keyboardType(.numberPad)
                        #endif
                    }
                }
            }
            Section {
                Button {
                    if activeForward == nil { openForward() } else { closeForward() }
                } label: {
                    Label(activeForward == nil ? "Open forward" : "Close forward",
                          systemImage: activeForward == nil ? "arrow.right.arrow.left" : "stop.circle")
                        .frame(maxWidth: .infinity)
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
        guard let pool = store.pool else {
            AppLog.warning(.portMap, "openForward without an active pool")
            return
        }
        let kind = mode
        let lHost = localHost
        let lPort = localPort
        let rHost = remoteHost
        let rPort = remotePort
        let meta: [String: String] = [
            "kind": kind.rawValue,
            "localHost": lHost,
            "localPort": String(lPort),
            "remoteHost": kind == .dynamic ? "" : rHost,
            "remotePort": kind == .dynamic ? "" : String(rPort),
        ]
        AppLog.info(.portMap, "Opening forward", metadata: meta)
        status = "Opening…"
        task = Task.detached {
            do {
                try await pool.run { connection in
                    let forward: SSHPortForward = try await AppLog.span(.portMap, "startForward", metadata: meta) {
                        switch kind {
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
                    let boundMeta = meta + [
                        "boundHost": forward.boundHost,
                        "boundPort": String(forward.boundPort),
                    ]
                    AppLog.info(.portMap, "Forward bound", metadata: boundMeta)
                    // Stay inside the withConnection scope until the user closes.
                    while await !shouldClose() {
                        try await Task.sleep(nanoseconds: 250_000_000)
                    }
                    AppLog.info(.portMap, "Closing forward", metadata: boundMeta)
                    try? await forward.close()
                }
            } catch {
                let message = AppLog.report(error, as: .portMap, message: "Forward failed", metadata: meta)
                await MainActor.run { status = "Error: \(message)" }
            }
            await MainActor.run {
                activeForward = nil
                task = nil
            }
        }
    }

    private func closeForward() {
        AppLog.info(.portMap, "User requested forward close")
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
