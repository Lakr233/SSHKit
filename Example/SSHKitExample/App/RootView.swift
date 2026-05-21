import SwiftUI

enum SidebarItem: String, Hashable, CaseIterable, Identifiable {
    case setup
    case command
    case terminal
    case sftp
    case portMap
    case multiCommand
    case sessionFuzz
    case latency
    case logs

    var id: String {
        rawValue
    }

    var title: String {
        switch self {
        case .setup: "Setup"
        case .command: "Command"
        case .terminal: "Terminal"
        case .sftp: "SFTP"
        case .portMap: "Port Map"
        case .multiCommand: "Multi-Command Stress"
        case .sessionFuzz: "Session Fuzz"
        case .latency: "Latency Probe"
        case .logs: "Logs"
        }
    }

    var systemImage: String {
        switch self {
        case .setup: "bolt.horizontal"
        case .command: "terminal"
        case .terminal: "rectangle.inset.filled.and.cursorarrow"
        case .sftp: "folder"
        case .portMap: "arrow.left.arrow.right"
        case .multiCommand: "bolt.horizontal"
        case .sessionFuzz: "die.face.5"
        case .latency: "gauge.with.dots.needle.50percent"
        case .logs: "text.alignleft"
        }
    }

    var section: SidebarSection {
        switch self {
        case .setup: .connection
        case .command, .terminal: .shell
        case .sftp: .transfers
        case .portMap: .tunnels
        case .multiCommand, .sessionFuzz, .latency: .diagnostics
        case .logs: .observability
        }
    }

    /// Screens that don't require an active SSH configuration.
    var requiresConfiguration: Bool {
        switch self {
        case .setup, .logs: false
        default: true
        }
    }
}

enum SidebarSection: String, Hashable, CaseIterable, Identifiable {
    case connection
    case shell
    case transfers
    case tunnels
    case diagnostics
    case observability

    var id: String {
        rawValue
    }

    var title: String {
        switch self {
        case .connection: "Connection"
        case .shell: "Shell"
        case .transfers: "Transfers"
        case .tunnels: "Tunnels"
        case .diagnostics: "Diagnostics"
        case .observability: "Observability"
        }
    }

    var items: [SidebarItem] {
        SidebarItem.allCases.filter { $0.section == self }
    }
}

struct RootView: View {
    @Environment(ConnectionStore.self) private var store
    @State private var selection: SidebarItem? = .setup

    var body: some View {
        NavigationSplitView {
            sidebar
                .navigationTitle("SSHKit Example")
        } detail: {
            detail
        }
        .accessibilityIdentifier("SSHKitExample.Root")
        .sheet(item: bindingForPendingEnrollment) { pending in
            HostTrustEnrollmentView(pending: pending)
                .environment(store)
        }
        .alert(
            "Connection error",
            isPresented: bindingForError,
            presenting: store.lastError,
        ) { _ in
            Button("OK", role: .cancel) { store.lastError = nil }
        } message: { error in
            Text(error.message)
        }
        .onChange(of: store.configuration == nil) { _, isDisconnected in
            if isDisconnected, let selected = selection, selected.requiresConfiguration {
                selection = .setup
            }
        }
    }

    private var sidebar: some View {
        List(selection: $selection) {
            ForEach(SidebarSection.allCases) { section in
                Section(section.title) {
                    ForEach(section.items) { item in
                        NavigationLink(value: item) {
                            Label(item.title, systemImage: item.systemImage)
                        }
                        .accessibilityIdentifier("SSHKitExample.Sidebar.\(item.rawValue)")
                    }
                }
            }
        }
        .listStyle(.sidebar)
    }

    @ViewBuilder
    private var detail: some View {
        if let item = selection {
            if item.requiresConfiguration, store.configuration == nil {
                ContentUnavailableView(
                    "Not connected",
                    systemImage: "network.slash",
                    description: Text("Open the Setup tab in the sidebar to start an SSH session."),
                )
            } else {
                content(for: item)
                    .accessibilityIdentifier("SSHKitExample.Detail.\(item.rawValue)")
            }
        } else {
            ContentUnavailableView(
                "Pick a feature",
                systemImage: "sidebar.left",
                description: Text("Choose a screen from the sidebar."),
            )
        }
    }

    @ViewBuilder
    private func content(for item: SidebarItem) -> some View {
        switch item {
        case .setup: SetupConnectionView()
        case .command: CommandView()
        case .terminal: TerminalScreen()
        case .sftp: SFTPBrowserView()
        case .portMap: PortMapView()
        case .multiCommand: MultiCommandStressView()
        case .sessionFuzz: SessionFuzzView()
        case .latency: LatencyView()
        case .logs: LogInspectorView()
        }
    }

    private var bindingForPendingEnrollment: Binding<PendingEnrollment?> {
        Binding(
            get: { store.pendingEnrollment },
            set: { store.pendingEnrollment = $0 },
        )
    }

    private var bindingForError: Binding<Bool> {
        Binding(
            get: { store.lastError != nil && store.pendingEnrollment == nil },
            set: { newValue in if !newValue { store.lastError = nil } },
        )
    }
}
