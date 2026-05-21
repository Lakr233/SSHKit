import SwiftUI

enum SidebarItem: String, Hashable, CaseIterable, Identifiable {
    case command
    case terminal
    case sftp
    case portMap
    case multiCommand
    case sessionFuzz
    case latency

    var id: String {
        rawValue
    }

    var title: String {
        switch self {
        case .command: "Command"
        case .terminal: "Terminal"
        case .sftp: "SFTP"
        case .portMap: "Port Map"
        case .multiCommand: "Multi-Command Stress"
        case .sessionFuzz: "Session Fuzz"
        case .latency: "Latency Probe"
        }
    }

    var systemImage: String {
        switch self {
        case .command: "terminal"
        case .terminal: "rectangle.inset.filled.and.cursorarrow"
        case .sftp: "folder"
        case .portMap: "arrow.left.arrow.right"
        case .multiCommand: "bolt.horizontal"
        case .sessionFuzz: "die.face.5"
        case .latency: "gauge.with.dots.needle.50percent"
        }
    }

    var section: SidebarSection {
        switch self {
        case .command, .terminal: .shell
        case .sftp: .transfers
        case .portMap: .tunnels
        case .multiCommand, .sessionFuzz, .latency: .diagnostics
        }
    }
}

enum SidebarSection: String, Hashable, CaseIterable, Identifiable {
    case shell
    case transfers
    case tunnels
    case diagnostics

    var id: String {
        rawValue
    }

    var title: String {
        switch self {
        case .shell: "Shell"
        case .transfers: "Transfers"
        case .tunnels: "Tunnels"
        case .diagnostics: "Diagnostics"
        }
    }

    var items: [SidebarItem] {
        SidebarItem.allCases.filter { $0.section == self }
    }
}

struct RootView: View {
    @Environment(ConnectionStore.self) private var store
    @State private var selection: SidebarItem? = .command

    var body: some View {
        NavigationSplitView {
            sidebar
                .navigationTitle("SSHKit Example")
        } detail: {
            detail
        }
        .accessibilityIdentifier("SSHKitExample.Root")
        .sheet(item: bindingForActiveSheet) { sheet in
            switch sheet {
            case .setup:
                SetupConnectionView()
                    .environment(store)
            case let .enrollment(pending):
                HostTrustEnrollmentView(pending: pending)
                    .environment(store)
            }
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
    }

    private var sidebar: some View {
        List(selection: $selection) {
            ForEach(SidebarSection.allCases) { section in
                Section(section.title) {
                    ForEach(section.items) { item in
                        Label(item.title, systemImage: item.systemImage)
                            .tag(Optional(item))
                            .accessibilityIdentifier("SSHKitExample.Sidebar.\(item.rawValue)")
                    }
                }
            }
        }
        .listStyle(.sidebar)
    }

    @ViewBuilder
    private var detail: some View {
        if store.configuration == nil {
            ContentUnavailableView(
                "Not connected",
                systemImage: "network.slash",
                description: Text("Tap Connect to set up an SSH session."),
            )
            .toolbar { connectToolbar }
        } else if let item = selection {
            content(for: item)
                .toolbar { connectToolbar }
                .accessibilityIdentifier("SSHKitExample.Detail.\(item.rawValue)")
        } else {
            ContentUnavailableView(
                "Pick a feature",
                systemImage: "sidebar.left",
                description: Text("Choose a screen from the sidebar."),
            )
            .toolbar { connectToolbar }
        }
    }

    @ViewBuilder
    private func content(for item: SidebarItem) -> some View {
        switch item {
        case .command: CommandView()
        case .terminal: TerminalScreen()
        case .sftp: SFTPBrowserView()
        case .portMap: PortMapView()
        case .multiCommand: MultiCommandStressView()
        case .sessionFuzz: SessionFuzzView()
        case .latency: LatencyView()
        }
    }

    @ToolbarContentBuilder
    private var connectToolbar: some ToolbarContent {
        ToolbarItem(placement: .primaryAction) {
            Button {
                store.startSetupFlow()
            } label: {
                Label(
                    store.configuration == nil ? "Connect" : "Reconnect",
                    systemImage: "bolt.horizontal",
                )
            }
            .accessibilityIdentifier("SSHKitExample.Toolbar.Connect")
        }
    }

    private var bindingForActiveSheet: Binding<ActiveSheet?> {
        Binding(
            get: { store.activeSheet },
            set: { store.activeSheet = $0 },
        )
    }

    private var bindingForError: Binding<Bool> {
        Binding(
            get: { store.lastError != nil },
            set: { newValue in if !newValue { store.lastError = nil } },
        )
    }
}
