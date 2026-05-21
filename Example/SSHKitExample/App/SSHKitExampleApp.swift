import Foundation
import SwiftUI

@main
struct SSHKitExampleApp: App {
    @State private var store = ConnectionStore()

    init() {
        AppLog.info(.lifecycle, "SSHKitExampleApp launching", metadata: [
            "bundle": Bundle.main.bundleIdentifier ?? "<unknown>",
            "simulator": SimulatorDetection.isRunningInSimulator ? "true" : "false",
            "processID": String(ProcessInfo.processInfo.processIdentifier),
        ])
    }

    var body: some Scene {
        WindowGroup {
            RootView()
                .environment(store)
                .onAppear {
                    AppLog.debug(.lifecycle, "Root WindowGroup attached")
                }
        }
        #if os(macOS)
        .windowToolbarStyle(.unified)
        .commands { SidebarCommands() }
        #endif
    }
}
