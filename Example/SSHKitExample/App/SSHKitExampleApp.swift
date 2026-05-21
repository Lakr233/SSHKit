import SwiftUI

@main
struct SSHKitExampleApp: App {
    @State private var store = ConnectionStore()

    var body: some Scene {
        WindowGroup {
            RootView()
                .environment(store)
        }
        #if os(macOS)
        .windowToolbarStyle(.unified)
        .commands { SidebarCommands() }
        #endif
    }
}
