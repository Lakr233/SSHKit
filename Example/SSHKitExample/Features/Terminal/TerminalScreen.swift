import GhosttyTerminal
import SSHKit
import SwiftUI

struct TerminalScreen: View {
    @Environment(ConnectionStore.self) private var store
    @State private var session: SSHTerminalSession?

    var body: some View {
        Group {
            if let session {
                TerminalSurfaceView(context: session.viewState)
                    .accessibilityIdentifier("SSHKitExample.Terminal.Surface")
                    .overlay(alignment: .topTrailing) {
                        if let err = session.lastError {
                            errorBanner(err)
                        }
                    }
            } else if store.configuration == nil {
                ContentUnavailableView(
                    "Not connected",
                    systemImage: "network.slash",
                    description: Text("Connect first to open a shell.")
                )
            } else {
                ProgressView("Opening shell…")
            }
        }
        .navigationTitle("Terminal")
        .task(id: store.configuration?.host) {
            if let config = store.configuration {
                AppLog.info(.terminal, "TerminalScreen attaching session", metadata: [
                    "host": config.host,
                    "port": String(config.port),
                ])
                let s = SSHTerminalSession(configuration: config, logRecorder: store.logRecorder)
                session = s
                await s.start()
            } else {
                AppLog.debug(.terminal, "TerminalScreen task fired without configuration")
            }
        }
        .onDisappear {
            AppLog.info(.terminal, "TerminalScreen disappearing — tearing down session")
            let s = session
            session = nil
            Task { await s?.stop() }
        }
    }

    private func errorBanner(_ error: SSHKitError) -> some View {
        Text(error.message)
            .font(.footnote.monospaced())
            .padding(8)
            .background(.red.opacity(0.85), in: .rect(cornerRadius: 6))
            .foregroundStyle(.white)
            .padding(8)
    }
}
