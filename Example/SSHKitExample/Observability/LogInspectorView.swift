import SSHKit
import SwiftUI

#if os(macOS) && !targetEnvironment(macCatalyst)
    import AppKit
#else
    import UIKit
#endif

/// In-app inspector for the unified event timeline. Reads `AppLog.recorder`
/// every 500 ms and re-renders. Useful when running on iOS where Console.app
/// is not handy, or to triage a stuck flow without leaving the app.
struct LogInspectorView: View {
    @State private var snapshot: [SSHLogEvent] = []
    @State private var filterText: String = ""
    @State private var selectedCategory: AppLogCategory? = nil
    @State private var minLevel: SSHLogLevel = .debug
    @State private var paused: Bool = false
    @State private var autoScroll: Bool = true

    private let dateFormatter: DateFormatter = {
        let f = DateFormatter()
        f.dateFormat = "HH:mm:ss.SSS"
        return f
    }()

    var body: some View {
        VStack(spacing: 0) {
            controlBar
            Divider()
            timeline
                .accessibilityIdentifier("SSHKitExample.Logs.List")
            Divider()
            footer
        }
        .navigationTitle("Logs")
        .toolbar { toolbarContent }
        .task(id: paused) {
            if paused { return }
            refresh()
            while !Task.isCancelled, !paused {
                try? await Task.sleep(nanoseconds: 500_000_000)
                if paused { break }
                refresh()
            }
        }
    }

    // MARK: - Controls

    private var controlBar: some View {
        VStack(spacing: 8) {
            HStack(spacing: 8) {
                Image(systemName: "magnifyingglass").foregroundStyle(.secondary)
                TextField("Filter (text / metadata)", text: $filterText)
                    .textFieldStyle(.roundedBorder)
                    .autocorrectionDisabled()
                #if os(iOS)
                    .textInputAutocapitalization(.never)
                #endif
                Picker("Level", selection: $minLevel) {
                    Text("Debug").tag(SSHLogLevel.debug)
                    Text("Info").tag(SSHLogLevel.info)
                    Text("Warn").tag(SSHLogLevel.warning)
                    Text("Error").tag(SSHLogLevel.error)
                }
                .pickerStyle(.segmented)
                .labelsHidden()
                .frame(width: 240)
                .fixedSize()
            }
            HStack(spacing: 4) {
                categoryChip(nil)
                ScrollView(.horizontal, showsIndicators: false) {
                    HStack(spacing: 4) {
                        ForEach(AppLogCategory.allCases, id: \.rawValue) { cat in
                            categoryChip(cat)
                        }
                    }
                }
            }
        }
        .padding(8)
        .background(.bar)
    }

    private func categoryChip(_ category: AppLogCategory?) -> some View {
        let isOn = selectedCategory == category
        let label = category?.displayName ?? "All"
        return Button {
            selectedCategory = category
        } label: {
            Text(label)
                .font(.caption.weight(.medium))
                .padding(.horizontal, 8)
                .padding(.vertical, 4)
                .background(isOn ? Color.accentColor : .clear, in: .capsule)
                .foregroundStyle(isOn ? Color.white : .secondary)
                .overlay {
                    Capsule().stroke(.secondary.opacity(0.4), lineWidth: isOn ? 0 : 1)
                }
        }
        .buttonStyle(.plain)
    }

    // MARK: - Timeline

    private var timeline: some View {
        ScrollViewReader { proxy in
            ScrollView {
                LazyVStack(alignment: .leading, spacing: 0) {
                    ForEach(Array(filteredEvents.enumerated()), id: \.offset) { _, event in
                        row(event)
                            .padding(.horizontal, 10)
                            .padding(.vertical, 4)
                        Divider().opacity(0.2)
                    }
                }
                .id("logs-top")
            }
            .onChange(of: snapshot.count) { _, _ in
                guard autoScroll, !paused else { return }
                proxy.scrollTo("logs-bottom", anchor: .bottom)
            }
            .overlay(alignment: .bottom) {
                Color.clear.frame(height: 0).id("logs-bottom")
            }
        }
    }

    private func row(_ event: SSHLogEvent) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            HStack(spacing: 6) {
                Text(dateFormatter.string(from: event.timestamp))
                    .font(.caption.monospaced())
                    .foregroundStyle(.secondary)
                levelBadge(event.level)
                Text(event.phase)
                    .font(.caption.weight(.bold))
                    .foregroundStyle(.secondary)
                Spacer()
            }
            Text(event.message)
                .font(.system(.caption, design: .monospaced))
                .textSelection(.enabled)
            if !event.metadata.isEmpty {
                Text(metadataLine(event.metadata))
                    .font(.system(.caption2, design: .monospaced))
                    .foregroundStyle(.tertiary)
                    .lineLimit(2)
                    .textSelection(.enabled)
            }
        }
    }

    private func levelBadge(_ level: SSHLogLevel) -> some View {
        let (label, color): (String, Color) = switch level {
        case .debug: ("DBG", .gray)
        case .info: ("INF", .blue)
        case .warning: ("WRN", .orange)
        case .error: ("ERR", .red)
        }
        return Text(label)
            .font(.caption2.weight(.heavy))
            .padding(.horizontal, 4)
            .padding(.vertical, 1)
            .foregroundStyle(.white)
            .background(color, in: .rect(cornerRadius: 3))
    }

    private func metadataLine(_ metadata: [String: String]) -> String {
        metadata
            .filter { $0.key != "source" && $0.key != "uptimeMs" }
            .sorted { $0.key < $1.key }
            .map { "\($0.key)=\($0.value)" }
            .joined(separator: " ")
    }

    // MARK: - Footer

    private var footer: some View {
        HStack {
            Text("\(filteredEvents.count) shown · \(snapshot.count) total")
                .font(.caption.monospaced())
                .foregroundStyle(.secondary)
            Spacer()
            Toggle("Auto-scroll", isOn: $autoScroll)
                .toggleStyle(.switch)
                .controlSize(.mini)
            Toggle(paused ? "Paused" : "Live", isOn: $paused)
                .toggleStyle(.switch)
                .controlSize(.mini)
        }
        .padding(.horizontal, 10)
        .padding(.vertical, 6)
        .background(.bar)
    }

    // MARK: - Toolbar

    @ToolbarContentBuilder
    private var toolbarContent: some ToolbarContent {
        ToolbarItem {
            Button {
                copyAll()
            } label: {
                Label("Copy", systemImage: "doc.on.doc")
            }
        }
        ToolbarItem {
            Button {
                refresh()
            } label: {
                Label("Refresh", systemImage: "arrow.clockwise")
            }
        }
    }

    // MARK: - Data

    private func refresh() {
        snapshot = AppLog.recorder.events
    }

    private var filteredEvents: [SSHLogEvent] {
        let query = filterText.trimmingCharacters(in: .whitespaces).lowercased()
        return snapshot.filter { event in
            guard event.level.rawValue >= minLevel.rawValue else { return false }
            if let selectedCategory, event.phase != selectedCategory.rawValue {
                return false
            }
            if query.isEmpty { return true }
            if event.message.lowercased().contains(query) { return true }
            if event.phase.lowercased().contains(query) { return true }
            for (key, value) in event.metadata {
                if key.lowercased().contains(query) || value.lowercased().contains(query) {
                    return true
                }
            }
            return false
        }
    }

    private func copyAll() {
        let lines = filteredEvents.map { event in
            let ts = dateFormatter.string(from: event.timestamp)
            let level = switch event.level {
            case .debug: "DBG"
            case .info: "INF"
            case .warning: "WRN"
            case .error: "ERR"
            }
            let meta = metadataLine(event.metadata)
            return "[\(ts)] \(level) \(event.phase): \(event.message)\(meta.isEmpty ? "" : "  {\(meta)}")"
        }
        let blob = lines.joined(separator: "\n")
        #if os(macOS) && !targetEnvironment(macCatalyst)
            NSPasteboard.general.prepareForNewContents()
            NSPasteboard.general.setString(blob, forType: .string)
        #else
            UIPasteboard.general.string = blob
        #endif
        AppLog.info(.ui, "Log inspector copy-to-clipboard", metadata: [
            "lineCount": String(lines.count),
            "byteCount": String(blob.utf8.count),
        ])
    }
}
