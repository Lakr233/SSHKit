import SSHKit
import SwiftUI
import UniformTypeIdentifiers

struct SFTPBrowserView: View {
    @Environment(ConnectionStore.self) private var store

    @State private var sftp: SFTPClient?
    @State private var owningConnection: SSHConnection?
    @State private var currentPath: String = "/"
    @State private var entries: [SFTPEntry] = []
    @State private var statusMessage: String = ""
    @State private var coordinator = FileTransferCoordinator()
    @State private var showImporter: Bool = false
    @State private var exportSource: URL?
    @State private var isLoading: Bool = false

    var body: some View {
        VStack(spacing: 0) {
            pathBar
            Divider()
            if isLoading {
                ProgressView().padding()
            } else {
                List(entries, id: \.filename) { entry in
                    row(for: entry)
                }
                .listStyle(.plain)
                .accessibilityIdentifier("SSHKitExample.SFTP.List")
            }
            transferStrip
            statusBar
        }
        .navigationTitle("SFTP")
        .toolbar {
            ToolbarItem(placement: .primaryAction) {
                Button {
                    showImporter = true
                } label: {
                    Label("Upload", systemImage: "arrow.up.doc")
                }
                .disabled(sftp == nil)
                .accessibilityIdentifier("SSHKitExample.SFTP.Upload")
            }
            ToolbarItem(placement: .primaryAction) {
                Button {
                    Task { await refresh() }
                } label: {
                    Label("Refresh", systemImage: "arrow.clockwise")
                }
                .disabled(sftp == nil)
            }
        }
        .task(id: store.configuration?.host) { await openSFTP() }
        .onDisappear { closeSFTP() }
        .uploadFileImporter(isPresented: $showImporter) { result in
            switch result {
            case let .success(url):
                Task { await performUpload(url: url) }
            case let .failure(error):
                statusMessage = "Picker error: \(error.localizedDescription)"
            }
        }
        .fileExporter(
            isPresented: Binding(
                get: { exportSource != nil },
                set: { newValue in if !newValue { exportSource = nil } },
            ),
            document: exportSource.map { ExportDocument(url: $0) },
            contentType: .data,
            defaultFilename: exportSource?.lastPathComponent,
        ) { _ in
            exportSource = nil
        }
    }

    private var pathBar: some View {
        HStack {
            Button {
                Task { await goUp() }
            } label: {
                Image(systemName: "chevron.up")
            }
            .disabled(currentPath == "/")
            TextField("/", text: $currentPath, onCommit: {
                Task { await refresh() }
            })
            .textFieldStyle(.roundedBorder)
            .accessibilityIdentifier("SSHKitExample.SFTP.PathField")
        }
        .padding(8)
    }

    private var transferStrip: some View {
        Group {
            if !coordinator.transfers.isEmpty {
                VStack(alignment: .leading, spacing: 4) {
                    ForEach(coordinator.transfers) { transfer in
                        VStack(alignment: .leading, spacing: 2) {
                            HStack {
                                Image(systemName: transfer.direction == .upload ? "arrow.up.doc" : "arrow.down.doc")
                                Text(transfer.name).font(.callout)
                                Spacer()
                                Text("\(transfer.completed)/\(transfer.total)")
                                    .font(.caption.monospaced())
                                    .foregroundStyle(.secondary)
                            }
                            ProgressView(value: transfer.fraction)
                        }
                    }
                }
                .padding(8)
                .background(.background.secondary, in: .rect)
            }
        }
    }

    private var statusBar: some View {
        Group {
            if !statusMessage.isEmpty {
                Text(statusMessage)
                    .font(.footnote.monospaced())
                    .foregroundStyle(.secondary)
                    .padding(.horizontal, 12)
                    .padding(.vertical, 6)
                    .frame(maxWidth: .infinity, alignment: .leading)
            }
        }
    }

    private func row(for entry: SFTPEntry) -> some View {
        let attrs = entry.attributes
        let isDir = attrs?.isDirectory ?? false
        return HStack {
            Image(systemName: iconName(for: entry))
                .foregroundStyle(.tint)
            Text(entry.filename)
                .lineLimit(1)
            Spacer()
            if let attrs, attrs.isRegular {
                Text(byteCountFormatter.string(fromByteCount: Int64(attrs.size)))
                    .font(.caption.monospaced())
                    .foregroundStyle(.secondary)
            }
        }
        .contentShape(.rect)
        .onTapGesture {
            if isDir {
                Task { await navigate(into: entry) }
            }
        }
        .contextMenu {
            if attrs?.isRegular ?? false {
                Button("Download…") {
                    Task { await performDownload(of: entry) }
                }
            }
            Button("Delete", role: .destructive) {
                Task { await performDelete(entry) }
            }
        }
    }

    private func iconName(for entry: SFTPEntry) -> String {
        guard let attrs = entry.attributes else { return "questionmark.square" }
        if attrs.isDirectory { return "folder" }
        if attrs.isSymlink { return "link" }
        return "doc"
    }

    private var byteCountFormatter: ByteCountFormatter {
        let f = ByteCountFormatter()
        f.allowedUnits = [.useKB, .useMB, .useGB]
        f.countStyle = .file
        return f
    }

    // MARK: - SFTP lifecycle

    private func openSFTP() async {
        guard let config = store.configuration else { return }
        statusMessage = "Connecting…"
        do {
            let conn = try await SSHClient.connect(configuration: config)
            owningConnection = conn
            let client = try await conn.openSFTP()
            sftp = client
            statusMessage = ""
            await refresh()
        } catch let error as SSHKitError {
            statusMessage = "Error: \(error.message)"
        } catch {
            statusMessage = "Error: \(error.localizedDescription)"
        }
    }

    private func closeSFTP() {
        let client = sftp
        let conn = owningConnection
        sftp = nil
        owningConnection = nil
        Task {
            try? await client?.close()
            try? await conn?.close()
        }
    }

    // MARK: - Navigation

    private func goUp() async {
        guard currentPath != "/" else { return }
        let trimmed = currentPath.hasSuffix("/")
            ? String(currentPath.dropLast())
            : currentPath
        let parent = (trimmed as NSString).deletingLastPathComponent
        currentPath = parent.isEmpty ? "/" : parent
        await refresh()
    }

    private func navigate(into entry: SFTPEntry) async {
        let separator = currentPath.hasSuffix("/") ? "" : "/"
        currentPath = "\(currentPath)\(separator)\(entry.filename)"
        await refresh()
    }

    private func refresh() async {
        guard let sftp else { return }
        isLoading = true
        defer { isLoading = false }
        do {
            let items = try await sftp.listDirectory(currentPath)
            entries = items
                .filter { $0.filename != "." && $0.filename != ".." }
                .sorted { lhs, rhs in
                    let lhsDir = lhs.attributes?.isDirectory ?? false
                    let rhsDir = rhs.attributes?.isDirectory ?? false
                    if lhsDir != rhsDir { return lhsDir && !rhsDir }
                    return lhs.filename.localizedCaseInsensitiveCompare(rhs.filename) == .orderedAscending
                }
        } catch let error as SSHKitError {
            statusMessage = "Error: \(error.message)"
        } catch {
            statusMessage = "Error: \(error.localizedDescription)"
        }
    }

    // MARK: - Operations

    private func performUpload(url: URL) async {
        guard let sftp else { return }
        let separator = currentPath.hasSuffix("/") ? "" : "/"
        let remotePath = "\(currentPath)\(separator)\(url.lastPathComponent)"
        await coordinator.upload(sftp: sftp, localURL: url, remotePath: remotePath)
        await refresh()
    }

    private func performDownload(of entry: SFTPEntry) async {
        guard let sftp else { return }
        let separator = currentPath.hasSuffix("/") ? "" : "/"
        let remotePath = "\(currentPath)\(separator)\(entry.filename)"
        let tempURL = await coordinator.downloadToTemp(sftp: sftp, remotePath: remotePath)
        if let tempURL {
            exportSource = tempURL
        }
    }

    private func performDelete(_ entry: SFTPEntry) async {
        guard let sftp else { return }
        let separator = currentPath.hasSuffix("/") ? "" : "/"
        let remotePath = "\(currentPath)\(separator)\(entry.filename)"
        do {
            if entry.attributes?.isDirectory == true {
                try await sftp.removeDirectory(remotePath)
            } else {
                try await sftp.removeFile(remotePath)
            }
            await refresh()
        } catch let error as SSHKitError {
            statusMessage = "Delete error: \(error.message)"
        } catch {
            statusMessage = "Delete error: \(error.localizedDescription)"
        }
    }
}

private struct ExportDocument: FileDocument {
    static let readableContentTypes: [UTType] = [.data]
    let url: URL

    init(url: URL) {
        self.url = url
    }

    init(configuration _: ReadConfiguration) throws {
        throw CocoaError(.fileReadUnsupportedScheme)
    }

    func fileWrapper(configuration _: WriteConfiguration) throws -> FileWrapper {
        let data = try Data(contentsOf: url)
        return FileWrapper(regularFileWithContents: data)
    }
}
