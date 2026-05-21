@preconcurrency import Foundation
import SSHKit
import SwiftUI
import UniformTypeIdentifiers

#if os(macOS) && !targetEnvironment(macCatalyst)
    import AppKit
#endif

/// SFTP browser, ported from vphone-cli's `VPhoneFileBrowserView`. The macOS
/// surface uses `Table` with the full toolbar/search/drag-drop loadout, and
/// iOS / Catalyst use a `List` with the same model underneath.
struct SFTPBrowserView: View {
    @Environment(ConnectionStore.self) private var store
    @State private var model: SFTPBrowserModel?

    var body: some View {
        Group {
            if store.configuration == nil {
                ContentUnavailableView(
                    "Not connected",
                    systemImage: "network.slash",
                    description: Text("Connect first to browse SFTP."),
                )
            } else if let model {
                if model.isConnected {
                    BrowserBody(model: model)
                } else if let err = model.error {
                    ContentUnavailableView {
                        Label("SFTP Failed", systemImage: "exclamationmark.triangle")
                    } description: {
                        Text(err)
                    } actions: {
                        Button("Retry") {
                            Task {
                                model.error = nil
                                await model.open()
                            }
                        }
                    }
                } else {
                    ProgressView("Opening SFTP…").progressViewStyle(.circular)
                }
            } else {
                ProgressView("Opening SFTP…").progressViewStyle(.circular)
            }
        }
        .navigationTitle("SFTP")
        .task(id: store.configuration?.host) {
            guard let config = store.configuration else { return }
            let m = SFTPBrowserModel(configuration: config)
            model = m
            await m.open()
        }
        .onDisappear {
            AppLog.info(.sftp, "SFTPBrowserView disappearing")
            let m = model
            model = nil
            m?.close()
        }
    }
}

// MARK: - Cross-platform body

private struct BrowserBody: View {
    @Bindable var model: SFTPBrowserModel
    @State private var showNewFolder = false
    @State private var newFolderName = ""
    @State private var renameTarget: SFTPRemoteFile?
    @State private var renameDraft: String = ""
    @State private var exportSource: URL?

    #if !os(macOS) || targetEnvironment(macCatalyst)
        @State private var showImporter = false
    #endif

    private let controlBarHeight: CGFloat = 28

    var body: some View {
        ZStack {
            content
                .padding(.bottom, controlBarHeight)
                .overlay(controlBar.frame(maxHeight: .infinity, alignment: .bottom))
                .opacity(isBusy ? 0.25 : 1)
                .disabled(isBusy)
                .toolbar { toolbarContent }
            if model.isTransferring {
                progressOverlay
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
                    .background(.thickMaterial)
                    .zIndex(100)
            } else if model.isLoading {
                listingOverlay
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
                    .background(.thickMaterial)
                    .zIndex(100)
            }
        }
        .accessibilityIdentifier("SSHKitExample.SFTP.Root")
        .alert(
            "Error",
            isPresented: errorBinding,
            actions: { Button("OK") { model.error = nil } },
            message: { Text(model.error ?? "") },
        )
        .sheet(isPresented: $showNewFolder) { newFolderSheet }
        .sheet(item: $renameTarget) { target in renameSheet(target: target) }
        #if !os(macOS) || targetEnvironment(macCatalyst)
            .uploadFileImporter(isPresented: $showImporter) { result in
                switch result {
                case let .success(url):
                    Task { await model.uploadFiles(urls: [url]) }
                case let .failure(error):
                    model.error = "Upload picker error: \(error.localizedDescription)"
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
        #endif
    }

    // MARK: - Content (platform-conditional)

    @ViewBuilder
    private var content: some View {
        #if os(macOS) && !targetEnvironment(macCatalyst)
            macTable
        #else
            iosList
        #endif
    }

    // MARK: - macOS Table

    #if os(macOS) && !targetEnvironment(macCatalyst)
        private var macTable: some View {
            Table(
                of: SFTPRemoteFile.self,
                selection: $model.selection,
                sortOrder: $model.sortOrder,
            ) {
                TableColumn("", value: \.name) { file in
                    Image(systemName: file.icon)
                        .foregroundStyle(file.isDirectoryLike ? .blue : .secondary)
                        .frame(width: 20)
                }
                .width(28)

                TableColumn("Name", value: \.name) { file in
                    Text(file.name).lineLimit(1).help(file.name)
                }
                .width(min: 120, ideal: 240, max: .infinity)

                TableColumn("Permissions", value: \.permissions) { file in
                    Text(file.permissions).font(.system(.body, design: .monospaced))
                }
                .width(90)

                TableColumn("Size", value: \.size) { file in
                    Text(file.displaySize)
                        .font(.system(.body, design: .monospaced))
                        .foregroundStyle(file.isDirectoryLike ? .secondary : .primary)
                }
                .width(min: 60, ideal: 90, max: .infinity)

                TableColumn("Modified", value: \.modified) { file in
                    Text(file.displayDate)
                }
                .width(min: 90, ideal: 160, max: .infinity)
            } rows: {
                ForEach(model.filteredFiles) { file in
                    TableRow(file)
                }
            }
            .accessibilityIdentifier("SSHKitExample.SFTP.Table")
            .searchable(text: $model.searchText, prompt: "Filter files")
            .onDrop(of: [.fileURL], isTargeted: nil, perform: dropFiles)
            .contextMenu(forSelectionType: SFTPRemoteFile.ID.self) { ids in
                contextMenu(for: ids)
            } primaryAction: { ids in
                primaryAction(for: ids)
            }
            .onChange(of: model.selection) { _, _ in }
        }
    #endif

    // MARK: - iOS List

    #if !os(macOS) || targetEnvironment(macCatalyst)
        private var iosList: some View {
            List(model.filteredFiles, id: \.id, selection: $model.selection) { file in
                HStack {
                    Image(systemName: file.icon)
                        .foregroundStyle(file.isDirectoryLike ? .blue : .secondary)
                    VStack(alignment: .leading, spacing: 2) {
                        Text(file.name).lineLimit(1)
                        Text("\(file.permissions)  \(file.displaySize)  \(file.displayDate)")
                            .font(.caption.monospaced())
                            .foregroundStyle(.secondary)
                    }
                }
                .contentShape(.rect)
                .onTapGesture {
                    if file.isDirectoryLike {
                        model.openItem(file)
                    } else {
                        model.selection = [file.id]
                    }
                }
                .contextMenu {
                    Button("Download…") {
                        Task {
                            if let url = await model.downloadToTemp(file: file) {
                                exportSource = url
                            }
                        }
                    }
                    Button("Rename…") {
                        renameTarget = file
                        renameDraft = file.name
                    }
                    Button("Delete", role: .destructive) {
                        model.selection = [file.id]
                        Task { await model.deleteSelected() }
                    }
                }
            }
            .listStyle(.plain)
            .searchable(text: $model.searchText, prompt: "Filter files")
            .accessibilityIdentifier("SSHKitExample.SFTP.List")
        }
    #endif

    // MARK: - Control Bar

    private var controlBar: some View {
        HStack(spacing: 6) {
            Circle()
                .fill(model.isConnected ? Color.green : Color.orange)
                .frame(width: 8, height: 8)
            Divider()
            ScrollView(.horizontal, showsIndicators: false) {
                HStack(spacing: 4) {
                    ForEach(Array(model.breadcrumbs.enumerated()), id: \.offset) { _, crumb in
                        if crumb.path != "/" || model.breadcrumbs.count == 1 {
                            Image(systemName: "chevron.right")
                                .font(.system(size: 8, weight: .semibold))
                                .foregroundStyle(.tertiary)
                        }
                        Button(crumb.name) { model.goToBreadcrumb(crumb.path) }
                            .buttonStyle(.plain)
                    }
                }
                .font(.system(size: 11, weight: .medium, design: .monospaced))
            }
            Divider()
            Text(model.statusText)
                .font(.system(size: 11, design: .monospaced))
                .foregroundStyle(.secondary)
                .frame(minWidth: 60)
        }
        .padding(.horizontal, 8)
        .frame(height: controlBarHeight)
        .frame(maxWidth: .infinity)
        .background(.bar)
    }

    // MARK: - Progress Overlay

    private var isBusy: Bool {
        model.isTransferring || model.isLoading
    }

    private var listingOverlay: some View {
        VStack(spacing: 12) {
            ProgressView().progressViewStyle(.circular)
            Text(model.currentPath)
                .font(.system(.footnote, design: .monospaced))
                .foregroundStyle(.secondary)
                .lineLimit(1)
                .truncationMode(.middle)
        }
        .frame(maxWidth: 280)
        .padding(24)
    }

    private var progressOverlay: some View {
        VStack(spacing: 12) {
            ProgressView().progressViewStyle(.circular)
            if model.transferTotal > 0 {
                ProgressView(value: Double(model.transferCurrent), total: Double(model.transferTotal))
                    .progressViewStyle(.linear)
            }
            HStack {
                Text(model.transferName ?? "Transferring…").lineLimit(1)
                Spacer()
                if model.transferTotal > 0 {
                    Text("\(formatBytes(model.transferCurrent)) / \(formatBytes(model.transferTotal))")
                }
            }
            .font(.system(.footnote, design: .monospaced))
        }
        .frame(maxWidth: 320)
        .padding(24)
    }

    // MARK: - Toolbar

    @ToolbarContentBuilder
    private var toolbarContent: some ToolbarContent {
        ToolbarItem(placement: .navigation) {
            Button {
                model.goBack()
            } label: {
                Label("Back", systemImage: "chevron.left")
            }
            .disabled(!model.canGoBack)
            .keyboardShortcut(.leftArrow, modifiers: .command)
        }
        ToolbarItem(placement: .navigation) {
            Button {
                model.goForward()
            } label: {
                Label("Forward", systemImage: "chevron.right")
            }
            .disabled(!model.canGoForward)
            .keyboardShortcut(.rightArrow, modifiers: .command)
        }
        ToolbarItem {
            Button {
                newFolderName = ""
                showNewFolder = true
            } label: {
                Label("New Folder", systemImage: "folder.badge.plus")
            }
            .keyboardShortcut("n", modifiers: .command)
        }
        ToolbarItem {
            Button {
                uploadAction()
            } label: {
                Label("Upload", systemImage: "square.and.arrow.up")
            }
            .accessibilityIdentifier("SSHKitExample.SFTP.Upload")
        }
        ToolbarItem {
            Button {
                downloadAction()
            } label: {
                Label("Download", systemImage: "square.and.arrow.down")
            }
            .disabled(model.selection.isEmpty)
        }
        ToolbarItem {
            Button {
                Task { await model.deleteSelected() }
            } label: {
                Label("Delete", systemImage: "trash")
            }
            .disabled(model.selection.isEmpty)
        }
        ToolbarItem {
            Button {
                Task { await model.refresh() }
            } label: {
                Label("Refresh", systemImage: "arrow.clockwise")
            }
            .keyboardShortcut("r", modifiers: .command)
        }
    }

    // MARK: - Context Menu (macOS)

    #if os(macOS) && !targetEnvironment(macCatalyst)
        @ViewBuilder
        private func contextMenu(for ids: Set<SFTPRemoteFile.ID>) -> some View {
            Button("Open") { primaryAction(for: ids) }
            Button("Download…") {
                model.selection = ids
                downloadAction()
            }
            Button("Delete", role: .destructive) {
                model.selection = ids
                Task { await model.deleteSelected() }
            }
            Divider()
            Button("Rename…") {
                if let id = ids.first, let file = model.filteredFiles.first(where: { $0.id == id }) {
                    renameTarget = file
                    renameDraft = file.name
                }
            }
            .disabled(ids.count != 1)
            Divider()
            Button("Refresh") { Task { await model.refresh() } }
            Divider()
            Button("Copy Name") { copyNames(ids: ids) }
            Button("Copy Path") { copyPaths(ids: ids) }
            Divider()
            Button("Upload…") { uploadAction() }
            Button("New Folder…") {
                newFolderName = ""
                showNewFolder = true
            }
        }

        private func primaryAction(for ids: Set<SFTPRemoteFile.ID>) {
            guard let id = ids.first,
                  let file = model.filteredFiles.first(where: { $0.id == id })
            else { return }
            model.openItem(file)
        }
    #endif

    // MARK: - Sheets

    private var newFolderSheet: some View {
        VStack(spacing: 16) {
            Text("New Folder").font(.headline)
            TextField("Folder name", text: $newFolderName)
                .textFieldStyle(.roundedBorder)
                .onSubmit { createFolder() }
            HStack {
                Button("Cancel") { showNewFolder = false }
                    .keyboardShortcut(.cancelAction)
                Spacer()
                Button("Create") { createFolder() }
                    .keyboardShortcut(.defaultAction)
                    .disabled(newFolderName.trimmingCharacters(in: .whitespaces).isEmpty)
            }
        }
        .padding(20)
        .frame(width: 300)
    }

    private func renameSheet(target: SFTPRemoteFile) -> some View {
        VStack(spacing: 16) {
            Text("Rename").font(.headline)
            Text(target.path)
                .font(.caption.monospaced())
                .foregroundStyle(.secondary)
            TextField("New name", text: $renameDraft)
                .textFieldStyle(.roundedBorder)
                .onSubmit { commitRename(target: target) }
            HStack {
                Button("Cancel") { renameTarget = nil }
                    .keyboardShortcut(.cancelAction)
                Spacer()
                Button("Rename") { commitRename(target: target) }
                    .keyboardShortcut(.defaultAction)
                    .disabled(renameDraft.trimmingCharacters(in: .whitespaces).isEmpty || renameDraft == target.name)
            }
        }
        .padding(20)
        .frame(minWidth: 320)
    }

    private func commitRename(target: SFTPRemoteFile) {
        let new = renameDraft.trimmingCharacters(in: .whitespaces)
        renameTarget = nil
        guard !new.isEmpty, new != target.name else { return }
        Task { await model.renameFile(target, to: new) }
    }

    // MARK: - Actions

    private func uploadAction() {
        #if os(macOS) && !targetEnvironment(macCatalyst)
            let panel = NSOpenPanel()
            panel.allowsMultipleSelection = true
            panel.canChooseFiles = true
            panel.canChooseDirectories = false
            guard panel.runModal() == .OK else { return }
            Task { await model.uploadFiles(urls: panel.urls) }
        #else
            showImporter = true
        #endif
    }

    private func downloadAction() {
        #if os(macOS) && !targetEnvironment(macCatalyst)
            let panel = NSOpenPanel()
            panel.allowsMultipleSelection = false
            panel.canChooseFiles = false
            panel.canChooseDirectories = true
            panel.prompt = "Save Here"
            guard panel.runModal() == .OK, let url = panel.url else { return }
            Task { await model.downloadSelected(to: url) }
        #else
            guard let id = model.selection.first,
                  let file = model.filteredFiles.first(where: { $0.id == id })
            else { return }
            Task {
                if let url = await model.downloadToTemp(file: file) {
                    exportSource = url
                }
            }
        #endif
    }

    private func createFolder() {
        let name = newFolderName.trimmingCharacters(in: .whitespaces)
        guard !name.isEmpty else { return }
        showNewFolder = false
        Task { await model.createFolder(name: name) }
    }

    private func dropFiles(_ providers: [NSItemProvider]) -> Bool {
        #if os(macOS) && !targetEnvironment(macCatalyst)
            let validProviders = providers.filter { $0.canLoadObject(ofClass: URL.self) }
            guard !validProviders.isEmpty else { return false }
            Task { @MainActor in
                var urls: [URL] = []
                for provider in validProviders {
                    if let url = await loadDroppedURL(from: provider) {
                        urls.append(url)
                    }
                }
                if urls.isEmpty {
                    model.error = "Could not load any files from the dropped items."
                } else {
                    await model.uploadFiles(urls: urls)
                }
            }
            return true
        #else
            _ = providers
            return false
        #endif
    }

    #if os(macOS) && !targetEnvironment(macCatalyst)
        private func loadDroppedURL(from provider: NSItemProvider) async -> URL? {
            await withCheckedContinuation { continuation in
                _ = provider.loadObject(ofClass: URL.self) { url, _ in
                    continuation.resume(returning: url)
                }
            }
        }

        private func copyNames(ids: Set<SFTPRemoteFile.ID>) {
            let names = model.filteredFiles
                .filter { ids.contains($0.id) }
                .map(\.name)
                .joined(separator: "\n")
            NSPasteboard.general.prepareForNewContents()
            NSPasteboard.general.setString(names, forType: .string)
        }

        private func copyPaths(ids: Set<SFTPRemoteFile.ID>) {
            let paths = model.filteredFiles
                .filter { ids.contains($0.id) }
                .map(\.path)
                .joined(separator: "\n")
            NSPasteboard.general.prepareForNewContents()
            NSPasteboard.general.setString(paths, forType: .string)
        }
    #endif

    private func formatBytes(_ bytes: Int64) -> String {
        ByteCountFormatter.string(fromByteCount: bytes, countStyle: .file)
    }

    private var errorBinding: Binding<Bool> {
        Binding(
            get: { model.error != nil },
            set: { newValue in if !newValue { model.error = nil } },
        )
    }
}

// MARK: - Export Document (iOS / Catalyst download save sheet)

#if !os(macOS) || targetEnvironment(macCatalyst)
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
#endif
