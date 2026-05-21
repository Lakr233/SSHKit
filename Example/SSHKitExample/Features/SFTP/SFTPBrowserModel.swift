import Foundation
import Observation
import SSHKit

/// Observable model behind the SFTP browser. Ported from vphone-cli's
/// `VPhoneFileBrowserModel`, adapted to drive an `SFTPClient` instead of the
/// vphoned RPC protocol. Owns the underlying `SSHConnection` + `SFTPClient`
/// lifecycle so the view is purely declarative.
@MainActor
@Observable
final class SFTPBrowserModel {
    // MARK: - SFTP plumbing

    private let configuration: SSHClientConfiguration
    private var owningConnection: SSHConnection?
    private(set) var sftp: SFTPClient?

    // MARK: - Browser state

    var currentPath = "/"
    var files: [SFTPRemoteFile] = []
    var isLoading = false
    var isConnected = false
    var error: String?
    var searchText = ""
    var selection = Set<SFTPRemoteFile.ID>()
    var sortOrder = [KeyPathComparator(\SFTPRemoteFile.name)]

    // MARK: - Transfer progress

    private var activeTransfer: ActiveTransfer?

    var isTransferring: Bool {
        activeTransfer != nil
    }

    var transferName: String? {
        activeTransfer?.name
    }

    var transferCurrent: Int64 {
        activeTransfer?.completed ?? 0
    }

    var transferTotal: Int64 {
        activeTransfer?.total ?? 0
    }

    private struct ActiveTransfer {
        var name: String
        var completed: Int64
        var total: Int64
    }

    // MARK: - Navigation stacks

    private var pathHistory: [String] = []
    private var forwardHistory: [String] = []

    /// Monotonic token guarding `refresh()` against stale results.
    /// Navigation/refresh calls overlap because libssh I/O is awaited; without
    /// this a slow listing of folder A could overwrite a newer listing of
    /// folder B after the user navigated away.
    private var refreshGeneration: UInt64 = 0

    init(configuration: SSHClientConfiguration) {
        self.configuration = configuration
    }

    // MARK: - Lifecycle

    func open() async {
        guard sftp == nil else { return }
        AppLog.info(.sftp, "Opening SFTP session", metadata: endpointMetadata())
        // Track *this* attempt's connection locally — if two `open()` calls
        // interleave across the `await`s, the catch must not close another
        // attempt's connection by reading the shared `owningConnection` field.
        var pendingConnection: SSHConnection?
        do {
            let conn = try await AppLog.span(.sftp, "SSHClient.connect", metadata: endpointMetadata()) {
                try await SSHClient.connect(configuration: configuration)
            }
            pendingConnection = conn
            owningConnection = conn
            let client = try await AppLog.span(.sftp, "openSFTP", metadata: endpointMetadata()) {
                try await conn.openSFTP()
            }
            sftp = client
            pendingConnection = nil
            isConnected = true
            AppLog.info(.sftp, "SFTP session ready", metadata: endpointMetadata())
            await refresh()
        } catch {
            tearDownPartialOpen(pendingConnection)
            self.error = AppLog.report(error, as: .sftp, message: "Failed to open SFTP", metadata: endpointMetadata())
            isConnected = false
        }
    }

    /// Close a connection from a failed `open()` attempt. Only nils the
    /// shared `owningConnection` if it still points at this attempt — so a
    /// concurrent retry that has already replaced it stays intact.
    private func tearDownPartialOpen(_ pending: SSHConnection?) {
        guard let pending else { return }
        if owningConnection === pending {
            owningConnection = nil
        }
        Task { @Sendable in
            do {
                try await pending.close()
            } catch {
                AppLog.report(error, as: .sftp, message: "Partial SSH connection close failed during open() cleanup")
            }
        }
    }

    func close() {
        AppLog.info(.sftp, "Closing SFTP session", metadata: endpointMetadata())
        let client = sftp
        let conn = owningConnection
        sftp = nil
        owningConnection = nil
        isConnected = false
        Task { @Sendable in
            try? await client?.close()
            try? await conn?.close()
            AppLog.debug(.sftp, "SFTP teardown complete")
        }
    }

    // MARK: - Computed

    var breadcrumbs: [Breadcrumb] {
        var result = [Breadcrumb(name: "/", path: "/")]
        let components = currentPath.split(separator: "/", omittingEmptySubsequences: true)
        var running = ""
        for c in components {
            running += "/\(c)"
            result.append(Breadcrumb(name: String(c), path: running))
        }
        return result
    }

    var filteredFiles: [SFTPRemoteFile] {
        let list: [SFTPRemoteFile]
        if searchText.isEmpty {
            list = files
        } else {
            let query = searchText.lowercased()
            list = files.filter { $0.name.lowercased().contains(query) }
        }
        return list.sorted(using: sortOrder)
    }

    var statusText: String {
        let count = filteredFiles.count
        let suffix = count == 1 ? "item" : "items"
        if !searchText.isEmpty {
            return "\(count) \(suffix) (filtered)"
        }
        return "\(count) \(suffix)"
    }

    struct Breadcrumb: Hashable {
        let name: String
        let path: String
    }

    // MARK: - Navigation

    func navigate(to path: String) {
        AppLog.debug(.sftp, "Navigate", metadata: ["from": currentPath, "to": path])
        moveTo(path.isEmpty ? "/" : path, recordingHistory: true, clearingForward: true)
    }

    func goBack() {
        guard let prev = pathHistory.popLast() else { return }
        forwardHistory.append(currentPath)
        AppLog.debug(.sftp, "Navigate back", metadata: ["currentPath": prev])
        moveTo(prev, recordingHistory: false, clearingForward: false)
    }

    func goForward() {
        guard let next = forwardHistory.popLast() else { return }
        pathHistory.append(currentPath)
        AppLog.debug(.sftp, "Navigate forward", metadata: ["currentPath": next])
        moveTo(next, recordingHistory: false, clearingForward: false)
    }

    func goToBreadcrumb(_ path: String) {
        if path == currentPath { return }
        AppLog.debug(.sftp, "Breadcrumb tap", metadata: ["currentPath": path])
        moveTo(path, recordingHistory: true, clearingForward: true)
    }

    var canGoBack: Bool {
        !pathHistory.isEmpty
    }

    var canGoForward: Bool {
        !forwardHistory.isEmpty
    }

    func openItem(_ file: SFTPRemoteFile) {
        if file.isDirectoryLike {
            navigate(to: file.path)
        }
    }

    /// Single source of truth for moving between directories. Centralizes the
    /// history bookkeeping + selection clearing + listing kick-off that every
    /// nav action used to repeat verbatim.
    private func moveTo(_ path: String, recordingHistory: Bool, clearingForward: Bool) {
        if recordingHistory {
            pathHistory.append(currentPath)
        }
        if clearingForward {
            forwardHistory.removeAll()
        }
        currentPath = path
        selection.removeAll()
        files = []
        // Invalidate any in-flight refresh synchronously so a stale listDirectory
        // resuming between this navigation and the new refresh's own increment
        // cannot write its results under the new path.
        refreshGeneration &+= 1
        Task { await refresh() }
    }

    // MARK: - Refresh

    func refresh() async {
        guard let sftp else { return }
        refreshGeneration &+= 1
        let generation = refreshGeneration
        let pathSnapshot = currentPath
        isLoading = true
        error = nil
        defer { if generation == refreshGeneration { isLoading = false } }

        AppLog.debug(.sftp, "Listing directory", metadata: ["path": pathSnapshot])
        do {
            let entries = try await sftp.listDirectory(pathSnapshot)
            guard generation == refreshGeneration else {
                AppLog.debug(.sftp, "Stale listing dropped", metadata: ["path": pathSnapshot])
                return
            }
            let built = await hydrate(entries, in: pathSnapshot, generation: generation)
            guard generation == refreshGeneration else { return }
            files = built
            AppLog.info(.sftp, "Directory listed", metadata: [
                "path": pathSnapshot,
                "count": String(built.count),
            ])
        } catch {
            guard generation == refreshGeneration else { return }
            self.error = AppLog.report(error, as: .sftp, message: "listDirectory failed", metadata: [
                "path": pathSnapshot,
            ])
            files = []
        }
    }

    /// Hydrate listing entries, following symlinks via `stat`. Bails out
    /// mid-iteration if the user has navigated away (newer `refreshGeneration`).
    private func hydrate(_ entries: [SFTPEntry], in dir: String, generation: UInt64) async -> [SFTPRemoteFile] {
        var built: [SFTPRemoteFile] = []
        for entry in entries {
            guard let initial = SFTPRemoteFile(dir: dir, entry: entry) else { continue }
            guard initial.isSymbolicLink else {
                built.append(initial)
                continue
            }
            let targetIsDirectory = await symlinkTargetIsDirectory(at: initial.path)
            guard generation == refreshGeneration else { return built }
            built.append(initial.withSymlinkTargetsDirectory(targetIsDirectory))
        }
        return built
    }

    private func symlinkTargetIsDirectory(at path: String) async -> Bool {
        guard let sftp else { return false }
        do {
            let attrs = try await sftp.stat(path)
            return attrs.isDirectory
        } catch {
            return false
        }
    }

    // MARK: - File operations

    func deleteSelected() async {
        guard let sftp else { return }
        let selected = files.filter { selection.contains($0.id) }
        AppLog.warning(.sftp, "Delete selected", metadata: [
            "count": String(selected.count),
            "paths": selected.map(\.path).joined(separator: ","),
        ])
        for file in selected {
            do {
                if file.isDirectory {
                    try await sftp.removeDirectory(file.path)
                } else {
                    try await sftp.removeFile(file.path)
                }
                AppLog.info(.sftp, "Deleted", metadata: ["path": file.path])
            } catch {
                self.error = "Delete failed for \(file.name): \(AppLog.report(error, as: .sftp, message: "Delete failed", metadata: ["path": file.path]))"
                return
            }
        }
        selection.removeAll()
        await refresh()
    }

    func createFolder(name: String) async {
        guard let sftp else { return }
        let path = currentPath.joiningRemotePath(name)
        AppLog.info(.sftp, "Creating folder", metadata: ["path": path])
        do {
            try await sftp.createDirectory(path)
            AppLog.info(.sftp, "Folder created", metadata: ["path": path])
            await refresh()
        } catch {
            self.error = "Create folder failed: \(AppLog.report(error, as: .sftp, message: "createDirectory failed", metadata: ["path": path]))"
        }
    }

    func renameFile(_ file: SFTPRemoteFile, to newName: String) async {
        guard let sftp else { return }
        let newPath = file.dir.joiningRemotePath(newName)
        AppLog.info(.sftp, "Renaming", metadata: ["from": file.path, "to": newPath])
        do {
            try await sftp.rename(file.path, to: newPath)
            await refresh()
        } catch {
            self.error = "Rename failed: \(AppLog.report(error, as: .sftp, message: "Rename failed", metadata: ["from": file.path, "to": newPath]))"
        }
    }

    // MARK: - Transfers

    func uploadFiles(urls: [URL]) async {
        guard let sftp else { return }
        AppLog.info(.transfer, "Upload batch starting", metadata: [
            "count": String(urls.count),
            "destination": currentPath,
        ])
        var uploadError: String?
        for url in urls {
            let scoped = SecurityScopedURL(url)
            defer { _ = scoped } // explicit keep-alive — security-scoped URL must outlive the upload
            let name = url.lastPathComponent
            let remotePath = currentPath.joiningRemotePath(name)
            let totalBytes = localFileSize(at: scoped.url)

            beginTransfer(name: name, totalBytes: totalBytes)
            AppLog.info(.transfer, "Upload start", metadata: [
                "localName": name,
                "remotePath": remotePath,
                "size": String(totalBytes),
            ])
            do {
                let start = DispatchTime.now()
                try await sftp.upload(localURL: scoped.url, to: remotePath) { [weak self] completed, total in
                    Task { @MainActor in self?.updateTransferProgress(completed: completed, total: total) }
                }
                AppLog.info(.transfer, "Upload complete", metadata: [
                    "remotePath": remotePath,
                    "size": String(totalBytes),
                    "durationMs": String(elapsedMilliseconds(since: start)),
                ])
            } catch {
                uploadError = "Upload failed for \"\(name)\": \(AppLog.report(error, as: .transfer, message: "Upload failed", metadata: ["remotePath": remotePath, "localName": name]))"
                break
            }
        }
        endTransfer()
        await refresh()
        if let uploadError {
            error = uploadError
        }
    }

    /// Download every selected entry into `directory`. Used on macOS where
    /// users can pick a destination folder via NSOpenPanel.
    func downloadSelected(to directory: URL) async {
        let selected = files.filter { selection.contains($0.id) }
        AppLog.info(.transfer, "Download batch starting", metadata: [
            "count": String(selected.count),
            "destinationDir": directory.path,
        ])
        for file in selected {
            if file.isDirectory {
                await downloadDirectory(file, to: directory)
            } else {
                await downloadFile(file, to: directory)
            }
            if error != nil { break }
        }
        endTransfer()
    }

    /// Download a single file to a freshly allocated temp URL — for iOS
    /// where the destination is picked by `fileExporter` afterwards.
    func downloadToTemp(file: SFTPRemoteFile) async -> URL? {
        guard let sftp else { return nil }
        guard let tempDir = makeTempDirectory() else { return nil }
        let destURL = tempDir.appendingPathComponent(file.name)

        beginTransfer(name: file.name, totalBytes: file.size)
        AppLog.info(.transfer, "Download (temp) start", metadata: [
            "remotePath": file.path,
            "tempPath": destURL.path,
            "size": String(file.size),
        ])
        defer { endTransfer() }
        do {
            let start = DispatchTime.now()
            try await sftp.download(remotePath: file.path, to: destURL) { [weak self] completed, total in
                Task { @MainActor in self?.updateTransferProgress(completed: completed, total: total) }
            }
            AppLog.info(.transfer, "Download (temp) complete", metadata: [
                "remotePath": file.path,
                "durationMs": String(elapsedMilliseconds(since: start)),
            ])
            return destURL
        } catch {
            self.error = "Download failed: \(AppLog.report(error, as: .transfer, message: "Download (temp) failed", metadata: ["remotePath": file.path]))"
            return nil
        }
    }

    private func downloadFile(_ file: SFTPRemoteFile, to directory: URL) async {
        guard let sftp else { return }
        let dest = directory.appendingPathComponent(file.name)
        beginTransfer(name: file.name, totalBytes: file.size)
        AppLog.info(.transfer, "Download file", metadata: [
            "remotePath": file.path,
            "localPath": dest.path,
            "size": String(file.size),
        ])
        do {
            try await sftp.download(remotePath: file.path, to: dest) { [weak self] completed, total in
                Task { @MainActor in self?.updateTransferProgress(completed: completed, total: total) }
            }
            AppLog.info(.transfer, "Download file complete", metadata: ["remotePath": file.path])
        } catch {
            self.error = "Download failed: \(AppLog.report(error, as: .transfer, message: "Download file failed", metadata: ["remotePath": file.path]))"
        }
    }

    private func downloadDirectory(_ file: SFTPRemoteFile, to localParent: URL) async {
        guard let sftp else { return }
        let localDir = localParent.appendingPathComponent(file.name)
        do {
            try FileManager.default.createDirectory(at: localDir, withIntermediateDirectories: true)
        } catch {
            self.error = "Create directory failed: \(error.localizedDescription)"
            return
        }
        AppLog.info(.transfer, "Download directory", metadata: [
            "remotePath": file.path,
            "localPath": localDir.path,
        ])
        let entries: [SFTPEntry]
        do {
            entries = try await sftp.listDirectory(file.path)
        } catch {
            self.error = "List directory failed: \(AppLog.report(error, as: .transfer, message: "listDirectory failed", metadata: ["remotePath": file.path]))"
            return
        }
        let children = entries.compactMap { SFTPRemoteFile(dir: file.path, entry: $0) }
        for child in children {
            if child.isDirectory {
                await downloadDirectory(child, to: localDir)
            } else {
                await downloadFile(child, to: localDir)
            }
            if error != nil { return }
        }
    }

    // MARK: - Helpers

    private func beginTransfer(name: String, totalBytes: UInt64) {
        activeTransfer = ActiveTransfer(name: name, completed: 0, total: Int64(totalBytes))
    }

    private func updateTransferProgress(completed: UInt64, total: UInt64) {
        guard activeTransfer != nil else { return }
        activeTransfer?.completed = Int64(completed)
        activeTransfer?.total = Int64(total)
    }

    private func endTransfer() {
        activeTransfer = nil
    }

    private func localFileSize(at url: URL) -> UInt64 {
        let attributes = try? FileManager.default.attributesOfItem(atPath: url.path)
        return (attributes?[.size] as? NSNumber)?.uint64Value ?? 0
    }

    private func makeTempDirectory() -> URL? {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        do {
            try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
            return dir
        } catch {
            self.error = "Failed to create temp dir: \(error.localizedDescription)"
            return nil
        }
    }

    private func elapsedMilliseconds(since start: DispatchTime) -> UInt64 {
        (DispatchTime.now().uptimeNanoseconds &- start.uptimeNanoseconds) / 1_000_000
    }

    private func endpointMetadata() -> [String: String] {
        [
            "host": configuration.host,
            "port": String(configuration.port),
            "username": configuration.username,
            "currentPath": currentPath,
        ]
    }
}
