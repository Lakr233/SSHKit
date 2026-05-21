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

    var transferName: String?
    var transferCurrent: Int64 = 0
    var transferTotal: Int64 = 0
    var isTransferring: Bool {
        transferName != nil
    }

    // MARK: - Navigation stacks

    private var pathHistory: [String] = []
    private var forwardHistory: [String] = []

    init(configuration: SSHClientConfiguration) {
        self.configuration = configuration
    }

    // MARK: - Lifecycle

    func open() async {
        guard sftp == nil else { return }
        AppLog.info(.sftp, "Opening SFTP session", metadata: endpointMetadata())
        do {
            let conn = try await AppLog.span(.sftp, "SSHClient.connect", metadata: endpointMetadata()) {
                try await SSHClient.connect(configuration: configuration)
            }
            owningConnection = conn
            let client = try await AppLog.span(.sftp, "openSFTP", metadata: endpointMetadata()) {
                try await conn.openSFTP()
            }
            sftp = client
            isConnected = true
            AppLog.info(.sftp, "SFTP session ready", metadata: endpointMetadata())
            await refresh()
        } catch let error as SSHKitError {
            AppLog.error(.sftp, "Failed to open SFTP", metadata: endpointMetadata().merging(error.logMetadata) { _, new in new })
            self.error = error.message
            isConnected = false
        } catch {
            AppLog.error(.sftp, "Failed to open SFTP (non-SSHKit)", metadata: endpointMetadata().merging([
                "errorMessage": error.localizedDescription,
            ]) { _, new in new })
            self.error = error.localizedDescription
            isConnected = false
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
        pathHistory.append(currentPath)
        forwardHistory.removeAll()
        currentPath = normalize(path)
        selection.removeAll()
        Task { await refresh() }
    }

    func goBack() {
        guard let prev = pathHistory.popLast() else { return }
        forwardHistory.append(currentPath)
        currentPath = prev
        selection.removeAll()
        AppLog.debug(.sftp, "Navigate back", metadata: ["currentPath": currentPath])
        Task { await refresh() }
    }

    func goForward() {
        guard let next = forwardHistory.popLast() else { return }
        pathHistory.append(currentPath)
        currentPath = next
        selection.removeAll()
        AppLog.debug(.sftp, "Navigate forward", metadata: ["currentPath": currentPath])
        Task { await refresh() }
    }

    func goToBreadcrumb(_ path: String) {
        if path == currentPath { return }
        pathHistory.append(currentPath)
        forwardHistory.removeAll()
        currentPath = path
        selection.removeAll()
        AppLog.debug(.sftp, "Breadcrumb tap", metadata: ["currentPath": currentPath])
        Task { await refresh() }
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

    // MARK: - Refresh

    func refresh() async {
        guard let sftp else { return }
        isLoading = true
        error = nil
        AppLog.debug(.sftp, "Listing directory", metadata: ["path": currentPath])
        do {
            let entries = try await sftp.listDirectory(currentPath)
            var built: [SFTPRemoteFile] = []
            for entry in entries {
                guard let file = SFTPRemoteFile(dir: currentPath, entry: entry) else { continue }
                if file.isSymbolicLink {
                    let symPath = file.path
                    let resolved = await resolveSymlinkTarget(at: symPath)
                    built.append(SFTPRemoteFile(
                        dir: file.dir,
                        name: file.name,
                        type: .symbolicLink,
                        size: file.size,
                        permissions: file.permissions,
                        modified: file.modified,
                        symlinkTargetsDirectory: resolved
                    ))
                } else {
                    built.append(file)
                }
            }
            files = built
            AppLog.info(.sftp, "Directory listed", metadata: [
                "path": currentPath,
                "count": String(built.count),
            ])
        } catch let error as SSHKitError {
            AppLog.error(.sftp, "listDirectory failed",
                         metadata: ["path": currentPath].merging(error.logMetadata) { _, new in new })
            self.error = error.message
            files = []
        } catch {
            AppLog.error(.sftp, "listDirectory failed (non-SSHKit)", metadata: [
                "path": currentPath,
                "errorMessage": error.localizedDescription,
            ])
            self.error = error.localizedDescription
            files = []
        }
        isLoading = false
    }

    private func resolveSymlinkTarget(at path: String) async -> Bool {
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
            } catch let error as SSHKitError {
                AppLog.error(.sftp, "Delete failed",
                             metadata: ["path": file.path].merging(error.logMetadata) { _, new in new })
                self.error = "Delete failed for \(file.name): \(error.message)"
                return
            } catch {
                AppLog.error(.sftp, "Delete failed (non-SSHKit)", metadata: [
                    "path": file.path,
                    "errorMessage": error.localizedDescription,
                ])
                self.error = "Delete failed for \(file.name): \(error.localizedDescription)"
                return
            }
        }
        selection.removeAll()
        await refresh()
    }

    func createNewFolder(name: String) async {
        guard let sftp else { return }
        let separator = currentPath.hasSuffix("/") ? "" : "/"
        let path = "\(currentPath)\(separator)\(name)"
        AppLog.info(.sftp, "Creating folder", metadata: ["path": path])
        do {
            try await sftp.createDirectory(path)
            AppLog.info(.sftp, "Folder created", metadata: ["path": path])
            await refresh()
        } catch let error as SSHKitError {
            AppLog.error(.sftp, "createDirectory failed",
                         metadata: ["path": path].merging(error.logMetadata) { _, new in new })
            self.error = "Create folder failed: \(error.message)"
        } catch {
            AppLog.error(.sftp, "createDirectory failed (non-SSHKit)", metadata: [
                "path": path,
                "errorMessage": error.localizedDescription,
            ])
            self.error = "Create folder failed: \(error.localizedDescription)"
        }
    }

    func renameFile(_ file: SFTPRemoteFile, to newName: String) async {
        guard let sftp else { return }
        let separator = file.dir.hasSuffix("/") ? "" : "/"
        let newPath = "\(file.dir)\(separator)\(newName)"
        AppLog.info(.sftp, "Renaming", metadata: ["from": file.path, "to": newPath])
        do {
            try await sftp.rename(file.path, to: newPath)
            await refresh()
        } catch let error as SSHKitError {
            AppLog.error(.sftp, "Rename failed",
                         metadata: ["from": file.path, "to": newPath].merging(error.logMetadata) { _, new in new })
            self.error = "Rename failed: \(error.message)"
        } catch {
            AppLog.error(.sftp, "Rename failed (non-SSHKit)", metadata: [
                "from": file.path,
                "to": newPath,
                "errorMessage": error.localizedDescription,
            ])
            self.error = "Rename failed: \(error.localizedDescription)"
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
            let separator = currentPath.hasSuffix("/") ? "" : "/"
            let dest = "\(currentPath)\(separator)\(name)"

            let total: Int64 = (try? FileManager.default.attributesOfItem(atPath: scoped.url.path)[.size] as? NSNumber)?.int64Value ?? 0
            transferName = name
            transferTotal = total
            transferCurrent = 0
            AppLog.info(.transfer, "Upload start", metadata: [
                "localName": name,
                "remotePath": dest,
                "size": String(total),
            ])
            do {
                let start = DispatchTime.now()
                try await sftp.upload(localURL: scoped.url, to: dest) { [weak self] completed, totalBytes in
                    Task { @MainActor in
                        self?.transferCurrent = Int64(completed)
                        self?.transferTotal = Int64(totalBytes)
                    }
                }
                let ms = (DispatchTime.now().uptimeNanoseconds &- start.uptimeNanoseconds) / 1_000_000
                AppLog.info(.transfer, "Upload complete", metadata: [
                    "remotePath": dest,
                    "size": String(total),
                    "durationMs": String(ms),
                ])
            } catch let error as SSHKitError {
                AppLog.error(.transfer, "Upload failed",
                             metadata: ["remotePath": dest, "localName": name].merging(error.logMetadata) { _, new in new })
                uploadError = "Upload failed for \"\(name)\": \(error.message)"
                break
            } catch {
                AppLog.error(.transfer, "Upload failed (non-SSHKit)", metadata: [
                    "remotePath": dest,
                    "localName": name,
                    "errorMessage": error.localizedDescription,
                ])
                uploadError = "Upload failed for \"\(name)\": \(error.localizedDescription)"
                break
            }
        }
        transferName = nil
        transferCurrent = 0
        transferTotal = 0
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
                await downloadDirectory(remotePath: file.path, name: file.name, to: directory)
            } else {
                await downloadFile(remotePath: file.path, name: file.name, size: file.size, to: directory)
            }
            if error != nil { break }
        }
        transferName = nil
        transferCurrent = 0
        transferTotal = 0
    }

    /// Download a single file to a freshly allocated temp URL — for iOS
    /// where the destination is picked by `fileExporter` afterwards.
    func downloadToTemp(file: SFTPRemoteFile) async -> URL? {
        guard let sftp else { return nil }
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        do {
            try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        } catch {
            self.error = "Failed to create temp dir: \(error.localizedDescription)"
            return nil
        }
        let destURL = dir.appendingPathComponent(file.name)
        transferName = file.name
        transferTotal = Int64(file.size)
        transferCurrent = 0
        AppLog.info(.transfer, "Download (temp) start", metadata: [
            "remotePath": file.path,
            "tempPath": destURL.path,
            "size": String(file.size),
        ])
        do {
            let start = DispatchTime.now()
            try await sftp.download(remotePath: file.path, to: destURL) { [weak self] completed, total in
                Task { @MainActor in
                    self?.transferCurrent = Int64(completed)
                    self?.transferTotal = Int64(total)
                }
            }
            let ms = (DispatchTime.now().uptimeNanoseconds &- start.uptimeNanoseconds) / 1_000_000
            AppLog.info(.transfer, "Download (temp) complete", metadata: [
                "remotePath": file.path,
                "durationMs": String(ms),
            ])
            transferName = nil
            transferCurrent = 0
            transferTotal = 0
            return destURL
        } catch let error as SSHKitError {
            AppLog.error(.transfer, "Download (temp) failed",
                         metadata: ["remotePath": file.path].merging(error.logMetadata) { _, new in new })
            self.error = "Download failed: \(error.message)"
        } catch {
            AppLog.error(.transfer, "Download (temp) failed (non-SSHKit)", metadata: [
                "remotePath": file.path,
                "errorMessage": error.localizedDescription,
            ])
            self.error = "Download failed: \(error.localizedDescription)"
        }
        transferName = nil
        transferCurrent = 0
        transferTotal = 0
        return nil
    }

    private func downloadFile(remotePath: String, name: String, size: UInt64, to directory: URL) async {
        guard let sftp else { return }
        let dest = directory.appendingPathComponent(name)
        transferName = name
        transferTotal = Int64(size)
        transferCurrent = 0
        AppLog.info(.transfer, "Download file", metadata: [
            "remotePath": remotePath,
            "localPath": dest.path,
            "size": String(size),
        ])
        do {
            try await sftp.download(remotePath: remotePath, to: dest) { [weak self] completed, total in
                Task { @MainActor in
                    self?.transferCurrent = Int64(completed)
                    self?.transferTotal = Int64(total)
                }
            }
            AppLog.info(.transfer, "Download file complete", metadata: ["remotePath": remotePath])
        } catch let error as SSHKitError {
            AppLog.error(.transfer, "Download file failed",
                         metadata: ["remotePath": remotePath].merging(error.logMetadata) { _, new in new })
            self.error = "Download failed: \(error.message)"
        } catch {
            AppLog.error(.transfer, "Download file failed (non-SSHKit)", metadata: [
                "remotePath": remotePath,
                "errorMessage": error.localizedDescription,
            ])
            self.error = "Download failed: \(error.localizedDescription)"
        }
    }

    private func downloadDirectory(remotePath: String, name: String, to localParent: URL) async {
        guard let sftp else { return }
        let localDir = localParent.appendingPathComponent(name)
        do {
            try FileManager.default.createDirectory(at: localDir, withIntermediateDirectories: true)
        } catch {
            self.error = "Create directory failed: \(error.localizedDescription)"
            return
        }
        AppLog.info(.transfer, "Download directory", metadata: [
            "remotePath": remotePath,
            "localPath": localDir.path,
        ])
        let entries: [SFTPEntry]
        do {
            entries = try await sftp.listDirectory(remotePath)
        } catch let error as SSHKitError {
            self.error = "List directory failed: \(error.message)"
            return
        } catch {
            self.error = "List directory failed: \(error.localizedDescription)"
            return
        }
        let children = entries.compactMap { SFTPRemoteFile(dir: remotePath, entry: $0) }
        for child in children {
            if child.isDirectory {
                await downloadDirectory(remotePath: child.path, name: child.name, to: localDir)
            } else {
                await downloadFile(remotePath: child.path, name: child.name, size: child.size, to: localDir)
            }
            if error != nil { return }
        }
    }

    // MARK: - Helpers

    private func normalize(_ path: String) -> String {
        if path.isEmpty { return "/" }
        return path
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
