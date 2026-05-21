import Foundation
import SSHKit

@MainActor
@Observable
final class FileTransferCoordinator {
    struct Progress: Identifiable {
        let id = UUID()
        var name: String
        var completed: UInt64
        var total: UInt64
        var direction: Direction

        enum Direction { case upload, download }

        var fraction: Double {
            total == 0 ? 0 : Double(completed) / Double(total)
        }
    }

    private(set) var transfers: [Progress] = []
    var lastError: SSHKitError?

    /// Upload a security-scoped local URL to `remotePath`. The URL is retained
    /// for the entire transfer; no `defer`/sub-function ownership.
    func upload(
        sftp: SFTPClient,
        localURL: URL,
        remotePath: String,
    ) async {
        let scoped = SecurityScopedURL(localURL)
        defer { _ = scoped } // explicit keep-alive — ARC retains via the captured variable
        let name = localURL.lastPathComponent
        var entry = Progress(name: name, completed: 0, total: 0, direction: .upload)
        transfers.append(entry)
        let id = entry.id
        do {
            try await sftp.upload(localURL: scoped.url, to: remotePath) { [weak self] completed, total in
                Task { @MainActor in
                    self?.updateTransfer(id: id, completed: completed, total: total)
                }
            }
            removeTransfer(id: id)
        } catch let error as SSHKitError {
            lastError = error
            removeTransfer(id: id)
        } catch {
            lastError = SSHKitError(
                code: SSHKitErrorCode.unavailable.rawValue,
                message: String(describing: error),
            )
            removeTransfer(id: id)
        }
        _ = entry
    }

    /// Download `remotePath` to a temp file, then return its URL so the view
    /// can present `.fileExporter` for the user to save it persistently.
    func downloadToTemp(
        sftp: SFTPClient,
        remotePath: String,
    ) async -> URL? {
        let tempURL = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString)
            .appendingPathComponent((remotePath as NSString).lastPathComponent)
        try? FileManager.default.createDirectory(
            at: tempURL.deletingLastPathComponent(),
            withIntermediateDirectories: true,
        )
        let name = (remotePath as NSString).lastPathComponent
        let entry = Progress(name: name, completed: 0, total: 0, direction: .download)
        transfers.append(entry)
        let id = entry.id
        do {
            try await sftp.download(remotePath: remotePath, to: tempURL) { [weak self] completed, total in
                Task { @MainActor in
                    self?.updateTransfer(id: id, completed: completed, total: total)
                }
            }
            removeTransfer(id: id)
            return tempURL
        } catch let error as SSHKitError {
            lastError = error
            removeTransfer(id: id)
            return nil
        } catch {
            lastError = SSHKitError(
                code: SSHKitErrorCode.unavailable.rawValue,
                message: String(describing: error),
            )
            removeTransfer(id: id)
            return nil
        }
    }

    private func updateTransfer(id: UUID, completed: UInt64, total: UInt64) {
        guard let index = transfers.firstIndex(where: { $0.id == id }) else { return }
        transfers[index].completed = completed
        transfers[index].total = total
    }

    private func removeTransfer(id: UUID) {
        transfers.removeAll { $0.id == id }
    }
}
