#if os(macOS) && !targetEnvironment(macCatalyst)
    import AppKit
    @preconcurrency import Quartz

    /// Ported from vphone-cli's `VPhoneQuickLookController`. Writes the preview
    /// payload into a unique temp dir, then asks `QLPreviewPanel` to show it. The
    /// temp dir is cleaned up after Quick Look closes.
    @MainActor
    final class SFTPQuickLookController: NSResponder, QLPreviewPanelDataSource {
        private var tempDir: URL?
        private(set) var previewURL: URL?

        func open(data: Data, filename: String) {
            cleanupTempFiles()

            let dir = FileManager.default.temporaryDirectory
                .appendingPathComponent(UUID().uuidString, isDirectory: true)
            do {
                try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
            } catch {
                AppLog.error(.sftp, "QuickLook temp dir creation failed", metadata: [
                    "errorMessage": error.localizedDescription,
                ])
                return
            }
            let fileURL = dir.appendingPathComponent(filename)
            do {
                try data.write(to: fileURL)
            } catch {
                AppLog.error(.sftp, "QuickLook temp file write failed", metadata: [
                    "filename": filename,
                    "errorMessage": error.localizedDescription,
                ])
                try? FileManager.default.removeItem(at: dir)
                return
            }
            tempDir = dir
            previewURL = fileURL
            AppLog.info(.sftp, "QuickLook opening", metadata: [
                "filename": filename,
                "bytes": String(data.count),
            ])

            guard let panel = QLPreviewPanel.shared() else { return }
            panel.dataSource = self
            panel.reloadData()
            panel.makeKeyAndOrderFront(nil)
        }

        func close() {
            guard previewURL != nil else { return }
            QLPreviewPanel.shared()?.orderOut(nil)
        }

        nonisolated func numberOfPreviewItems(in _: QLPreviewPanel!) -> Int {
            MainActor.assumeIsolated { previewURL != nil ? 1 : 0 }
        }

        nonisolated func previewPanel(_: QLPreviewPanel!, previewItemAt _: Int) -> any QLPreviewItem {
            MainActor.assumeIsolated { (previewURL ?? URL(fileURLWithPath: "/dev/null")) as NSURL }
        }

        override nonisolated func acceptsPreviewPanelControl(_: QLPreviewPanel!) -> Bool {
            MainActor.assumeIsolated { previewURL != nil }
        }

        override nonisolated func beginPreviewPanelControl(_: QLPreviewPanel!) {}

        override nonisolated func endPreviewPanelControl(_: QLPreviewPanel!) {
            Task { @MainActor in cleanupTempFiles() }
        }

        private func cleanupTempFiles() {
            previewURL = nil
            if let dir = tempDir {
                try? FileManager.default.removeItem(at: dir)
                tempDir = nil
            }
        }
    }
#endif
