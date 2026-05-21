import SwiftUI
import UniformTypeIdentifiers

#if os(macOS) && !targetEnvironment(macCatalyst)
    import AppKit
#endif

/// Cross-platform "pick one file to upload" helper.
/// - iOS / Mac Catalyst: SwiftUI `fileImporter` with file-only allowed types.
/// - macOS native: `NSOpenPanel` configured to disallow directory selection.
@MainActor
enum FilePicker {
    #if os(macOS) && !targetEnvironment(macCatalyst)
        static func pickFileToUpload() -> URL? {
            let panel = NSOpenPanel()
            panel.canChooseFiles = true
            panel.canChooseDirectories = false
            panel.allowsMultipleSelection = false
            panel.resolvesAliases = true
            guard panel.runModal() == .OK else { return nil }
            return panel.url
        }
    #endif
}

/// SwiftUI modifier wrapper for iOS / Catalyst file import — the system will
/// hand back security-scoped URLs which the caller must retain via
/// SecurityScopedURL for the duration of the transfer.
struct UploadFileImporter: ViewModifier {
    @Binding var isPresented: Bool
    let onResult: (Result<URL, Error>) -> Void

    func body(content: Content) -> some View {
        content.fileImporter(
            isPresented: $isPresented,
            allowedContentTypes: [.data],
            allowsMultipleSelection: false
        ) { result in
            switch result {
            case let .success(urls):
                guard let url = urls.first else { return }
                onResult(.success(url))
            case let .failure(error):
                onResult(.failure(error))
            }
        }
    }
}

extension View {
    func uploadFileImporter(
        isPresented: Binding<Bool>,
        onResult: @escaping (Result<URL, Error>) -> Void
    ) -> some View {
        modifier(UploadFileImporter(isPresented: isPresented, onResult: onResult))
    }
}
