import Foundation

final class SecurityScopedURL {
    let url: URL
    private let didStart: Bool

    init(_ url: URL) {
        self.url = url
        didStart = url.startAccessingSecurityScopedResource()
    }

    deinit {
        if didStart {
            url.stopAccessingSecurityScopedResource()
        }
    }
}
