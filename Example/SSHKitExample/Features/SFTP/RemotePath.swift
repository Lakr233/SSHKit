import Foundation

extension String {
    /// Append a POSIX path component to the receiver, normalizing the
    /// boundary slash so callers do not repeat the `hasSuffix("/")` ternary at
    /// every join site.
    func joiningRemotePath(_ component: String) -> String {
        let separator = hasSuffix("/") ? "" : "/"
        return self + separator + component
    }
}
