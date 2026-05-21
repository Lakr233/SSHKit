import Foundation
import SSHKit

/// A row in the SFTP browser. Ported from vphone-cli's `VPhoneRemoteFile`, but
/// hydrated from `SFTPEntry` / `SFTPAttributes` and POSIX permission bits.
struct SFTPRemoteFile: Identifiable, Hashable {
    let dir: String
    let name: String
    let type: FileType
    let size: UInt64
    let permissions: String
    let modified: Date
    let symlinkTargetsDirectory: Bool

    var id: String {
        path
    }

    var path: String {
        dir.joiningRemotePath(name)
    }

    var isDirectory: Bool {
        type == .directory
    }

    var isSymbolicLink: Bool {
        type == .symbolicLink
    }

    var isDirectoryLike: Bool {
        isDirectory || symlinkTargetsDirectory
    }

    var displaySize: String {
        if isDirectory || isSymbolicLink { return "-" }
        return ByteCountFormatter.string(fromByteCount: Int64(size), countStyle: .file)
    }

    var displayDate: String {
        Self.dateFormatter.string(from: modified)
    }

    var icon: String {
        switch type {
        case .directory: "folder.fill"
        case .symbolicLink: "link"
        case .file: Self.fileIcon(for: name)
        }
    }

    enum FileType: String, Hashable {
        case file
        case directory
        case symbolicLink
    }

    private static let dateFormatter: DateFormatter = {
        let f = DateFormatter()
        f.dateStyle = .short
        f.timeStyle = .short
        return f
    }()

    private static func fileIcon(for name: String) -> String {
        let ext = (name as NSString).pathExtension.lowercased()
        return switch ext {
        case "png", "jpg", "jpeg", "gif", "bmp", "tiff", "heic": "photo"
        case "mov", "mp4", "m4v": "film"
        case "mp3", "wav", "flac", "m4a": "music.note"
        case "txt", "md", "log": "doc.text"
        case "plist", "json", "xml", "yaml", "yml", "toml": "doc.badge.gearshape"
        case "zip", "tar", "gz", "tgz", "bz2", "xz", "7z": "doc.zipper"
        case "dylib", "framework", "so", "a": "shippingbox"
        case "app": "app.dashed"
        case "sh", "bash", "zsh", "swift", "py", "rb", "js", "ts", "go", "c", "h", "cpp", "hpp", "m", "mm": "chevron.left.forwardslash.chevron.right"
        default: "doc"
        }
    }
}

extension SFTPRemoteFile {
    /// Return a copy with the symlink-target-is-directory flag overridden,
    /// once the model has resolved the link target.
    func withSymlinkTargetsDirectory(_ value: Bool) -> SFTPRemoteFile {
        SFTPRemoteFile(
            dir: dir,
            name: name,
            type: type,
            size: size,
            permissions: permissions,
            modified: modified,
            symlinkTargetsDirectory: value
        )
    }

    /// Hydrate from an SFTPEntry. The symlink-target-is-directory flag is the
    /// caller's job (we don't follow links in the listing path itself).
    init?(dir: String, entry: SFTPEntry, symlinkTargetsDirectory: Bool = false) {
        let name = entry.filename
        guard name != ".", name != ".." else { return nil }
        let attrs = entry.attributes

        let type: FileType = if let attrs {
            if attrs.isDirectory {
                .directory
            } else if attrs.isSymlink {
                .symbolicLink
            } else {
                .file
            }
        } else {
            .file
        }

        self.dir = dir
        self.name = name
        self.type = type
        size = attrs?.size ?? 0
        permissions = Self.permissionString(mode: attrs?.permissions ?? 0, type: type)
        modified = attrs?.modifiedAt ?? Date(timeIntervalSince1970: 0)
        self.symlinkTargetsDirectory = symlinkTargetsDirectory
    }

    /// Convert POSIX mode bits to the familiar `drwxr-xr-x` string.
    static func permissionString(mode: UInt32, type: FileType) -> String {
        var output = ""
        switch type {
        case .directory: output.append("d")
        case .symbolicLink: output.append("l")
        case .file: output.append("-")
        }
        let bits: [(UInt32, String, String, String)] = [
            (0o400, "r", "", ""),
            (0o200, "w", "", ""),
            (0o100, "x", "", ""),
            (0o040, "r", "", ""),
            (0o020, "w", "", ""),
            (0o010, "x", "", ""),
            (0o004, "r", "", ""),
            (0o002, "w", "", ""),
            (0o001, "x", "", ""),
        ]
        for (mask, set, _, _) in bits {
            output.append((mode & mask) != 0 ? set : "-")
        }
        return output
    }
}
