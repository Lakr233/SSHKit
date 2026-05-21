import Foundation
import SSHKit

extension SFTPAttributes {
    /// libssh sftp.h:
    ///   SSH_FILEXFER_TYPE_REGULAR   = 1
    ///   SSH_FILEXFER_TYPE_DIRECTORY = 2
    ///   SSH_FILEXFER_TYPE_SYMLINK   = 3
    ///   SSH_FILEXFER_TYPE_SPECIAL   = 4
    ///   SSH_FILEXFER_TYPE_UNKNOWN   = 5
    var isRegular: Bool {
        type == 1
    }

    var isDirectory: Bool {
        type == 2
    }

    var isSymlink: Bool {
        type == 3
    }
}
