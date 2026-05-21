import Foundation
import SSHKit
@testable import SSHKitExample
import Testing

@Suite("SFTPAttributes helpers")
struct SFTPAttributesHelpersTests {
    @Test
    func `Type 1 is regular`() {
        let attrs = SFTPAttributes(size: 0, permissions: 0, uid: 0, gid: 0, type: 1, accessedAt: nil, modifiedAt: nil)
        #expect(attrs.isRegular == true)
        #expect(attrs.isDirectory == false)
        #expect(attrs.isSymlink == false)
    }

    @Test
    func `Type 2 is directory`() {
        let attrs = SFTPAttributes(size: 0, permissions: 0, uid: 0, gid: 0, type: 2, accessedAt: nil, modifiedAt: nil)
        #expect(attrs.isDirectory == true)
    }

    @Test
    func `Type 3 is symlink`() {
        let attrs = SFTPAttributes(size: 0, permissions: 0, uid: 0, gid: 0, type: 3, accessedAt: nil, modifiedAt: nil)
        #expect(attrs.isSymlink == true)
    }
}
