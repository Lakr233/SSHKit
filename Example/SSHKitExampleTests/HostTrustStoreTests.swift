import Foundation
import SSHKit
@testable import SSHKitExample
import Testing

@Suite("HostTrustStoreFactory")
struct HostTrustStoreFactoryTests {
    @Test
    func `Default keychain service matches the documented value`() {
        #expect(HostTrustStoreFactory.keychainServiceName == "wiki.qaq.sshkit")
        #expect(SSHKeychainHostTrustStore.defaultService == "wiki.qaq.sshkit")
    }

    @Test
    func `Memory trust store round trip`() throws {
        let store = SSHMemoryHostTrustStore()
        let fp = SSHHostKeyFingerprint("SHA256:test")
        try store.saveFingerprint(fp, host: "example.com", port: 22)
        #expect(try store.fingerprint(host: "example.com", port: 22) == fp)
        try store.removeFingerprint(host: "example.com", port: 22)
        #expect(try store.fingerprint(host: "example.com", port: 22) == nil)
    }
}
