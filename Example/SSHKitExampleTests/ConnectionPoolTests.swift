import Foundation
import SSHKit
@testable import SSHKitExample
import Testing

@Suite("ConnectionPool surface")
struct ConnectionPoolTests {
    @Test
    func `Pool holds the configuration it was constructed with`() {
        let config = SSHClientConfiguration(
            host: "127.0.0.1",
            port: 22,
            username: "user",
            authentication: .password("hunter2"),
            hostKeyPolicy: .insecureAcceptAnyHostKey,
        )
        let pool = ConnectionPool(configuration: config)
        #expect(pool.configuration.host == "127.0.0.1")
        #expect(pool.configuration.port == 22)
        #expect(pool.configuration.username == "user")
    }
}
