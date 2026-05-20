import Testing
@testable import SSHKit

@Test func configurationKeepsConnectionInputs() {
    let configuration = SSHClientConfiguration(
        host: "example.com",
        username: "user",
        authentication: .password("secret"),
        hostKeyPolicy: .knownHostsFile("/tmp/known_hosts")
    )

    #expect(configuration.host == "example.com")
    #expect(configuration.port == 22)
    #expect(configuration.username == "user")
}
