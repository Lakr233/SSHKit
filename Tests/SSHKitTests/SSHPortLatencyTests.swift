import Foundation
@testable import SSHKit
import Testing

@Test func `latency report records connect and service timing`() {
    let report = SSHPortLatencyReport(
        host: "example.com",
        port: 22,
        route: .direct,
        connectDuration: 0.12,
        sshServiceDuration: 0.03,
        totalDuration: 0.18,
    )

    #expect(report.host == "example.com")
    #expect(report.port == 22)
    #expect(report.route == .direct)
    #expect(report.connectDuration == 0.12)
    #expect(report.sshServiceDuration == 0.03)
    #expect(report.totalDuration == 0.18)
}

@Test func `latency route describes direct configuration`() {
    let configuration = SSHClientConfiguration(
        host: "target.example.com",
        username: "user",
        authentication: .password("secret"),
        hostKeyPolicy: .knownHostsFile("/tmp/known_hosts"),
    )

    #expect(SSHPortLatencyRoute(proxyRoute: configuration.proxyRoute) == .direct)
}

@Test func `latency route describes proxy configuration`() {
    let socksEndpoint = SSHProxyEndpoint(host: "proxy.example.com", port: 1080)
    let httpEndpoint = SSHProxyEndpoint(host: "proxy.example.com", port: 8080)

    #expect(SSHPortLatencyRoute(proxyRoute: .socks5(socksEndpoint)) == .socks5(host: "proxy.example.com", port: 1080))
    #expect(SSHPortLatencyRoute(proxyRoute: .httpConnect(httpEndpoint)) == .httpConnect(host: "proxy.example.com", port: 8080))
}

@Test func `latency route describes ProxyJump configuration`() {
    let jumpHost = SSHJumpHost(
        host: "jump.example.com",
        port: 2222,
        username: "jump-user",
        authentication: .password("secret"),
        hostKeyPolicy: .knownHostsFile("/tmp/jump_known_hosts"),
    )

    #expect(SSHPortLatencyRoute(proxyRoute: .proxyJump(jumpHost)) == .proxyJump(host: "jump.example.com", port: 2222))
}
