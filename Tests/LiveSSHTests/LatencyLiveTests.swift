import SSHKit
import XCTest

final class LatencyLiveTests: LiveSSHTestCase {
    func testMeasuresDirectFixtureSSHServiceLatency() async throws {
        try requireLiveTestsEnabled()

        let fixture = try AlpineSSHFixture()
        let configuration = try privateKeyConfiguration(fixture: fixture)
        let report = try await SSHPortLatencyProbe.measure(
            configuration: configuration,
            serviceCommand: "printf 'latency-ok\\n'",
        )

        XCTAssertEqual(report.host, fixture.host)
        XCTAssertEqual(report.port, fixture.port)
        XCTAssertEqual(report.route, .direct)
        XCTAssertGreaterThanOrEqual(report.connectDuration, 0)
        XCTAssertGreaterThanOrEqual(report.sshServiceDuration, 0)
        XCTAssertGreaterThanOrEqual(report.totalDuration, report.connectDuration + report.sshServiceDuration)
    }

    func testMeasuresSOCKS5ProxyFixtureSSHServiceLatency() async throws {
        try requireLiveTestsEnabled()

        let fixture = try AlpineSSHFixture()
        let proxy = try LoopbackProxyServer(mode: .socks5)
        defer {
            proxy.close()
        }

        let configuration = try privateKeyConfiguration(
            fixture: fixture,
            proxyRoute: .socks5(SSHProxyEndpoint(host: "127.0.0.1", port: proxy.port)),
        )
        let report = try await SSHPortLatencyProbe.measure(configuration: configuration)

        XCTAssertEqual(report.route, .socks5(host: "127.0.0.1", port: proxy.port))
        XCTAssertGreaterThanOrEqual(report.connectDuration, 0)
        XCTAssertGreaterThanOrEqual(report.sshServiceDuration, 0)
    }

    func testMeasuresHTTPConnectProxyFixtureSSHServiceLatency() async throws {
        try requireLiveTestsEnabled()

        let fixture = try AlpineSSHFixture()
        let proxy = try LoopbackProxyServer(mode: .httpConnect)
        defer {
            proxy.close()
        }

        let configuration = try privateKeyConfiguration(
            fixture: fixture,
            proxyRoute: .httpConnect(SSHProxyEndpoint(host: "127.0.0.1", port: proxy.port)),
        )
        let report = try await SSHPortLatencyProbe.measure(configuration: configuration)

        XCTAssertEqual(report.route, .httpConnect(host: "127.0.0.1", port: proxy.port))
        XCTAssertGreaterThanOrEqual(report.connectDuration, 0)
        XCTAssertGreaterThanOrEqual(report.sshServiceDuration, 0)
    }

    func testMeasuresProxyJumpFixtureSSHServiceLatency() async throws {
        try requireLiveTestsEnabled()

        let fixture = try AlpineSSHFixture()
        let privateKeyPath = try makePrivateKeyFile(fixture: fixture)
        let knownHostsPath = try makeKnownHostsFile(fixture: fixture)
        let jumpHost = SSHJumpHost(
            host: fixture.host,
            port: fixture.port,
            username: fixture.username,
            authentication: .privateKeyFile(path: privateKeyPath),
            hostKeyPolicy: .knownHostsFile(knownHostsPath),
        )
        let configuration = SSHClientConfiguration(
            host: "127.0.0.1",
            port: fixture.port,
            username: fixture.username,
            authentication: .privateKeyFile(path: privateKeyPath),
            hostKeyPolicy: .insecureAcceptAnyHostKey,
            timeout: 10,
            proxyRoute: .proxyJump(jumpHost),
        )
        let report = try await SSHPortLatencyProbe.measure(configuration: configuration)

        XCTAssertEqual(report.route, .proxyJump(host: fixture.host, port: fixture.port))
        XCTAssertGreaterThanOrEqual(report.connectDuration, 0)
        XCTAssertGreaterThanOrEqual(report.sshServiceDuration, 0)
    }

    private func privateKeyConfiguration(
        fixture: AlpineSSHFixture,
        proxyRoute: SSHProxyRoute? = nil,
    ) throws -> SSHClientConfiguration {
        try SSHClientConfiguration(
            host: fixture.host,
            port: fixture.port,
            username: fixture.username,
            authentication: .privateKeyFile(path: makePrivateKeyFile(fixture: fixture)),
            hostKeyPolicy: .knownHostsFile(makeKnownHostsFile(fixture: fixture)),
            timeout: 10,
            proxyRoute: proxyRoute,
        )
    }
}
