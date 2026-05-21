import Foundation
@testable import SSHKit
import SSHKitObjC
import Testing

@Test func `configuration keeps connection inputs`() {
    let configuration = SSHClientConfiguration(
        host: "example.com",
        username: "user",
        authentication: .password("secret"),
        hostKeyPolicy: .knownHostsFile("/tmp/known_hosts"),
    )

    #expect(configuration.host == "example.com")
    #expect(configuration.port == 22)
    #expect(configuration.username == "user")
}

@Test func `command event stream finishes after closed event`() async {
    let sink = SSHCommandEventSink()
    sink.yield(.standardOutput(Data("one".utf8)))
    sink.yield(.closed(0))

    var events: [SSHCommandEvent] = []
    for await event in sink.stream {
        events.append(event)
    }

    #expect(events == [.standardOutput(Data("one".utf8)), .closed(0)])
}

@Test func `SFTP entry keeps filename`() {
    let attributes = SFTPAttributes(size: 12, permissions: 0o644, uid: 501, gid: 20, type: 1)
    let entry = SFTPEntry(filename: "upload.txt", attributes: attributes)

    #expect(entry.filename == "upload.txt")
    #expect(entry.attributes == attributes)
}

@Test func `keyboard interactive bridge forwards prompts`() throws {
    let configuration = SSHClientConfiguration(
        host: "example.com",
        username: "user",
        authentication: .keyboardInteractive { name, instruction, prompts in
            #expect(name == "login")
            #expect(instruction == "answer prompts")
            #expect(prompts == [SSHKeyboardInteractivePrompt(prompt: "Password:", echo: false)])
            return ["secret"]
        },
        hostKeyPolicy: .knownHostsFile("/tmp/known_hosts"),
    ).bridgeConfiguration

    let responder = try #require(configuration.keyboardInteractiveResponder)
    let answers = responder("login", "answer prompts", [
        SSHKitKeyboardInteractivePrompt(prompt: "Password:", echo: false),
    ])

    #expect(configuration.authenticationKind == .keyboardInteractive)
    #expect(answers == ["secret"])
}

@Test func `agent authentication bridges to Objective C configuration`() {
    let configuration = SSHClientConfiguration(
        host: "example.com",
        username: "user",
        authentication: .agent(SSHAgentConfiguration(socketPath: "/tmp/agent.sock")),
        hostKeyPolicy: .knownHostsFile("/tmp/known_hosts"),
    ).bridgeConfiguration

    #expect(configuration.authenticationKind == .agent)
    #expect(configuration.identityAgentPath == "/tmp/agent.sock")
}

@Test func `host key fingerprint normalizes SHA256 prefix`() {
    #expect(SSHHostKeyFingerprint("abc123").rawValue == "SHA256:abc123")
    #expect(SSHHostKeyFingerprint("SHA256:abc123").rawValue == "SHA256:abc123")
}

@Test func `configuration bridge maps pinned fingerprint policy`() {
    let configuration = SSHClientConfiguration(
        host: "example.com",
        username: "user",
        authentication: .password("secret"),
        hostKeyPolicy: .pinnedFingerprint(SSHHostKeyFingerprint("abc123")),
    ).bridgeConfiguration

    #expect(configuration.hostKeyPolicyKind == .pinnedFingerprint)
    #expect(configuration.pinnedHostKeySHA256Fingerprint == "SHA256:abc123")
}

@Test func `configuration bridge maps memory trust store policy`() throws {
    let store = SSHMemoryHostTrustStore()
    try store.saveFingerprint(SSHHostKeyFingerprint("abc123"), host: "example.com", port: 2222)

    let configuration = SSHClientConfiguration(
        host: "example.com",
        port: 2222,
        username: "user",
        authentication: .password("secret"),
        hostKeyPolicy: .trustStore(store),
    ).bridgeConfiguration

    #expect(configuration.hostKeyPolicyKind == .trustedFingerprint)
    #expect(configuration.trustedHostKeySHA256Fingerprint == "SHA256:abc123")
}

@Test func `configuration bridge surfaces missing trust store entry`() {
    let configuration = SSHClientConfiguration(
        host: "example.com",
        port: 2222,
        username: "user",
        authentication: .password("secret"),
        hostKeyPolicy: .trustStore(SSHMemoryHostTrustStore()),
    ).bridgeConfiguration

    #expect(configuration.hostKeyPolicyKind == .trustedFingerprint)
    #expect(configuration.trustedHostKeySHA256Fingerprint == nil)
}

@Test func `authentication discovery maps Objective C methods`() {
    let result = SSHKitAuthenticationDiscoveryResult(
        methods: [
            NSNumber(value: SSHKitAuthenticationMethod.password.rawValue),
            NSNumber(value: SSHKitAuthenticationMethod.publicKey.rawValue),
            NSNumber(value: SSHKitAuthenticationMethod.keyboardInteractive.rawValue),
        ],
        issueBanner: "notice",
        serverBanner: "SSH-2.0-fixture",
    )

    let discovery = SSHAuthenticationDiscoveryResult(result)

    #expect(discovery.methods == [.password, .publicKey, .keyboardInteractive])
    #expect(discovery.issueBanner == "notice")
    #expect(discovery.serverBanner == "SSH-2.0-fixture")
}

@Test func `log event redacts sensitive metadata`() {
    let event = SSHLogEvent(
        level: .info,
        phase: "auth",
        message: "auth selected",
        metadata: [
            "username": "user",
            "password": "secret",
            "privateKeyPath": "/tmp/id_ed25519",
            "tokenValue": "abc",
        ],
    ).redacted

    #expect(event.metadata["username"] == "user")
    #expect(event.metadata["password"] == "<redacted>")
    #expect(event.metadata["privateKeyPath"] == "<redacted>")
    #expect(event.metadata["tokenValue"] == "<redacted>")
}

@Test func `log recorder bounds and redacts events`() {
    let recorder = SSHLogRecorder(capacity: 2)

    recorder.record(SSHLogEvent(level: .info, phase: "connect", message: "first"))
    recorder.record(SSHLogEvent(level: .info, phase: "auth", message: "second", metadata: ["password": "secret"]))
    recorder.record(SSHLogEvent(level: .info, phase: "command", message: "third"))

    let events = recorder.events
    #expect(events.map(\.message) == ["second", "third"])
    #expect(events[0].metadata["password"] == "<redacted>")
}

@Test func `configuration bridge forwards redacted log events`() throws {
    final class Box: @unchecked Sendable {
        var events: [SSHLogEvent] = []
    }
    let box = Box()
    let configuration = SSHClientConfiguration(
        host: "example.com",
        username: "user",
        authentication: .password("secret"),
        hostKeyPolicy: .knownHostsFile("/tmp/known_hosts"),
        logHandler: { event in
            box.events.append(event)
        },
    ).bridgeConfiguration

    let handler = try #require(configuration.logHandler)
    handler(SSHKitLogEvent(
        level: .info,
        phase: "auth",
        message: "auth selected",
        metadata: ["password": "secret"],
    ))

    #expect(box.events.count == 1)
    #expect(box.events[0].level == .info)
    #expect(box.events[0].metadata["password"] == "<redacted>")
}

@Test func `configuration bridge maps SOCKS5 proxy route`() {
    let configuration = SSHClientConfiguration(
        host: "target.example.com",
        username: "user",
        authentication: .password("secret"),
        hostKeyPolicy: .knownHostsFile("/tmp/known_hosts"),
        proxyRoute: .socks5(SSHProxyEndpoint(host: "proxy.example.com", port: 1080, username: "proxy-user", password: "proxy-pass")),
    ).bridgeConfiguration

    #expect(configuration.proxyRouteKind == .SOCKS5)
    #expect(configuration.proxyHost == "proxy.example.com")
    #expect(configuration.proxyPort == 1080)
    #expect(configuration.proxyUsername == "proxy-user")
    #expect(configuration.proxyPassword == "proxy-pass")
}

@Test func `configuration bridge maps HTTP CONNECT proxy route`() {
    let configuration = SSHClientConfiguration(
        host: "target.example.com",
        username: "user",
        authentication: .password("secret"),
        hostKeyPolicy: .knownHostsFile("/tmp/known_hosts"),
        proxyRoute: .httpConnect(SSHProxyEndpoint(host: "proxy.example.com", port: 8080)),
    ).bridgeConfiguration

    #expect(configuration.proxyRouteKind == .httpConnect)
    #expect(configuration.proxyHost == "proxy.example.com")
    #expect(configuration.proxyPort == 8080)
}

@Test func `configuration bridge maps ProxyJump route`() throws {
    let configuration = SSHClientConfiguration(
        host: "target.example.com",
        username: "user",
        authentication: .password("secret"),
        hostKeyPolicy: .knownHostsFile("/tmp/known_hosts"),
        proxyRoute: .proxyJump(SSHJumpHost(
            host: "jump.example.com",
            port: 2222,
            username: "jump-user",
            authentication: .privateKeyFile(path: "/tmp/jump_key"),
            hostKeyPolicy: .knownHostsFile("/tmp/jump_known_hosts"),
        )),
    ).bridgeConfiguration

    #expect(configuration.proxyRouteKind == .proxyJump)
    let jump = try #require(configuration.proxyJump)
    #expect(jump.host == "jump.example.com")
    #expect(jump.port == 2222)
    #expect(jump.username == "jump-user")
    #expect(jump.authenticationKind == .privateKeyFile)
    #expect(jump.privateKeyPath == "/tmp/jump_key")
    #expect(jump.knownHostsPath == "/tmp/jump_known_hosts")
}

@Test func `configuration bridge maps algorithm profile`() {
    let configuration = SSHClientConfiguration(
        host: "target.example.com",
        username: "user",
        authentication: .password("secret"),
        hostKeyPolicy: .knownHostsFile("/tmp/known_hosts"),
        algorithmProfile: .legacyRSA,
    ).bridgeConfiguration

    #expect(configuration.hostKeyAlgorithms == "+ssh-rsa")
    #expect(configuration.publicKeyAcceptedAlgorithms == "+ssh-rsa")
    #expect(configuration.minimumRSAKeySize == 1024)
}

@Test func `algorithm inspection exposes effective profile`() throws {
    let snapshot = try SSHAlgorithmProfile.modern.inspectEffectiveAlgorithms()

    #expect(snapshot.keyExchangeAlgorithms.isEmpty == false)
    #expect(snapshot.hostKeyAlgorithms.isEmpty == false)
    #expect(snapshot.publicKeyAcceptedAlgorithms.isEmpty == false)
    #expect(snapshot.publicKeyAcceptedAlgorithms == snapshot.hostKeyAlgorithms)
    #expect(snapshot.ciphersClientToServer.isEmpty == false)
    #expect(snapshot.minimumRSAKeySize == 3072)
}

@Test func `custom algorithm profile changes inspected ciphers`() throws {
    let modernSnapshot = try SSHAlgorithmProfile.modern.inspectEffectiveAlgorithms()
    let firstModernCipher = try #require(modernSnapshot.ciphersClientToServer.split(separator: ",").first)
    let customCipher = String(firstModernCipher)
    let customSnapshot = try SSHAlgorithmProfile(ciphersClientToServer: customCipher).inspectEffectiveAlgorithms()

    #expect(customSnapshot.ciphersClientToServer == customCipher)
}

@Test func `legacy RSA opt in changes inspected algorithms`() throws {
    let snapshot = try SSHAlgorithmProfile.legacyRSA.inspectEffectiveAlgorithms()

    #expect(snapshot.hostKeyAlgorithms.contains("ssh-rsa"))
    #expect(snapshot.publicKeyAcceptedAlgorithms.contains("ssh-rsa"))
    #expect(snapshot.minimumRSAKeySize == 1024)
}

@Test func `OpenSSH key generation exports authorized key`() throws {
    let keyPair = try SSHKeyGenerator.generateOpenSSHKeyPair(type: .ed25519, comment: "sshkit-test")

    #expect(keyPair.privateKeyOpenSSH.contains("BEGIN OPENSSH PRIVATE KEY"))
    #expect(keyPair.authorizedKey.hasPrefix("ssh-ed25519 "))
    #expect(keyPair.authorizedKey.hasSuffix(" sshkit-test"))
    #expect(keyPair.publicKeyType == "ssh-ed25519")
}

@Test func `Keychain credential store saves and loads app credentials`() throws {
    let store = SSHKeychainCredentialStore(service: "wiki.qaq.sshkit.tests.\(UUID().uuidString)")
    let account = "fixture@example.com"
    let credential = SSHPrivateKeyCredential(privateKeyOpenSSH: "-----BEGIN OPENSSH PRIVATE KEY-----\ntest\n-----END OPENSSH PRIVATE KEY-----")

    try store.savePassword("secret", account: account)
    try store.savePrivateKey(credential, account: account)

    #expect(try store.password(account: account) == "secret")
    #expect(try store.privateKey(account: account) == credential)
}

@Test func `Keychain host trust store saves and loads fingerprints`() throws {
    let store = SSHKeychainHostTrustStore(service: "wiki.qaq.sshkit.hostTrust.tests.\(UUID().uuidString)")
    let fingerprint = SSHHostKeyFingerprint("abc123")

    try store.saveFingerprint(fingerprint, host: "Example.COM", port: 2222)

    #expect(try store.fingerprint(host: "example.com", port: 2222) == fingerprint)
    try store.removeFingerprint(host: "example.com", port: 2222)
    #expect(try store.fingerprint(host: "example.com", port: 2222) == nil)
}

@Test func `SCP validator rejects unsafe paths and filenames`() {
    expectThrows {
        try SCPPathValidator.validateRemotePath("")
    }
    expectThrows {
        try SCPPathValidator.validateRemotePath("-option")
    }
    expectThrows {
        try SCPPathValidator.validateRemotePath("bad\npath")
    }
    expectThrows {
        try SCPPathValidator.validateFilename("../secret")
    }
    expectThrows {
        try SCPPathValidator.validateFilename("bad\rname")
    }
    expectThrows {
        try SCPPathValidator.validatePermissions(0o10000)
    }
    expectThrows {
        _ = try SCPPathValidator.validatedByteCount(UInt64(Int.max) + 1)
    }
}

@Test func `SCP upload size guard rejects large local sources before transfer`() throws {
    let directory = FileManager.default.temporaryDirectory
        .appendingPathComponent("SSHKitSCPUnitTests")
        .appendingPathComponent(UUID().uuidString)
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
    let url = directory.appendingPathComponent("source.txt")
    try Data(repeating: 0x61, count: 4).write(to: url)

    expectThrows {
        try SCPPathValidator.validateUploadSize(localURL: url, maximumSize: 3)
    }
    expectThrows {
        try SCPPathValidator.validateUploadByteCount(5, maximumSize: 4)
    }
    try SCPPathValidator.validateUploadSize(localURL: url, maximumSize: 4)
    try SCPPathValidator.validateUploadByteCount(4, maximumSize: 4)
}

@Test func `SCP shell quoting preserves single quotes`() {
    #expect(SCPPathValidator.shellQuoted("/tmp/it's-here") == "'/tmp/it'\\''s-here'")
}

@Test func `diagnostic report includes connection context and redacts metadata`() {
    let configuration = SSHClientConfiguration(
        host: "example.com",
        port: 2222,
        username: "user",
        authentication: .privateKeyFile(path: "/tmp/id_ed25519", passphrase: "secret"),
        hostKeyPolicy: .knownHostsFile("/tmp/known_hosts"),
    )

    let report = configuration.diagnosticReport(
        phase: "auth",
        metadata: ["privateKeyPassphrase": "secret", "attempt": "1"],
        recentEvents: [
            SSHLogEvent(level: .info, phase: "connect", message: "connected", metadata: ["password": "secret"]),
        ],
    )

    #expect(report.host == "example.com")
    #expect(report.port == 2222)
    #expect(report.username == "user")
    #expect(report.authentication == "privateKeyFile")
    #expect(report.hostKeyPolicy == "knownHostsFile")
    #expect(report.metadata["privateKeyPassphrase"] == "<redacted>")
    #expect(report.metadata["attempt"] == "1")
    #expect(report.recentEvents[0].metadata["password"] == "<redacted>")
}

private func expectThrows(_ operation: () throws -> Void) {
    do {
        try operation()
        #expect(Bool(false))
    } catch {
        #expect(Bool(true))
    }
}
