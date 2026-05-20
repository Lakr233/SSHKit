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
