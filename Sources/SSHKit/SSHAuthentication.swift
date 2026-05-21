import Foundation

public struct SSHKeyboardInteractivePrompt: Equatable, Sendable {
    public var prompt: String
    public var echo: Bool

    public init(prompt: String, echo: Bool) {
        self.prompt = prompt
        self.echo = echo
    }
}

public typealias SSHKeyboardInteractiveResponseProvider = @Sendable (_ name: String, _ instruction: String, _ prompts: [SSHKeyboardInteractivePrompt]) -> [String]

public struct SSHAgentConfiguration: Equatable, Sendable {
    public var socketPath: String?

    public init(socketPath: String? = nil) {
        self.socketPath = socketPath
    }
}

public enum SSHAuthentication: Sendable {
    case password(String)
    case privateKeyFile(path: String, passphrase: String? = nil)
    case keyboardInteractive(SSHKeyboardInteractiveResponseProvider)
    case agent(SSHAgentConfiguration = SSHAgentConfiguration())

    var diagnosticName: String {
        switch self {
        case .password:
            "password"
        case .privateKeyFile:
            "privateKeyFile"
        case .keyboardInteractive:
            "keyboardInteractive"
        case .agent:
            "agent"
        }
    }
}
