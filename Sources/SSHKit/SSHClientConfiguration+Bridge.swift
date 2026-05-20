import Foundation
import SSHKitObjC

extension SSHClientConfiguration {
    var bridgeConfiguration: SSHKitConfiguration {
        let configuration = SSHKitConfiguration(host: host, username: username)
        configuration.port = port
        configuration.timeout = timeout
        if let logHandler {
            configuration.logHandler = { event in
                logHandler(SSHLogEvent(event).redacted)
            }
        }

        switch authentication {
        case let .password(password):
            configuration.authenticationKind = .password
            configuration.password = password
        case let .privateKeyFile(path, passphrase):
            configuration.authenticationKind = .privateKeyFile
            configuration.privateKeyPath = path
            configuration.privateKeyPassphrase = passphrase
        case let .keyboardInteractive(responseProvider):
            configuration.authenticationKind = .keyboardInteractive
            configuration.keyboardInteractiveResponder = { name, instruction, prompts in
                let swiftPrompts = prompts.map { prompt in
                    SSHKeyboardInteractivePrompt(prompt: prompt.prompt, echo: prompt.echo)
                }
                return responseProvider(name, instruction, swiftPrompts)
            }
        }

        switch hostKeyPolicy {
        case .insecureAcceptAnyHostKey:
            configuration.hostKeyPolicyKind = .insecureAcceptAnyHostKey
        case let .knownHostsFile(path):
            configuration.hostKeyPolicyKind = .knownHostsFile
            configuration.knownHostsPath = path
        }

        return configuration
    }
}
