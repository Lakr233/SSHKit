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

        switch proxyRoute {
        case nil:
            configuration.proxyRouteKind = .none
        case let .socks5(endpoint):
            configuration.proxyRouteKind = .SOCKS5
            configuration.proxyHost = endpoint.host
            configuration.proxyPort = endpoint.port
            configuration.proxyUsername = endpoint.username
            configuration.proxyPassword = endpoint.password
        case let .httpConnect(endpoint):
            configuration.proxyRouteKind = .httpConnect
            configuration.proxyHost = endpoint.host
            configuration.proxyPort = endpoint.port
            configuration.proxyUsername = endpoint.username
            configuration.proxyPassword = endpoint.password
        case let .proxyJump(jumpHost):
            configuration.proxyRouteKind = .proxyJump
            let jumpConfiguration = SSHClientConfiguration(
                host: jumpHost.host,
                port: jumpHost.port,
                username: jumpHost.username,
                authentication: jumpHost.authentication,
                hostKeyPolicy: jumpHost.hostKeyPolicy,
                timeout: jumpHost.timeout,
            ).bridgeConfiguration
            configuration.proxyJump = jumpConfiguration
        }

        return configuration
    }
}
