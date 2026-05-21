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
        configuration.keyExchangeAlgorithms = algorithmProfile.keyExchangeAlgorithms
        configuration.hostKeyAlgorithms = algorithmProfile.hostKeyAlgorithms
        configuration.publicKeyAcceptedAlgorithms = algorithmProfile.publicKeyAcceptedAlgorithms
        configuration.ciphersClientToServer = algorithmProfile.ciphersClientToServer
        configuration.ciphersServerToClient = algorithmProfile.ciphersServerToClient
        configuration.macsClientToServer = algorithmProfile.macsClientToServer
        configuration.macsServerToClient = algorithmProfile.macsServerToClient
        configuration.minimumRSAKeySize = algorithmProfile.minimumRSAKeySize.map(NSNumber.init(value:))

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
        case let .agent(agentConfiguration):
            configuration.authenticationKind = .agent
            configuration.identityAgentPath = agentConfiguration.socketPath
        }

        switch hostKeyPolicy {
        case .insecureAcceptAnyHostKey:
            configuration.hostKeyPolicyKind = .insecureAcceptAnyHostKey
        case let .knownHostsFile(path):
            configuration.hostKeyPolicyKind = .knownHostsFile
            configuration.knownHostsPath = path
        case let .pinnedFingerprint(fingerprint):
            configuration.hostKeyPolicyKind = .pinnedFingerprint
            configuration.pinnedHostKeySHA256Fingerprint = fingerprint.rawValue
        case let .trustStore(store):
            configuration.hostKeyPolicyKind = .trustedFingerprint
            do {
                configuration.trustedHostKeySHA256Fingerprint = try store.fingerprint(host: host, port: port)?.rawValue
            } catch {
                configuration.hostKeyTrustStoreError = error.localizedDescription
            }
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
                algorithmProfile: jumpHost.algorithmProfile
            ).bridgeConfiguration
            configuration.proxyJump = jumpConfiguration
        }

        return configuration
    }
}

extension SSHHostKeyDiscoveryConfiguration {
    var bridgeConfiguration: SSHKitConfiguration {
        let configuration = SSHKitConfiguration(host: host, username: "sshkit-host-key-discovery")
        configuration.port = port
        configuration.timeout = timeout
        if let logHandler {
            configuration.logHandler = { event in
                logHandler(SSHLogEvent(event).redacted)
            }
        }
        configuration.keyExchangeAlgorithms = algorithmProfile.keyExchangeAlgorithms
        configuration.hostKeyAlgorithms = algorithmProfile.hostKeyAlgorithms
        configuration.publicKeyAcceptedAlgorithms = algorithmProfile.publicKeyAcceptedAlgorithms
        configuration.ciphersClientToServer = algorithmProfile.ciphersClientToServer
        configuration.ciphersServerToClient = algorithmProfile.ciphersServerToClient
        configuration.macsClientToServer = algorithmProfile.macsClientToServer
        configuration.macsServerToClient = algorithmProfile.macsServerToClient
        configuration.minimumRSAKeySize = algorithmProfile.minimumRSAKeySize.map(NSNumber.init(value:))
        configuration.authenticationKind = .password
        configuration.password = ""
        configuration.hostKeyPolicyKind = .insecureAcceptAnyHostKey

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
                algorithmProfile: jumpHost.algorithmProfile
            ).bridgeConfiguration
            configuration.proxyJump = jumpConfiguration
        }

        return configuration
    }
}
