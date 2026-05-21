import Foundation
import SSHKitObjC

public enum SSHAuthenticationMethod: Equatable, Sendable {
    case none
    case password
    case publicKey
    case hostBased
    case keyboardInteractive
    case gssapi
}

public struct SSHAuthenticationDiscoveryResult: Equatable, Sendable {
    public var methods: [SSHAuthenticationMethod]
    public var issueBanner: String?
    public var serverBanner: String?

    public init(methods: [SSHAuthenticationMethod], issueBanner: String?, serverBanner: String?) {
        self.methods = methods
        self.issueBanner = issueBanner
        self.serverBanner = serverBanner
    }
}

extension SSHAuthenticationDiscoveryResult {
    init(_ result: SSHKitObjC.SSHKitAuthenticationDiscoveryResult) {
        methods = result.methods.compactMap { SSHAuthenticationMethod(rawValue: $0.intValue) }
        issueBanner = result.issueBanner
        serverBanner = result.serverBanner
    }
}

private extension SSHAuthenticationMethod {
    init?(rawValue: Int) {
        switch rawValue {
        case 1:
            self = .none
        case 2:
            self = .password
        case 3:
            self = .publicKey
        case 4:
            self = .hostBased
        case 5:
            self = .keyboardInteractive
        case 6:
            self = .gssapi
        default:
            return nil
        }
    }
}
