import Foundation
import SSHKitObjC

public struct SSHAlgorithmProfile: Equatable, Sendable {
    public var keyExchangeAlgorithms: String?
    public var hostKeyAlgorithms: String?
    public var publicKeyAcceptedAlgorithms: String?
    public var ciphersClientToServer: String?
    public var ciphersServerToClient: String?
    public var macsClientToServer: String?
    public var macsServerToClient: String?
    public var minimumRSAKeySize: Int?

    public init(
        keyExchangeAlgorithms: String? = nil,
        hostKeyAlgorithms: String? = nil,
        publicKeyAcceptedAlgorithms: String? = nil,
        ciphersClientToServer: String? = nil,
        ciphersServerToClient: String? = nil,
        macsClientToServer: String? = nil,
        macsServerToClient: String? = nil,
        minimumRSAKeySize: Int? = nil,
    ) {
        self.keyExchangeAlgorithms = keyExchangeAlgorithms
        self.hostKeyAlgorithms = hostKeyAlgorithms
        self.publicKeyAcceptedAlgorithms = publicKeyAcceptedAlgorithms
        self.ciphersClientToServer = ciphersClientToServer
        self.ciphersServerToClient = ciphersServerToClient
        self.macsClientToServer = macsClientToServer
        self.macsServerToClient = macsServerToClient
        self.minimumRSAKeySize = minimumRSAKeySize
    }

    public static let modern = SSHAlgorithmProfile(minimumRSAKeySize: 3072)

    public static let legacyRSA = SSHAlgorithmProfile(
        hostKeyAlgorithms: "+ssh-rsa",
        publicKeyAcceptedAlgorithms: "+ssh-rsa",
        minimumRSAKeySize: 1024,
    )

    public func inspectEffectiveAlgorithms() throws -> SSHAlgorithmSnapshot {
        do {
            let values = try SSHKitAlgorithmInspector.inspectAlgorithms(
                withKeyExchangeAlgorithms: keyExchangeAlgorithms,
                hostKeyAlgorithms: hostKeyAlgorithms,
                publicKeyAcceptedAlgorithms: publicKeyAcceptedAlgorithms,
                ciphersClientToServer: ciphersClientToServer,
                ciphersServerToClient: ciphersServerToClient,
                macsClientToServer: macsClientToServer,
                macsServerToClient: macsServerToClient,
                minimumRSAKeySize: minimumRSAKeySize.map(NSNumber.init(value:)),
            )
            return SSHAlgorithmSnapshot(values: values)
        } catch let error as NSError {
            throw SSHKitError(error)
        }
    }
}

public struct SSHAlgorithmSnapshot: Equatable, Sendable {
    public var keyExchangeAlgorithms: String
    public var hostKeyAlgorithms: String
    public var publicKeyAcceptedAlgorithms: String
    public var ciphersClientToServer: String
    public var ciphersServerToClient: String
    public var macsClientToServer: String
    public var macsServerToClient: String
    public var minimumRSAKeySize: Int?

    init(values: [String: String]) {
        keyExchangeAlgorithms = values["keyExchangeAlgorithms"] ?? ""
        hostKeyAlgorithms = values["hostKeyAlgorithms"] ?? ""
        publicKeyAcceptedAlgorithms = values["publicKeyAcceptedAlgorithms"] ?? ""
        ciphersClientToServer = values["ciphersClientToServer"] ?? ""
        ciphersServerToClient = values["ciphersServerToClient"] ?? ""
        macsClientToServer = values["macsClientToServer"] ?? ""
        macsServerToClient = values["macsServerToClient"] ?? ""
        minimumRSAKeySize = values["minimumRSAKeySize"].flatMap(Int.init)
    }
}
