import Foundation
import SSHKitObjC

public enum SSHKeyGenerationType: Sendable, Equatable {
    case ed25519
    case rsa(bits: Int = 3072)
    case ecdsaP256
    case ecdsaP384
    case ecdsaP521

    var bridgeValue: (type: SSHKitKeyGenerationType, bits: Int) {
        switch self {
        case .ed25519:
            (.ed25519, 0)
        case let .rsa(bits):
            (.RSA, bits)
        case .ecdsaP256:
            (.ECDSAP256, 256)
        case .ecdsaP384:
            (.ECDSAP384, 384)
        case .ecdsaP521:
            (.ECDSAP521, 521)
        }
    }
}

public struct SSHGeneratedKeyPair: Equatable, Sendable {
    public var privateKeyOpenSSH: String
    public var authorizedKey: String
    public var publicKeyType: String

    public init(privateKeyOpenSSH: String, authorizedKey: String, publicKeyType: String) {
        self.privateKeyOpenSSH = privateKeyOpenSSH
        self.authorizedKey = authorizedKey
        self.publicKeyType = publicKeyType
    }
}

public enum SSHKeyGenerator {
    public static func generateOpenSSHKeyPair(
        type: SSHKeyGenerationType = .ed25519,
        comment: String? = nil,
        passphrase: String? = nil
    ) throws -> SSHGeneratedKeyPair {
        let bridge = type.bridgeValue
        do {
            let keyPair = try SSHKitGeneratedKeyPair.generateOpenSSHKeyPair(
                with: bridge.type,
                bits: bridge.bits,
                comment: comment,
                passphrase: passphrase
            )
            return SSHGeneratedKeyPair(
                privateKeyOpenSSH: keyPair.privateKeyOpenSSH,
                authorizedKey: keyPair.authorizedKey,
                publicKeyType: keyPair.publicKeyType
            )
        } catch let error as NSError {
            throw SSHKitError(error)
        }
    }
}
