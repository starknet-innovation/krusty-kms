import Foundation
import CKms

public enum KmsError: Error {
    case code(Int32, String)
    case invalidFeltLength(Int)

    static func fromCode(_ code: Int32) -> KmsError {
        let msg = String(cString: kms_error_message(code))
        return .code(code, msg)
    }
}

public struct Felt: Equatable {
    public let bytes: [UInt8]

    public init(bytes: [UInt8]) throws {
        guard bytes.count == 32 else { throw KmsError.invalidFeltLength(bytes.count) }
        self.bytes = bytes
    }

    fileprivate init(cValue: KmsFelt) {
        self.bytes = withUnsafeBytes(of: cValue.bytes) { Array($0) }
    }

    fileprivate func toCValue() -> KmsFelt {
        var out = KmsFelt()
        withUnsafeMutableBytes(of: &out.bytes) { dst in
            dst.copyBytes(from: bytes)
        }
        return out
    }
}

public struct AffinePoint: Equatable {
    public let x: Felt
    public let y: Felt

    fileprivate init(cValue: KmsAffinePoint) {
        self.x = Felt(cValue: cValue.x)
        self.y = Felt(cValue: cValue.y)
    }

    fileprivate func toCValue() -> KmsAffinePoint {
        KmsAffinePoint(
            x: x.toCValue(),
            y: y.toCValue()
        )
    }
}

public struct ProjectivePoint: Equatable {
    public let x: Felt
    public let y: Felt
    public let z: Felt

    fileprivate init(cValue: KmsProjectivePoint) {
        self.x = Felt(cValue: cValue.x)
        self.y = Felt(cValue: cValue.y)
        self.z = Felt(cValue: cValue.z)
    }

    fileprivate func toCValue() -> KmsProjectivePoint {
        KmsProjectivePoint(
            x: x.toCValue(),
            y: y.toCValue(),
            z: z.toCValue()
        )
    }
}

public struct TongoKeyPair: Equatable {
    public let privateKey: Felt
    public let publicKey: ProjectivePoint

    fileprivate init(cValue: KmsTongoKeyPair) {
        self.privateKey = Felt(cValue: cValue.private_key)
        self.publicKey = ProjectivePoint(cValue: cValue.public_key)
    }
}

public struct NostrKeyPair: Equatable {
    public let privateKey: [UInt8]
    public let publicKeyXOnly: [UInt8]

    fileprivate init(cValue: KmsNostrKeyPair) {
        self.privateKey = withUnsafeBytes(of: cValue.private_key) { Array($0) }
        self.publicKeyXOnly = withUnsafeBytes(of: cValue.public_key_xonly) { Array($0) }
    }
}

public enum CoinTypes {
    public static let tongo = Int(kms_get_coin_type_tongo())
    public static let starknet = Int(kms_get_coin_type_starknet())
    public static let tongoView = Int(kms_get_coin_type_tongo_view())
    public static let nostr = Int(kms_get_coin_type_nostr())
}

public enum Kms {
    private static func check(_ code: Int32) throws {
        if code != KMS_OK { throw KmsError.fromCode(code) }
    }

    private static func dynamicString(
        _ call: (_ out: UnsafeMutablePointer<CChar>?, _ outLen: Int, _ outWritten: UnsafeMutablePointer<Int>?) -> Int32
    ) throws -> String {
        var written = 0
        try check(call(nil, 0, &written))

        var out = [CChar](repeating: 0, count: written + 1)
        try check(call(&out, out.count, &written))
        return String(cString: out)
    }

    public static func abiVersion() throws -> (major: UInt32, minor: UInt32) {
        var major: UInt32 = 0
        var minor: UInt32 = 0
        try check(kms_get_abi_version(&major, &minor))
        return (major, minor)
    }

    public static func versionString() throws -> String {
        try dynamicString(kms_get_version_string)
    }

    public static func errorName(code: Int32) -> String {
        String(cString: kms_error_name(code))
    }

    public static func errorMessage(code: Int32) -> String {
        String(cString: kms_error_message(code))
    }

    public static func feltFromHex(_ hex: String) throws -> Felt {
        var out = KmsFelt()
        let rc = hex.withCString { kms_felt_from_hex($0, &out) }
        try check(rc)
        return Felt(cValue: out)
    }

    public static func feltToHex(_ value: Felt) throws -> String {
        var cValue = value.toCValue()
        return try dynamicString { out, outLen, outWritten in
            kms_felt_to_hex(&cValue, out, outLen, outWritten)
        }
    }

    public static func feltFromBytesBe(_ bytes: [UInt8]) throws -> Felt {
        var out = KmsFelt()
        let rc = bytes.withUnsafeBufferPointer { ptr in
            kms_felt_from_bytes_be(ptr.baseAddress, ptr.count, &out)
        }
        try check(rc)
        return Felt(cValue: out)
    }

    public static func feltToBytesBe(_ value: Felt) throws -> [UInt8] {
        var cValue = value.toCValue()
        var out = [UInt8](repeating: 0, count: 32)
        var written = 0
        let rc = out.withUnsafeMutableBufferPointer { ptr in
            kms_felt_to_bytes_be(&cValue, ptr.baseAddress, ptr.count, &written)
        }
        try check(rc)
        return Array(out.prefix(written))
    }

    public static func projectiveFromAffine(_ value: AffinePoint) throws -> ProjectivePoint {
        var cAffine = value.toCValue()
        var out = KmsProjectivePoint()
        try check(kms_projective_from_affine(&cAffine, &out))
        return ProjectivePoint(cValue: out)
    }

    public static func projectiveToAffine(_ value: ProjectivePoint) throws -> AffinePoint {
        var cPoint = value.toCValue()
        var out = KmsAffinePoint()
        try check(kms_projective_to_affine(&cPoint, &out))
        return AffinePoint(cValue: out)
    }

    public static func pedersenHash(_ left: Felt, _ right: Felt) throws -> Felt {
        var cLeft = left.toCValue()
        var cRight = right.toCValue()
        var out = KmsFelt()
        try check(kms_pedersen_hash(&cLeft, &cRight, &out))
        return Felt(cValue: out)
    }

    public static func poseidonHashMany(_ values: [Felt]) throws -> Felt {
        var cValues = values.map { $0.toCValue() }
        var out = KmsFelt()
        let rc = cValues.withUnsafeMutableBufferPointer { ptr in
            kms_poseidon_hash_many(ptr.baseAddress, ptr.count, &out)
        }
        try check(rc)
        return Felt(cValue: out)
    }

    public static func generateMnemonic(_ wordCount: UInt32) throws -> String {
        try dynamicString { out, outLen, outWritten in
            kms_generate_mnemonic(wordCount, out, outLen, outWritten)
        }
    }

    public static func generateMnemonicFromEntropy(_ entropy: [UInt8]) throws -> String {
        try entropy.withUnsafeBufferPointer { ptr in
            try dynamicString { out, outLen, outWritten in
                kms_generate_mnemonic_from_entropy(
                    ptr.baseAddress,
                    ptr.count,
                    out,
                    outLen,
                    outWritten
                )
            }
        }
    }

    public static func validateMnemonic(_ phrase: String) throws {
        let rc = phrase.withCString { kms_validate_mnemonic($0) }
        try check(rc)
    }

    public static func mnemonicToSeed(_ phrase: String, passphrase: String = "") throws -> [UInt8] {
        var out = [UInt8](repeating: 0, count: 64)
        var written = 0
        let rc = phrase.withCString { p in
            passphrase.withCString { pp in
                kms_mnemonic_to_seed(p, pp, &out, out.count, &written)
            }
        }
        try check(rc)
        return Array(out.prefix(written))
    }

    public static func derivePrivateKey(
        mnemonic: String,
        index: UInt32,
        accountIndex: UInt32,
        coinType: UInt32,
        passphrase: String = ""
    ) throws -> Felt {
        var out = KmsFelt()
        let rc = mnemonic.withCString { m in
            passphrase.withCString { p in
                kms_derive_private_key_with_coin_type(m, index, accountIndex, coinType, p, &out)
            }
        }
        try check(rc)
        return Felt(cValue: out)
    }

    public static func deriveKeypair(
        mnemonic: String,
        index: UInt32,
        accountIndex: UInt32,
        coinType: UInt32,
        passphrase: String = ""
    ) throws -> TongoKeyPair {
        var out = KmsTongoKeyPair()
        let rc = mnemonic.withCString { m in
            passphrase.withCString { p in
                kms_derive_keypair_with_coin_type(m, index, accountIndex, coinType, p, &out)
            }
        }
        try check(rc)
        return TongoKeyPair(cValue: out)
    }

    public static func deriveViewPrivateKey(
        mnemonic: String,
        index: UInt32,
        accountIndex: UInt32,
        passphrase: String = ""
    ) throws -> Felt {
        var out = KmsFelt()
        let rc = mnemonic.withCString { m in
            passphrase.withCString { p in
                kms_derive_view_private_key(m, index, accountIndex, p, &out)
            }
        }
        try check(rc)
        return Felt(cValue: out)
    }

    public static func deriveViewKeypair(
        mnemonic: String,
        index: UInt32,
        accountIndex: UInt32,
        passphrase: String = ""
    ) throws -> TongoKeyPair {
        var out = KmsTongoKeyPair()
        let rc = mnemonic.withCString { m in
            passphrase.withCString { p in
                kms_derive_view_keypair(m, index, accountIndex, p, &out)
            }
        }
        try check(rc)
        return TongoKeyPair(cValue: out)
    }

    public static func deriveNostrPrivateKey(
        mnemonic: String,
        index: UInt32,
        accountIndex: UInt32,
        passphrase: String = ""
    ) throws -> [UInt8] {
        var out = [UInt8](repeating: 0, count: 32)
        let rc = mnemonic.withCString { m in
            passphrase.withCString { p in
                kms_derive_nostr_private_key(m, index, accountIndex, p, &out)
            }
        }
        try check(rc)
        return out
    }

    public static func deriveNostrKeypair(
        mnemonic: String,
        index: UInt32,
        accountIndex: UInt32,
        passphrase: String = ""
    ) throws -> NostrKeyPair {
        var out = KmsNostrKeyPair()
        let rc = mnemonic.withCString { m in
            passphrase.withCString { p in
                kms_derive_nostr_keypair(m, index, accountIndex, p, &out)
            }
        }
        try check(rc)
        return NostrKeyPair(cValue: out)
    }

    public static func calculateContractAddress(
        salt: Felt,
        classHash: Felt,
        constructorCalldata: [Felt],
        deployer: Felt
    ) throws -> Felt {
        var cSalt = salt.toCValue()
        var cClassHash = classHash.toCValue()
        var cDeployer = deployer.toCValue()
        var cCalldata = constructorCalldata.map { $0.toCValue() }
        var out = KmsFelt()

        let rc = cCalldata.withUnsafeMutableBufferPointer { ptr in
            kms_calculate_contract_address(
                &cSalt,
                &cClassHash,
                ptr.baseAddress,
                ptr.count,
                &cDeployer,
                &out
            )
        }
        try check(rc)
        return Felt(cValue: out)
    }

    public static func deriveOzAccountAddress(
        publicKeyX: Felt,
        classHash: Felt,
        salt: Felt? = nil
    ) throws -> Felt {
        var cPublicKeyX = publicKeyX.toCValue()
        var cClassHash = classHash.toCValue()
        var cSalt = salt?.toCValue()
        var out = KmsFelt()

        let rc = withUnsafeMutablePointer(to: &cSalt) { saltPtr in
            let rawSaltPtr = salt == nil ? nil : UnsafeMutableRawPointer(saltPtr).assumingMemoryBound(to: KmsFelt.self)
            return kms_derive_oz_account_address(
                &cPublicKeyX,
                &cClassHash,
                rawSaltPtr,
                &out
            )
        }
        try check(rc)
        return Felt(cValue: out)
    }
}
