import Foundation
import CryptoKit
import StoreKit
import DeviceCheck

public struct StoreProofReceipt: Decodable {
    public let environment: String
    public let expiresAt: String
    public var expiry: Date? { HostedDate.parse(expiresAt) }
}

@MainActor final class StoreEnvironmentProof {
    private(set) var localEnvironment: String?
    private static let publicOrigin = "https://api.rooklayer.com"

    // The injectable provider is internal. The app-facing entry point accepts no
    // caller-supplied Apple JWS or device identifier.
    struct VerifiedTransaction {
        let signedAppTransaction: String
        let nonce: UUID
        let deviceVerificationID: UUID?
        let deviceVerification: Data
        let environment: String
    }
    struct Dependencies {
        let isSupported: () -> Bool
        let transaction: () async throws -> VerifiedTransaction
        let generateKey: () async throws -> String
        let attest: (String, Data) async throws -> Data
        let assert: (String, Data) async throws -> Data
    }
    private let defaults: UserDefaults
    private let dependencies: Dependencies
    private var pending = [String: Task<StoreProofReceipt, Error>]()

    convenience init() {
        self.init(defaults: .standard, dependencies: .init(
            isSupported: { DCAppAttestService.shared.isSupported },
            transaction: {
                let result = try await AppTransaction.shared
                guard case .verified(let transaction) = result,
                      transaction.bundleID == Bundle.main.bundleIdentifier,
                      transaction.environment == .production || transaction.environment == .sandbox else {
                    throw HostedError("The App Store could not verify this installation. Try again later.")
                }
                return VerifiedTransaction(
                    signedAppTransaction: result.jwsRepresentation,
                    nonce: transaction.deviceVerificationNonce,
                    deviceVerificationID: AppStore.deviceVerificationID,
                    deviceVerification: transaction.deviceVerification,
                    environment: transaction.environment.rawValue)
            },
            generateKey: { try await DCAppAttestService.shared.generateKey() },
            attest: { key, hash in try await DCAppAttestService.shared.attestKey(key, clientDataHash: hash) },
            assert: { key, hash in try await DCAppAttestService.shared.generateAssertion(key, clientDataHash: hash) }))
    }

    init(defaults: UserDefaults, dependencies: Dependencies) {
        self.defaults = defaults
        self.dependencies = dependencies
    }
    func establish(client: HostedClient, session: HostedSession) async throws -> StoreProofReceipt {
        localEnvironment = nil
        guard client.origin.absoluteString == Self.publicOrigin || client.origin.absoluteString == Self.publicOrigin + "/" else {
            throw HostedError("Store verification requires Rook’s public service.")
        }
        try session.validate(expectedOrigin: client.origin)
        guard let expiry = session.expiry, expiry > Date() else {
            throw HostedError("Sign in again to verify your App Store installation.")
        }
        guard dependencies.isSupported() else {
            throw HostedError("This device cannot verify its App Store installation with Apple App Attest.")
        }
        let transaction = try await dependencies.transaction()
        // Complete the local device binding before generating a key or sending a
        // challenge, so a copied valid AppTransaction cannot be freshly attested.
        try Self.validateDeviceVerification(nonce: transaction.nonce,
                                           currentDeviceID: transaction.deviceVerificationID,
                                           verification: transaction.deviceVerification)
        guard transaction.deviceVerificationID != nil,
              !transaction.signedAppTransaction.isEmpty,
              ["Production", "Sandbox"].contains(transaction.environment) else {
            throw HostedError("The App Store could not verify this installation.")
        }
        localEnvironment = transaction.environment
        let cacheID = "rook.store-proof.key.v1.\(session.user.id.uuidString.lowercased()).\(session.device.id)"
        if let operation = pending[cacheID] { return try await operation.value }
        let operation = Task { try await self.perform(client: client, session: session, cacheID: cacheID, transaction: transaction) }
        pending[cacheID] = operation
        defer { pending[cacheID] = nil }
        return try await operation.value
    }

    private func perform(client: HostedClient, session: HostedSession, cacheID: String,
                         transaction: VerifiedTransaction) async throws -> StoreProofReceipt {
        guard let deviceID = transaction.deviceVerificationID else {
            throw HostedError("The App Store could not identify this device.")
        }

        let cachedKey = defaults.string(forKey: cacheID)
        var keyID: String
        if let cachedKey { keyID = cachedKey }
        else { keyID = try await generateKey(cacheID: cacheID) }
        var challenge = try await requestChallenge(client: client, session: session, keyID: keyID)
        if cachedKey != nil && !challenge.keyRegistered {
            // Apple attests a key only once. A server that lost or rejected its
            // registration requires a new key and a challenge bound to that key.
            keyID = try await generateKey(cacheID: cacheID)
            challenge = try await requestChallenge(client: client, session: session, keyID: keyID)
        }
        let data = try Self.clientData(challengeID: challenge.challengeId, nonce: challenge.nonce,
                                       accountID: session.user.id, pairedDeviceID: session.device.id,
                                       keyID: keyID, signedAppTransaction: transaction.signedAppTransaction,
                                       deviceVerificationID: deviceID)
        let hash = Data(SHA256.hash(data: data))
        let appleProof: Data
        do {
            appleProof = try await challenge.keyRegistered
                ? dependencies.assert(keyID, hash)
                : dependencies.attest(keyID, hash)
        } catch {
            if (error as NSError).domain == DCError.errorDomain,
               (error as NSError).code == DCError.Code.invalidKey.rawValue {
                defaults.removeObject(forKey: cacheID)
            }
            throw error
        }
        guard !appleProof.isEmpty else { throw HostedError("Apple did not return an installation proof.") }
        try challenge.validate()
        let receipt: StoreProofReceipt = try await client.send(
            "v1/billing/device/proof", token: session.accountToken,
            body: ProofRequest(deviceId: session.device.id, challengeId: challenge.challengeId, keyId: keyID,
                               signedAppTransaction: transaction.signedAppTransaction,
                               deviceVerificationId: deviceID.uuidString.lowercased(),
                               attestation: challenge.keyRegistered ? nil : appleProof.base64EncodedString(),
                               assertion: challenge.keyRegistered ? appleProof.base64EncodedString() : nil))
        guard receipt.environment == transaction.environment,
              let expiry = receipt.expiry, expiry > Date() else {
            throw HostedError("Rook could not verify this App Store installation. Try again later.")
        }
        return receipt
    }

    private func generateKey(cacheID: String) async throws -> String {
        let keyID = try await dependencies.generateKey()
        guard !keyID.isEmpty else { throw HostedError("Apple did not return an installation key.") }
        // This is only the nonsensitive identifier. Apple retains the private key
        // inside the Secure Enclave; no private key or transaction is cached here.
        defaults.set(keyID, forKey: cacheID)
        return keyID
    }

    private func requestChallenge(client: HostedClient, session: HostedSession, keyID: String) async throws -> ProofChallenge {
        let challenge: ProofChallenge = try await client.send(
            "v1/billing/device/challenge", token: session.accountToken,
            body: ChallengeRequest(deviceId: session.device.id, keyId: keyID))
        try challenge.validate()
        return challenge
    }
    static func clientData(challengeID: String, nonce: String, accountID: UUID,
                           pairedDeviceID: String, keyID: String, signedAppTransaction: String,
                           deviceVerificationID: UUID) throws -> Data {
        let transactionHash = SHA256.hash(data: Data(signedAppTransaction.utf8))
            .map { String(format: "%02x", $0) }.joined()
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.withoutEscapingSlashes]
        return try encoder.encode([
            "rook.store-proof.v1", publicOrigin, challengeID, nonce,
            accountID.uuidString.lowercased(), pairedDeviceID, keyID,
            transactionHash, deviceVerificationID.uuidString.lowercased()
        ])
    }
    static func validateDeviceVerification(nonce: UUID, currentDeviceID: UUID?, verification: Data) throws {
        guard let currentDeviceID else {
            throw HostedError("The App Store could not identify this device. Try again later.")
        }
        let input = nonce.uuidString.lowercased() + currentDeviceID.uuidString.lowercased()
        guard Data(SHA384.hash(data: Data(input.utf8))) == verification else {
            throw HostedError("This App Store installation could not be verified for this device.")
        }
    }

    private struct ChallengeRequest: Encodable { let deviceId: String; let keyId: String }
    private struct ProofChallenge: Decodable {
        let challengeId: String; let nonce: String; let expiresAt: String; let keyRegistered: Bool
        func validate() throws {
            guard !challengeId.isEmpty, !nonce.isEmpty,
                  let expiry = HostedDate.parse(expiresAt), expiry > Date() else {
                throw HostedError("The installation verification challenge expired. Try again.")
            }
        }
    }
    private struct ProofRequest: Encodable {
        let deviceId: String; let challengeId: String; let keyId: String
        let signedAppTransaction: String; let deviceVerificationId: String
        let attestation: String?; let assertion: String?
    }
}
