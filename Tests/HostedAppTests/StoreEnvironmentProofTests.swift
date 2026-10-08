import XCTest
import CryptoKit
@testable import Gatekeeper

@MainActor final class StoreEnvironmentProofTests: XCTestCase {
    private let nonce = UUID(uuidString: "00112233-4455-6677-8899-AABBCCDDEEFF")!
    private let deviceID = UUID(uuidString: "FFEEDDCC-BBAA-9988-7766-554433221100")!
    private let accountID = UUID(uuidString: "AABBCCDD-1234-5678-9ABC-001122334455")!
    private var defaults: UserDefaults!
    private var defaultsName: String!

    override func setUp() async throws {
        defaultsName = "StoreEnvironmentProofTests.\(UUID().uuidString)"
        defaults = UserDefaults(suiteName: defaultsName)!
    }
    override func tearDown() async throws {
        defaults.removePersistentDomain(forName: defaultsName)
        StoreProofURLProtocol.handler = nil
    }

    func testCanonicalBytesMatchJavaScriptJSONWithLowercaseUUIDsAndUnescapedSlashes() throws {
        let bytes = try StoreEnvironmentProof.clientData(
            challengeID: "challenge/一", nonce: "nonce/é", accountID: accountID,
            pairedDeviceID: "paired-device", keyID: "key/+==",
            signedAppTransaction: "header.payload.signature", deviceVerificationID: deviceID)
        let expected = #"["rook.store-proof.v1","https://api.rooklayer.com","challenge/一","nonce/é","aabbccdd-1234-5678-9abc-001122334455","paired-device","key/+==","256d04db4e5e4ac308751ed0885b722b758630567c53a7125ed9fbd068e5c3f6","ffeeddcc-bbaa-9988-7766-554433221100"]"#
        XCTAssertEqual(bytes, Data(expected.utf8))
    }

    func testDeviceVerificationUsesNonceThenCurrentDeviceLowercaseUUIDs() throws {
        try StoreEnvironmentProof.validateDeviceVerification(
            nonce: nonce, currentDeviceID: deviceID, verification: verification)
        XCTAssertThrowsError(try StoreEnvironmentProof.validateDeviceVerification(
            nonce: deviceID, currentDeviceID: nonce, verification: verification))
        XCTAssertThrowsError(try StoreEnvironmentProof.validateDeviceVerification(
            nonce: nonce, currentDeviceID: UUID(), verification: verification))
        XCTAssertThrowsError(try StoreEnvironmentProof.validateDeviceVerification(
            nonce: nonce, currentDeviceID: nil, verification: verification))
        XCTAssertThrowsError(try StoreEnvironmentProof.validateDeviceVerification(
            nonce: nonce, currentDeviceID: deviceID, verification: Data()))
    }

    func testFreshKeyAttestsVerifiedTransactionThenRegisteredKeyAssertsFreshChallenge() async throws {
        let requests = StoreProofRequests()
        StoreProofURLProtocol.handler = { request in
            requests.add(request)
            if request.url!.path.hasSuffix("challenge") {
                return self.challenge(id: requests.count == 1 ? "first" : "second", registered: requests.count > 1)
            }
            return self.receipt()
        }
        var attestedHashes = [Data](); var assertionHashes = [Data](); var generated = 0
        let proof = makeProof(generateKey: { generated += 1; return "apple/key" },
                              attest: { key, hash in XCTAssertEqual(key, "apple/key"); attestedHashes.append(hash); return Data([1, 2]) },
                              assert: { key, hash in XCTAssertEqual(key, "apple/key"); assertionHashes.append(hash); return Data([3, 4]) })
        let first = try await proof.establish(client: client(), session: session())
        let second = try await proof.establish(client: client(), session: session())
        XCTAssertEqual(first.environment, "Sandbox")
        XCTAssertEqual(second.environment, "Sandbox")
        XCTAssertEqual(generated, 1)
        XCTAssertEqual(attestedHashes.count, 1)
        XCTAssertEqual(assertionHashes.count, 1)
        XCTAssertEqual(attestedHashes.first?.map { String(format: "%02x", $0) }.joined(),
                       "d6a78156155a2f462e6769cd7d98c13c8a0fc085b7b792d44d97d1a14b29ef6c")
        XCTAssertNotEqual(attestedHashes.first, assertionHashes.first)
        let bodies = try requests.values.map(body)
        XCTAssertEqual(bodies[0]["deviceId"] as? String, "paired-device")
        XCTAssertEqual(bodies[1]["attestation"] as? String, "AQI=")
        XCTAssertNil(bodies[1]["assertion"])
        XCTAssertEqual(bodies[1]["signedAppTransaction"] as? String, "header.payload.signature")
        XCTAssertEqual(bodies[1]["deviceVerificationId"] as? String, deviceID.uuidString.lowercased())
        XCTAssertEqual(bodies[3]["assertion"] as? String, "AwQ=")
        XCTAssertNil(bodies[3]["attestation"])
        XCTAssertTrue(requests.values.allSatisfy { $0.value(forHTTPHeaderField: "Authorization") == "Bearer \(String(repeating: "a", count: 32))" })
    }
    func testSandboxPurchaseDeliveryAlwaysRenewsProofIncludingAfterAValidCachedReceipt() async throws {
        let requests = StoreProofRequests()
        StoreProofURLProtocol.handler = { request in
            requests.add(request)
            return request.url!.path.hasSuffix("challenge") ? self.challenge(id: "fresh", registered: requests.count > 1) : self.receipt()
        }
        let client = client(), saved = session()
        let account = HostedAccount(origin: client.origin, session: saved, client: client, persist: { _ in }, clear: {}, storeProof: makeProof())
        try await account.refreshSandboxPurchaseProof(client: client, session: saved)
        try await account.refreshSandboxPurchaseProof(client: client, session: saved)
        XCTAssertEqual(requests.count, 4)
        XCTAssertEqual(try body(requests.values[3])["assertion"] as? String, "Ag==")
    }
    func testForegroundRenewsNearExpiryTestAccessAndLeavesLocalProtectionAlone() async throws {
        let requests = StoreProofRequests(); var receipts = 0; var closes = 0
        let saved = session(), client = client()
        let snapshot = Data("{\"user\":{\"id\":\"\(saved.user.id.uuidString)\"},\"devices\":[],\"entitlement\":{\"active\":false,\"betaAccess\":false,\"access\":{\"available\":true,\"mode\":\"sandbox_test\",\"deviceId\":\"paired-device\"}}}".utf8)
        StoreProofURLProtocol.handler = { request in
            requests.add(request)
            if request.url!.path.hasSuffix("account") { return snapshot }
            if request.url!.path.hasSuffix("conversation") { return Data(#"{"messages":[]}"#.utf8) }
            if request.url!.path.hasSuffix("products") { return Data(#"{"productIds":[],"betaAccess":false}"#.utf8) }
            if request.url!.path.hasSuffix("agents") { return Data(#"{"connections":[]}"#.utf8) }
            if request.url!.path.hasSuffix("challenge") { return self.challenge(id: "fresh", registered: receipts > 0) }
            receipts += 1
            let expiry = ISO8601DateFormatter().string(from: Date().addingTimeInterval(receipts == 1 ? 30 : 900))
            return Data("{\"environment\":\"Sandbox\",\"expiresAt\":\"\(expiry)\"}".utf8)
        }
        let account = HostedAccount(origin: client.origin, session: saved, client: client, persist: { _ in }, clear: {}, closeProtection: { closes += 1 }, storeProof: makeProof())
        await account.reload()
        XCTAssertEqual(receipts, 1)
        let before = requests.count
        await account.renewSandboxAccessIfNeeded()
        XCTAssertEqual(requests.count, before + 3)
        XCTAssertTrue(account.hasAccess)
        XCTAssertEqual(closes, 0)
        await account.renewSandboxAccessIfNeeded()
        XCTAssertEqual(requests.count, before + 3)
    }

    func testUnknownCachedKeyIsReplacedAndBindsNewChallenge() async throws {
        let requests = StoreProofRequests()
        StoreProofURLProtocol.handler = { request in
            requests.add(request)
            if request.url!.path.hasSuffix("challenge") { return self.challenge(id: "challenge-\(requests.count)", registered: false) }
            return self.receipt()
        }
        var generated = 0; var attestedKeys = [String]()
        let proof = makeProof(generateKey: { generated += 1; return "key-\(generated)" },
                              attest: { key, _ in attestedKeys.append(key); return Data([1]) })
        _ = try await proof.establish(client: client(), session: session())
        _ = try await proof.establish(client: client(), session: session())
        XCTAssertEqual(generated, 2)
        XCTAssertEqual(attestedKeys, ["key-1", "key-2"])
        let bodies = try requests.values.map(body)
        XCTAssertEqual(bodies[2]["keyId"] as? String, "key-1")
        XCTAssertEqual(bodies[3]["keyId"] as? String, "key-2")
        XCTAssertEqual(bodies[4]["challengeId"] as? String, "challenge-4")
    }

    func testDeviceMismatchFailsBeforeGeneratingAnyAppleProofOrCallingServer() async {
        var generated = 0
        let proof = makeProof(verification: Data(repeating: 0, count: 48), generateKey: { generated += 1; return "key" })
        StoreProofURLProtocol.handler = { _ in XCTFail("Mismatched StoreKit result reached server"); return self.receipt() }
        do { _ = try await proof.establish(client: client(), session: session()); XCTFail("Device mismatch accepted") } catch {}
        XCTAssertEqual(generated, 0)
        XCTAssertNil(proof.localEnvironment)
    }

    func testLocallyVerifiedEnvironmentSurvivesNetworkErrorButNextAttemptClearsStaleClassification() async {
        var wrongDevice = false
        let proof = StoreEnvironmentProof(defaults: defaults, dependencies: .init(
            isSupported: { true }, transaction: { self.snapshot(verification: wrongDevice ? Data() : nil) },
            generateKey: { "key" }, attest: { _, _ in Data([1]) }, assert: { _, _ in Data([2]) }))
        XCTAssertNil(proof.localEnvironment)
        StoreProofURLProtocol.handler = { _ in throw URLError(.notConnectedToInternet) }
        do { _ = try await proof.establish(client: client(), session: session()); XCTFail("Offline proof returned receipt") }
        catch { XCTAssertEqual((error as? URLError)?.code, .notConnectedToInternet) }
        XCTAssertEqual(proof.localEnvironment, "Sandbox")
        wrongDevice = true
        do { _ = try await proof.establish(client: client(), session: session()); XCTFail("Device mismatch returned receipt") } catch {}
        XCTAssertNil(proof.localEnvironment)
    }

    func testInvalidOriginClearsEarlierLocallyVerifiedEnvironment() async {
        let proof = makeProof()
        StoreProofURLProtocol.handler = { _ in throw URLError(.notConnectedToInternet) }
        _ = try? await proof.establish(client: client(), session: session())
        XCTAssertEqual(proof.localEnvironment, "Sandbox")
        _ = try? await proof.establish(client: client(origin: "https://other.example"), session: session())
        XCTAssertNil(proof.localEnvironment)
    }

    func testProductionInstallationCannotRetainEarlierSandboxClassificationAfterProofError() async {
        var environment = "Sandbox"
        let proof = StoreEnvironmentProof(defaults: defaults, dependencies: .init(
            isSupported: { true }, transaction: { self.snapshot(environment: environment) },
            generateKey: { "key" }, attest: { _, _ in Data([1]) }, assert: { _, _ in Data([2]) }))
        StoreProofURLProtocol.handler = { _ in throw URLError(.notConnectedToInternet) }
        _ = try? await proof.establish(client: client(), session: session())
        XCTAssertEqual(proof.localEnvironment, "Sandbox")
        environment = "Production"
        do { _ = try await proof.establish(client: client(), session: session()); XCTFail("Offline proof returned receipt") } catch {}
        XCTAssertEqual(proof.localEnvironment, "Production")
    }

    func testUnsupportedAppAttestFailsClosed() async {
        var loaded = false
        let proof = StoreEnvironmentProof(defaults: defaults, dependencies: .init(
            isSupported: { false }, transaction: { loaded = true; return self.snapshot() },
            generateKey: { XCTFail("Unsupported provider generated key"); return "key" },
            attest: { _, _ in XCTFail("Unsupported provider attested"); return Data([1]) },
            assert: { _, _ in XCTFail("Unsupported provider asserted"); return Data([1]) }))
        do { _ = try await proof.establish(client: client(), session: session()); XCTFail("Unsupported service classified app") } catch {}
        XCTAssertFalse(loaded)
    }

    func testProviderAndNetworkErrorsDoNotReturnClassification() async {
        StoreProofURLProtocol.handler = { _ in throw URLError(.notConnectedToInternet) }
        do { _ = try await makeProof().establish(client: client(), session: session()); XCTFail("Offline server classified app") }
        catch { XCTAssertEqual((error as? URLError)?.code, .notConnectedToInternet) }
        StoreProofURLProtocol.handler = { _ in self.challenge(id: "fresh", registered: false) }
        let proof = makeProof(attest: { _, _ in throw URLError(.cannotConnectToHost) })
        do { _ = try await proof.establish(client: client(), session: session()); XCTFail("Apple error classified app") }
        catch { XCTAssertEqual((error as? URLError)?.code, .cannotConnectToHost) }
    }

    func testUnverifiedStoreKitProviderCannotReachAppAttest() async {
        let proof = StoreEnvironmentProof(defaults: defaults, dependencies: .init(
            isSupported: { true }, transaction: { throw HostedError("Unverified app transaction") },
            generateKey: { XCTFail("Unverified transaction generated key"); return "key" },
            attest: { _, _ in XCTFail("Unverified transaction attested"); return Data([1]) },
            assert: { _, _ in XCTFail("Unverified transaction asserted"); return Data([1]) }))
        do { _ = try await proof.establish(client: client(), session: session()); XCTFail("Unverified StoreKit accepted") } catch {}
    }

    func testExpiredChallengeCannotBeAttested() async {
        StoreProofURLProtocol.handler = { _ in Data(#"{"challengeId":"expired","nonce":"nonce","expiresAt":"2020-01-01T00:00:00Z","keyRegistered":false}"#.utf8) }
        let proof = makeProof(attest: { _, _ in XCTFail("Expired challenge was attested"); return Data([1]) })
        do { _ = try await proof.establish(client: client(), session: session()); XCTFail("Expired challenge accepted") } catch {}
    }

    func testUnexpectedReceiptEnvironmentFailsClosed() async {
        StoreProofURLProtocol.handler = { request in request.url!.path.hasSuffix("challenge") ? self.challenge(id: "fresh", registered: false) : self.receipt(environment: "Production") }
        do { _ = try await makeProof().establish(client: client(), session: session()); XCTFail("Mismatched environment accepted") } catch {}
    }

    func testExpiredReceiptDoesNotGrantSandboxAccess() async {
        StoreProofURLProtocol.handler = { request in
            request.url!.path.hasSuffix("challenge") ? self.challenge(id: "fresh", registered: false)
            : Data(#"{"environment":"Sandbox","expiresAt":"2020-01-01T00:00:00Z"}"#.utf8)
        }
        do { _ = try await makeProof().establish(client: client(), session: session()); XCTFail("Expired receipt accepted") } catch {}
    }

    func testKeyIdentifierPersistsAndIsScopedToAccountAndPairedDevice() async throws {
        var registeredKeys = Set<String>()
        StoreProofURLProtocol.handler = { request in
            if request.url!.path.hasSuffix("challenge") {
                let key = try XCTUnwrap(self.body(request)["keyId"] as? String)
                let registered = registeredKeys.contains(key)
                registeredKeys.insert(key)
                return self.challenge(id: UUID().uuidString, registered: registered)
            }
            return self.receipt()
        }
        var generated = 0; var assertedKeys = [String]()
        func makeInstance() -> StoreEnvironmentProof {
            makeProof(generateKey: { generated += 1; return "key-\(generated)" },
                      assert: { key, _ in assertedKeys.append(key); return Data([2]) })
        }
        _ = try await makeInstance().establish(client: client(), session: session())
        _ = try await makeInstance().establish(client: client(), session: session())
        _ = try await makeInstance().establish(client: client(), session: session(accountID: UUID()))
        _ = try await makeInstance().establish(client: client(), session: session(pairedDeviceID: "other-device"))
        XCTAssertEqual(generated, 3)
        XCTAssertEqual(assertedKeys, ["key-1"])
    }

    func testOnlyPublicAPIOriginCanReceiveAccountProof() async {
        StoreProofURLProtocol.handler = { _ in XCTFail("Account proof sent to other origin"); return self.receipt() }
        do { _ = try await makeProof().establish(client: client(origin: "https://other.example"), session: session()); XCTFail("Other origin accepted") } catch {}
    }

    private var verification: Data {
        let hex = "443da3e7f6ac3e01c63ee957111da769c2c453286d9967ca29526b64d3f9838b4d2d7611d0f43496b3a092dfe3d0d141"
        return Data(stride(from: 0, to: hex.count, by: 2).map { i in
            let start = hex.index(hex.startIndex, offsetBy: i)
            return UInt8(hex[start..<hex.index(start, offsetBy: 2)], radix: 16)!
        })
    }
    private func snapshot(verification: Data? = nil, environment: String = "Sandbox") -> StoreEnvironmentProof.VerifiedTransaction {
        .init(signedAppTransaction: "header.payload.signature", nonce: nonce,
              deviceVerificationID: deviceID, deviceVerification: verification ?? self.verification, environment: environment)
    }
    private func makeProof(verification: Data? = nil, generateKey: @escaping () async throws -> String = { "apple/key" },
                           attest: @escaping (String, Data) async throws -> Data = { _, _ in Data([1]) },
                           assert: @escaping (String, Data) async throws -> Data = { _, _ in Data([2]) }) -> StoreEnvironmentProof {
        StoreEnvironmentProof(defaults: defaults, dependencies: .init(
            isSupported: { true }, transaction: { self.snapshot(verification: verification) },
            generateKey: generateKey, attest: attest, assert: assert))
    }
    private func session(accountID: UUID? = nil, pairedDeviceID: String = "paired-device") -> HostedSession {
        .init(user: .init(id: accountID ?? self.accountID, displayName: nil), accountToken: String(repeating: "a", count: 32),
              refreshToken: String(repeating: "r", count: 32), expiresAt: "2099-01-01T00:00:00Z",
              device: .init(id: pairedDeviceID, token: String(repeating: "d", count: 32), name: "Test"), apiOrigin: "https://api.rooklayer.com")
    }
    private func client(origin: String = "https://api.rooklayer.com") -> HostedClient {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [StoreProofURLProtocol.self]
        return HostedClient(origin: URL(string: origin)!, session: URLSession(configuration: configuration))
    }
    private func challenge(id: String, registered: Bool) -> Data {
        Data("{\"challengeId\":\"\(id)\",\"nonce\":\"fresh-nonce\",\"expiresAt\":\"2099-01-01T00:00:00Z\",\"keyRegistered\":\(registered)}".utf8)
    }
    private func receipt(environment: String = "Sandbox") -> Data {
        Data("{\"environment\":\"\(environment)\",\"expiresAt\":\"2099-01-01T00:00:00Z\"}".utf8)
    }
    private func body(_ request: URLRequest) throws -> [String: Any] {
        var data = request.httpBody ?? Data()
        if data.isEmpty, let stream = request.httpBodyStream {
            stream.open(); defer { stream.close() }
            var buffer = [UInt8](repeating: 0, count: 4096)
            while stream.hasBytesAvailable {
                let count = stream.read(&buffer, maxLength: buffer.count)
                if count <= 0 { break }
                data.append(buffer, count: count)
            }
        }
        return try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
    }
}

private final class StoreProofRequests {
    private let lock = NSLock()
    private var stored = [URLRequest]()
    func add(_ request: URLRequest) { lock.lock(); defer { lock.unlock() }; stored.append(request) }
    var values: [URLRequest] { lock.lock(); defer { lock.unlock() }; return stored }
    var count: Int { values.count }
}
private final class StoreProofURLProtocol: URLProtocol {
    static var handler: ((URLRequest) throws -> Data)?
    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }
    override func startLoading() {
        do {
            let data = try Self.handler!(request)
            client?.urlProtocol(self, didReceive: HTTPURLResponse(url: request.url!, statusCode: 200, httpVersion: nil, headerFields: ["Content-Type": "application/json"])!, cacheStoragePolicy: .notAllowed)
            client?.urlProtocol(self, didLoad: data)
            client?.urlProtocolDidFinishLoading(self)
        } catch { client?.urlProtocol(self, didFailWithError: error) }
    }
    override func stopLoading() {}
}
