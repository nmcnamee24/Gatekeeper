import XCTest
import AuthenticationServices
@testable import Gatekeeper

@MainActor final class AppleCredentialGateTests: XCTestCase {
    func testRevokedNotFoundAndTransferredClearCredentialsAndRelock() async {
        for state in [ASAuthorizationAppleIDProvider.CredentialState.revoked, .notFound, .transferred] {
            var clears = 0; var closes = 0
            let gate = AppleCredentialGate(loadIdentifier: { "opaque.apple.user" }, clearCredentials: { clears += 1 }, closeProtection: { closes += 1 }, check: { _ in state })
            do { try await gate.requireAuthorization(); XCTFail("Invalid Apple state was authorized") } catch {}
            XCTAssertFalse(gate.authorized)
            XCTAssertEqual(clears, 1)
            XCTAssertEqual(closes, 1)
            XCTAssertNotNil(gate.message)
            // Definitive sign-out cannot be undone by a later cached Apple response.
            do { try await gate.requireAuthorization(); XCTFail("Sign-in required") } catch {}
            XCTAssertEqual(clears, 1)
        }
    }
    func testNetworkFailureRetainsCredentialsButBlocksUntilVerified() async throws {
        var fail = true; var clears = 0; var closes = 0
        let gate = AppleCredentialGate(loadIdentifier: { "opaque.apple.user" }, clearCredentials: { clears += 1 }, closeProtection: { closes += 1 }, check: { _ in
            if fail { throw URLError(.notConnectedToInternet) }
            return .authorized
        })
        do { try await gate.requireAuthorization(); XCTFail("Offline verification authorized") } catch {}
        XCTAssertFalse(gate.authorized)
        XCTAssertEqual(clears, 0)
        XCTAssertEqual(closes, 0)
        XCTAssertFalse(gate.message?.contains("revoked") ?? true)
        fail = false
        try await gate.requireAuthorization(force: true)
        XCTAssertTrue(gate.authorized)
        XCTAssertNil(gate.message)
    }
    func testTransientFailurePreservesRunningPassButDefinitiveRevocationClosesIt() async {
        var expiry: Date? = Date().addingTimeInterval(900)
        let approvedEnd = expiry
        let gate = AppleCredentialGate(loadIdentifier: { "opaque.apple.user" }, clearCredentials: {}, closeProtection: { expiry = nil }, check: { _ in
            throw URLError(.notConnectedToInternet)
        })
        gate.recordSuccessfulSignIn(identifier: "opaque.apple.user")
        do { try await gate.requireAuthorization(force: true); XCTFail("New access requires verification") } catch {}
        XCTAssertFalse(gate.authorized)
        XCTAssertEqual(expiry, approvedEnd)
        gate.credentialRevoked()
        XCTAssertNil(expiry)
        XCTAssertFalse(gate.authorized)
    }
    func testConcurrentAppleChecksShareOneProviderOperation() async throws {
        var checks = 0
        let gate = AppleCredentialGate(loadIdentifier: { "opaque.apple.user" }, clearCredentials: {}, closeProtection: {}, check: { _ in
            checks += 1
            try await Task.sleep(for: .milliseconds(30))
            return .authorized
        })
        async let first: Void = gate.requireAuthorization(force: true)
        async let second: Void = gate.requireAuthorization(force: true)
        _ = try await (first, second)
        XCTAssertEqual(checks, 1)
        XCTAssertTrue(gate.authorized)
    }
    func testRevocationNotificationDefeatsInFlightAuthorizedResponse() async {
        var callback: CheckedContinuation<ASAuthorizationAppleIDProvider.CredentialState, Error>?
        var clears = 0
        let gate = AppleCredentialGate(loadIdentifier: { "opaque.apple.user" }, clearCredentials: { clears += 1 }, closeProtection: {}, check: { _ in
            try await withCheckedThrowingContinuation { callback = $0 }
        })
        let pending = Task { try? await gate.requireAuthorization() }
        for _ in 0..<100 where callback == nil { await Task.yield() }
        XCTAssertNotNil(callback)
        gate.credentialRevoked()
        callback?.resume(returning: .authorized)
        await pending.value
        XCTAssertFalse(gate.authorized)
        XCTAssertEqual(clears, 1)
        XCTAssertTrue(gate.message?.contains("revoked") ?? false)
    }
    func testMissingPrivateIdentifierRequiresFreshSignIn() async {
        var checks = 0; var clears = 0
        let gate = AppleCredentialGate(loadIdentifier: { nil }, clearCredentials: { clears += 1 }, closeProtection: {}, check: { _ in checks += 1; return .authorized })
        do { try await gate.requireAuthorization(); XCTFail("Missing Apple ID authorized") } catch {}
        XCTAssertFalse(gate.authorized)
        XCTAssertEqual(checks, 0)
        XCTAssertEqual(clears, 1)
        XCTAssertTrue(gate.message?.contains("Sign in with Apple again") ?? false)
    }
    func testAppleRevokedNotificationTriggersImmediateSignOutGate() {
        var cleared = false; var closed = false
        let gate = AppleCredentialGate(loadIdentifier: { "opaque.apple.user" }, clearCredentials: { cleared = true }, closeProtection: { closed = true }, check: { _ in .authorized }, observeNotifications: true)
        gate.recordSuccessfulSignIn(identifier: "opaque.apple.user")
        XCTAssertTrue(gate.authorized)
        NotificationCenter.default.post(name: ASAuthorizationAppleIDProvider.credentialRevokedNotification, object: nil)
        XCTAssertFalse(gate.authorized)
        XCTAssertTrue(cleared)
        XCTAssertTrue(closed)
    }

}
