import XCTest
import Foundation
import AuthenticationServices
@testable import Gatekeeper

private final class AccountProtocol: URLProtocol {
    static var handler: ((URLRequest) -> (Int, Data))!
    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }
    override func startLoading() {
        let (status, data) = Self.handler(request)
        client?.urlProtocol(self, didReceive: HTTPURLResponse(url: request.url!, statusCode: status, httpVersion: nil, headerFields: nil)!, cacheStoragePolicy: .notAllowed)
        client?.urlProtocol(self, didLoad: data)
        client?.urlProtocolDidFinishLoading(self)
    }
    override func stopLoading() {}
}
@MainActor final class HostedAccountTests: XCTestCase {
    private let user = UUID(uuidString: "12345678-1234-1234-1234-123456789ABC")!
    private let origin = URL(string: "https://api.example.com")!
    private func saved(expired: Bool = false, suffix: String = "old") -> HostedSession {
        HostedSession(user: HostedUser(id: user, displayName: nil), accountToken: String(repeating: "a", count: 32) + suffix,
            refreshToken: String(repeating: "r", count: 32) + suffix,
            expiresAt: expired ? "2000-01-01T00:00:00Z" : "2099-01-01T00:00:00Z",
            device: HostedDeviceCredential(id: "phone", token: String(repeating: "d", count: 32) + suffix, name: "iPhone"), apiOrigin: origin.absoluteString)
    }
    private func client() -> HostedClient {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [AccountProtocol.self]
        return HostedClient(origin: origin, session: URLSession(configuration: configuration))
    }
    private func reply(_ request: URLRequest) -> (Int, Data) {
        switch request.url!.path {
        case "/v1/account": return (200, Data(#"{"user":{"id":"12345678-1234-1234-1234-123456789ABC"},"devices":[],"aiConsentVersion":"2026-10-08","entitlement":{"active":false,"betaAccess":true}}"#.utf8))
        case "/v1/conversation": return (200, Data(#"{"messages":[]}"#.utf8))
        case "/v1/billing/products": return (200, Data(#"{"productIds":[],"betaAccess":true}"#.utf8))
        case "/v1/agents": return (200, Data(#"{"connections":[]}"#.utf8))
        default: return (404, Data(#"{"error":"Missing endpoint","code":"not_found"}"#.utf8))
        }
    }
    func testConcurrentExpiredSessionsRotateOnceAndPersistWholeSession() async throws {
        let lock = NSLock()
        var refreshes = 0
        var persisted: [HostedSession] = []
        let rotated = saved(suffix: "new")
        let rotatedData = try JSONEncoder().encode(rotated)
        AccountProtocol.handler = { [self] request in
            if request.url?.path == "/v1/auth/refresh" {
                lock.lock(); refreshes += 1; lock.unlock()
                Thread.sleep(forTimeInterval: 0.05)
                return (200, rotatedData)
            }
            return reply(request)
        }
        let account = HostedAccount(origin: origin, session: saved(expired: true), client: client(), persist: { persisted.append($0) }, clear: {})
        async let first: Void = account.reload()
        async let second: Void = account.reload()
        _ = await (first, second)
        XCTAssertEqual(refreshes, 1)
        XCTAssertEqual(persisted.count, 1)
        XCTAssertEqual(account.session?.accountToken, rotated.accountToken)
        XCTAssertEqual(persisted.first?.refreshToken, rotated.refreshToken)
        XCTAssertEqual(persisted.first?.device.token, rotated.device.token)
        XCTAssertNil(account.error)
    }
    func test401AccountRotatesAndRetriesWithNewAccountCredential() async throws {
        let rotated = saved(suffix: "new")
        let rotatedData = try JSONEncoder().encode(rotated)
        let original = saved()
        var refreshes = 0
        AccountProtocol.handler = { [self] request in
            if request.url?.path == "/v1/auth/refresh" { refreshes += 1; return (200, rotatedData) }
            if request.value(forHTTPHeaderField: "Authorization") == "Bearer \(original.accountToken)" {
                return (401, Data(#"{"error":"Expired","code":"unauthorized"}"#.utf8))
            }
            XCTAssertEqual(request.value(forHTTPHeaderField: "Authorization"), "Bearer \(rotated.accountToken)")
            return reply(request)
        }
        let account = HostedAccount(origin: origin, session: original, client: client(), persist: { _ in }, clear: {})
        await account.reload()
        XCTAssertEqual(refreshes, 1)
        XCTAssertEqual(account.session?.accountToken, rotated.accountToken)
        XCTAssertNil(account.error)
    }
    func testRevokedRefreshClearsSessionAndFailsClosed() async {
        var cleared = false
        AccountProtocol.handler = { _ in (401, Data(#"{"error":"Refresh revoked","code":"unauthorized"}"#.utf8)) }
        let account = HostedAccount(origin: origin, session: saved(expired: true), client: client(), persist: { _ in XCTFail("Should not persist revoked session") }, clear: { cleared = true })
        await account.reload()
        XCTAssertTrue(cleared)
        XCTAssertNil(account.session)
        XCTAssertNotNil(account.error)
        XCTAssertFalse(account.hasAccess)
    }
    func testProviderUnavailableNeverBecomesApprovalAndPreservesDraft() async {
        AccountProtocol.handler = { [self] request in
            if request.url?.path == "/v1/conversation", request.httpMethod == "POST" {
                return (503, Data(#"{"error":"Muse is unavailable. Apps remain blocked.","code":"ai_unavailable"}"#.utf8))
            }
            return reply(request)
        }
        let account = HostedAccount(origin: origin, session: saved(), client: client(), persist: { _ in }, clear: {})
        await account.reload()
        XCTAssertTrue(account.hasConsent)
        XCTAssertTrue(account.hasAccess)
        let sent = await account.send("Reply to Alex and leave once sent", minutes: 5)
        XCTAssertFalse(sent)
        XCTAssertFalse(account.approvalPending)
        XCTAssertTrue(account.messages.isEmpty)
        XCTAssertEqual(account.error, "Muse is unavailable. Apps remain blocked.")
    }
    func testWithdrawnConsentBlocksFurtherConversation() async {
        var withdrawn = false
        var conversations = 0
        AccountProtocol.handler = { [self] request in
            if request.url?.path == "/v1/account/consent", request.httpMethod == "DELETE" {
                withdrawn = true
                return (200, Data(#"{"received":true}"#.utf8))
            }
            if request.url?.path == "/v1/account", withdrawn {
                return (200, Data(#"{"user":{"id":"12345678-1234-1234-1234-123456789ABC"},"devices":[],"aiConsentVersion":null,"entitlement":{"active":false,"betaAccess":true}}"#.utf8))
            }
            if request.url?.path == "/v1/conversation", request.httpMethod == "POST" { conversations += 1 }
            return reply(request)
        }
        let account = HostedAccount(origin: origin, session: saved(), client: client(), persist: { _ in }, clear: {})
        await account.reload()
        XCTAssertTrue(account.hasConsent)
        await account.withdrawConsent()
        XCTAssertFalse(account.hasConsent)
        let sent = await account.send("Do a small task then leave", minutes: 5)
        XCTAssertFalse(sent)
        XCTAssertEqual(conversations, 0)
    }
    func testLocalhostAgentApprovalStaysOnPhoneWithReturnInstruction() async {
        AccountProtocol.handler = { [self] request in
            if request.url!.path.hasSuffix("/decision") {
                return (200, Data(#"{"redirectURL":"http://127.0.0.1:8765/callback?code=one-use-code","requiresOriginalBrowser":true}"#.utf8))
            }
            return reply(request)
        }
        let account = HostedAccount(origin: origin, session: saved(), client: client(), persist: { _ in }, clear: {})
        account.agentRequest = AgentAuthorizationRequest(id: UUID().uuidString, clientName: "Trusted agent", redirectURI: "http://127.0.0.1:8765/callback", scopes: ["gatekeeper:approve"])
        let callback = await account.decideAgent(approve: true)
        XCTAssertNil(callback, "Never open a desktop loopback callback on the phone")
        XCTAssertNotNil(account.agentRequest, "Keep the confirmation visible until Done")
        XCTAssertEqual(account.agentReturnNotice, "Approved. Return to your agent on the device where you started connecting.")
    }

    func testEndAccessNotifiesServerEvenDuringAnotherOperation() async {
        var localClosed = false
        var notified = false
        AccountProtocol.handler = { request in
            XCTAssertEqual(request.url?.path, "/v1/access/end")
            XCTAssertEqual(request.httpMethod, "POST")
            notified = true
            return (200, Data(#"{"status":"end_requested"}"#.utf8))
        }
        let account = HostedAccount(origin: origin, session: saved(), client: client(), persist: { _ in }, clear: {}, closeProtection: { localClosed = true })
        account.busy = true
        await account.endAccess()
        XCTAssertTrue(localClosed)
        XCTAssertTrue(notified)
        XCTAssertTrue(account.busy, "Ending access should not clear another operation's busy state")
        XCTAssertFalse(account.approvalPending)
    }

    func testAppleRevocationDuringRefreshCannotReinstallSession() async throws {
        var persisted = 0; var cleared = 0
        let gate = AppleCredentialGate(loadIdentifier: { "opaque.apple.user" }, clearCredentials: { cleared += 1 }, closeProtection: {}, check: { _ in .authorized })
        let rotatedData = try JSONEncoder().encode(saved(suffix: "new"))
        AccountProtocol.handler = { [self] request in
            if request.url?.path == "/v1/auth/refresh" {
                Task { @MainActor in gate.credentialRevoked() }
                Thread.sleep(forTimeInterval: 0.05)
                return (200, rotatedData)
            }
            return reply(request)
        }
        let account = HostedAccount(origin: origin, session: saved(expired: true), client: client(), persist: { _ in persisted += 1 }, clear: {}, appleGate: gate)
        await account.reload()
        XCTAssertEqual(persisted, 0, "A response issued before revocation must never restore credentials")
        XCTAssertNil(account.session)
        XCTAssertFalse(account.hasAccess)
        XCTAssertEqual(cleared, 1)
    }
    func testRefreshCannotChangeAccountIdentity() async throws {
        var cleared = false
        let changed = HostedSession(user: HostedUser(id: UUID(), displayName: nil), accountToken: String(repeating: "a", count: 32), refreshToken: String(repeating: "r", count: 32), expiresAt: "2099-01-01T00:00:00Z", device: saved().device, apiOrigin: origin.absoluteString)
        let data = try JSONEncoder().encode(changed)
        AccountProtocol.handler = { _ in (200, data) }
        let account = HostedAccount(origin: origin, session: saved(expired: true), client: client(), persist: { _ in XCTFail("Must reject changed identity") }, clear: { cleared = true })
        await account.reload()
        XCTAssertTrue(cleared)
        XCTAssertNil(account.session)
        XCTAssertFalse(account.hasAccess)
    }
    func testMaliciousAgentCallbackIsNeverOpened() async {
        for redirect in ["javascript:alert(1)", "https://evil.example/callback", "https://attacker:secret@trusted.example/callback", "https://trusted.example/callback#payload"] {
            AccountProtocol.handler = { _ in (200, try! JSONSerialization.data(withJSONObject: ["redirectURL": redirect])) }
            let account = HostedAccount(origin: origin, session: saved(), client: client(), persist: { _ in }, clear: {})
            account.agentRequest = AgentAuthorizationRequest(id: UUID().uuidString, clientName: "Agent", redirectURI: "https://trusted.example/callback", scopes: ["gatekeeper:status"])
            let callback = await account.decideAgent(approve: true)
            XCTAssertNil(callback)
            XCTAssertNotNil(account.error)
        }
    }

}
