import XCTest
import Foundation
import AuthenticationServices
import FamilyControls
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

@MainActor final class PushRegistrationTests: XCTestCase {
    private func registrationFailure(_ bridge: BackgroundBridge, afterSync: Bool) async -> Error? {
        let savedToken = UserDefaults.standard.object(forKey: "apnsToken")
        UserDefaults.standard.set(String(repeating: "a", count: 64), forKey: "apnsToken")
        defer {
            if let savedToken { UserDefaults.standard.set(savedToken, forKey: "apnsToken") }
            else { UserDefaults.standard.removeObject(forKey: "apnsToken") }
        }
        do {
            if afterSync { try await bridge.sync() }
            try await bridge.registerToken()
            XCTFail("Expected push registration to fail")
            return nil
        } catch { return error }
    }
    nonisolated private func state() -> [String: Any] {
        ["pendingGrantId": NSNull(), "lastGrantId": "prior-grant", "lastGrantRevoked": false]
    }
    func testCurrentPush401RelocksAfterSuccessfulSyncAndDirectCallback() async throws {
        for afterSync in [true, false] {
            let fixture = try BridgeFixture(open: true)
            let approvedEnd = fixture.lastWindowEnd
            let grantedAt = fixture.lastGrant
            let bearer = fixture.configuration!.token
            var paths: [String] = []
            BridgeProtocol.handler = { [self] transport, request in
                Task { @MainActor in
                    let path = request.url!.path
                    paths.append(path)
                    switch path {
                    case "/device/state": transport.reply(200, state())
                    case "/device/report": transport.reply(200, ["received": true])
                    default:
                        XCTAssertEqual(path, "/device/push")
                        XCTAssertEqual(request.httpMethod, "POST")
                        XCTAssertEqual(request.value(forHTTPHeaderField: "Authorization"), "Bearer \(bearer)")
                        transport.reply(401, ["error": "Device revoked", "code": "unauthorized"])
                    }
                }
            }
            let error = await registrationFailure(fixture.bridge(), afterSync: afterSync)
            XCTAssertEqual((error as? ConnectorError)?.statusCode, 401)
            XCTAssertEqual(paths, afterSync ? ["/device/state", "/device/report", "/device/push"] : ["/device/push"])
            XCTAssertNil(fixture.expiry)
            XCTAssertEqual(fixture.closeCalls, 1)
            XCTAssertEqual(fixture.lastWindowEnd, approvedEnd)
            XCTAssertEqual(fixture.lastGrant, grantedAt)
        }
    }
    func testStalePush401PreservesRotatedCredentialsAccountBindingAndSwitchedSetup() async throws {
        for afterSync in [true, false] {
            for change in ["device", "account", "setup"] {
                let fixture = try BridgeFixture(open: true)
                let newEnd = Date().addingTimeInterval(400)
                BridgeProtocol.handler = { [self] transport, request in
                    Task { @MainActor in
                        switch request.url!.path {
                        case "/device/state": transport.reply(200, state())
                        case "/device/report": transport.reply(200, ["received": true])
                        default:
                            XCTAssertEqual(request.url!.path, "/device/push")
                            let old = fixture.configuration!
                            if change == "account" {
                                // Atomic account persistence can precede its separate connector write.
                                fixture.accountToken = String(repeating: "r", count: 64)
                            } else {
                                fixture.configuration = try! BridgeConfiguration(address: change == "setup" ? "https://personal.example.com" : old.baseURL.absoluteString,
                                    token: change == "setup" ? old.token : String(repeating: "r", count: 64), hosted: change != "setup")
                                fixture.accountToken = fixture.configuration!.token
                            }
                            fixture.expiry = newEnd
                            fixture.lastWindowEnd = newEnd
                            transport.reply(401, ["error": "Old device credential revoked"])
                        }
                    }
                }
                let error = await registrationFailure(fixture.bridge(), afterSync: afterSync)
                XCTAssertEqual((error as? ConnectorError)?.statusCode, 401)
                XCTAssertEqual(fixture.expiry, newEnd, "A stale push response must not close \(change) replacement access")
                XCTAssertEqual(fixture.lastWindowEnd, newEnd)
                XCTAssertEqual(fixture.closeCalls, 0)
            }
        }
    }
    func testPushNetworkAndNon401FailuresPreserveOfflineWindow() async throws {
        for afterSync in [true, false] {
            for status in [0, 500, 503, 429, 403] {
                let fixture = try BridgeFixture(open: true)
                let expiry = fixture.expiry
                let approvedEnd = fixture.lastWindowEnd
                BridgeProtocol.handler = { [self] transport, request in
                    switch request.url!.path {
                    case "/device/state": transport.reply(200, state())
                    case "/device/report": transport.reply(200, ["received": true])
                    default:
                        XCTAssertEqual(request.url!.path, "/device/push")
                        if status == 0 { transport.fail() }
                        else { transport.reply(status, ["error": "Temporary service failure"]) }
                    }
                }
                let error = await registrationFailure(fixture.bridge(), afterSync: afterSync)
                if status == 0 { XCTAssertEqual((error as? URLError)?.code, .notConnectedToInternet) }
                else { XCTAssertEqual((error as? ConnectorError)?.statusCode, status) }
                XCTAssertEqual(fixture.expiry, expiry)
                XCTAssertEqual(fixture.lastWindowEnd, approvedEnd)
                XCTAssertEqual(fixture.closeCalls, 0, "HTTP \(status) must not imply revoked device credentials")
            }
        }
    }
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
        case "/v1/account": return (200, Data(#"{"user":{"id":"12345678-1234-1234-1234-123456789ABC"},"devices":[],"aiConsentVersion":"2026-10-08-openai-v1","entitlement":{"active":false,"betaAccess":true}}"#.utf8))
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

private final class BridgeProtocol: URLProtocol {
    static var handler: ((BridgeProtocol, URLRequest) -> Void)!
    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }
    override func startLoading() { Self.handler(self, request) }
    override func stopLoading() {}
    func reply(_ status: Int, _ object: [String: Any]) {
        let data = try! JSONSerialization.data(withJSONObject: object)
        client?.urlProtocol(self, didReceive: HTTPURLResponse(url: request.url!, statusCode: status, httpVersion: nil, headerFields: nil)!, cacheStoragePolicy: .notAllowed)
        client?.urlProtocol(self, didLoad: data)
        client?.urlProtocolDidFinishLoading(self)
    }
    func fail() { client?.urlProtocol(self, didFailWithError: URLError(.notConnectedToInternet)) }
}
@MainActor private final class BridgeFixture {
    var configuration: BridgeConfiguration?
    var accountToken: String?
    var expiry: Date?
    var lastGrant: Date?
    var lastWindowEnd: Date?
    var remoteGrantId: String?
    var closeCalls = 0
    var grantCalls = 0
    let session: URLSession
    init(open: Bool) throws {
        configuration = try BridgeConfiguration(address: "https://api.example.com", token: String(repeating: "d", count: 64), hosted: true)
        accountToken = configuration!.token
        expiry = open ? Date().addingTimeInterval(300) : nil
        lastGrant = open ? Date().addingTimeInterval(-10) : nil
        lastWindowEnd = expiry
        remoteGrantId = open ? "prior-grant" : nil
        let config = URLSessionConfiguration.ephemeral
        config.protocolClasses = [BridgeProtocol.self]
        session = URLSession(configuration: config)
    }
    func bridge() -> BackgroundBridge {
        BackgroundBridge(environment: .init(configuration: { self.configuration }, requireApple: { _ in }, matchesAccount: { $0.hosted != true || self.accountToken == $0.token }, validateHosted: { _ in }, localState: {
            BackgroundBridge.LocalState(authorized: true, selected: true, selection: FamilyActivitySelection(), expiry: self.expiry,
                lastGrant: self.lastGrant, lastWindowEnd: self.lastWindowEnd, remoteGrantId: self.remoteGrantId)
        }, reconcile: {}, close: { self.closeCalls += 1; self.expiry = nil }, grant: { end, id in
            self.grantCalls += 1; self.expiry = end; self.lastGrant = Date(); self.lastWindowEnd = end; self.remoteGrantId = id
        }, client: { ConnectorClient(configuration: $0, session: self.session) }))
    }
}
@MainActor final class BackgroundBridgeTests: XCTestCase {
    nonisolated private func state(pending: Bool = false) -> [String: Any] {
        ["pendingGrantId": pending ? "new-grant" : NSNull(), "lastGrantId": pending ? NSNull() : "new-grant", "lastGrantRevoked": false]
    }
    private func syncFailure(_ bridge: BackgroundBridge) async -> Error? {
        do { try await bridge.sync(); XCTFail("Expected the transport failure"); return nil } catch { return error }
    }
    func testConnectorPreserves401StatusAndServiceCode() async throws {
        let fixture = try BridgeFixture(open: true)
        let bearer = fixture.configuration!.token
        BridgeProtocol.handler = { transport, request in
            XCTAssertEqual(request.value(forHTTPHeaderField: "Authorization"), "Bearer \(bearer)")
            transport.reply(401, ["error": "Device credential revoked", "code": "unauthorized"])
        }
        do {
            _ = try await ConnectorClient(configuration: fixture.configuration!, session: fixture.session).state()
            XCTFail("Expected 401")
        } catch let error as ConnectorError {
            XCTAssertEqual(error.statusCode, 401)
            XCTAssertEqual(error.serviceCode, "unauthorized")
            XCTAssertEqual(error.localizedDescription, "Device credential revoked")
        }
    }
    func testState401ImmediatelyRelocksAnOpenWindowWithoutClearingCooldown() async throws {
        let fixture = try BridgeFixture(open: true)
        let approvedEnd = fixture.lastWindowEnd
        let grantedAt = fixture.lastGrant
        BridgeProtocol.handler = { transport, _ in transport.reply(401, ["error": "Revoked", "code": "unauthorized"]) }
        _ = await syncFailure(fixture.bridge())
        XCTAssertNil(fixture.expiry)
        XCTAssertEqual(fixture.closeCalls, 1)
        XCTAssertEqual(fixture.lastWindowEnd, approvedEnd)
        XCTAssertEqual(fixture.lastGrant, grantedAt)
    }
    func testReport401RelocksAnExistingWindow() async throws {
        let fixture = try BridgeFixture(open: true)
        let approvedEnd = fixture.lastWindowEnd
        BridgeProtocol.handler = { [self] transport, request in
            if request.url!.path == "/device/state" { transport.reply(200, state()) }
            else { XCTAssertEqual(request.url!.path, "/device/report"); transport.reply(401, ["error": "Revoked"]) }
        }
        _ = await syncFailure(fixture.bridge())
        XCTAssertNil(fixture.expiry)
        XCTAssertEqual(fixture.closeCalls, 1)
        XCTAssertEqual(fixture.lastWindowEnd, approvedEnd)
    }
    func testRedeem401KeepsProtectionClosed() async throws {
        let fixture = try BridgeFixture(open: false)
        BridgeProtocol.handler = { [self] transport, request in
            if request.url!.path == "/device/state" { transport.reply(200, state(pending: true)) }
            else { XCTAssertEqual(request.url!.path, "/device/redeem"); transport.reply(401, ["error": "Revoked"]) }
        }
        _ = await syncFailure(fixture.bridge())
        XCTAssertNil(fixture.expiry)
        XCTAssertEqual(fixture.grantCalls, 0)
        XCTAssertEqual(fixture.closeCalls, 1)
    }
    func testReport401AfterGrantRelocksNewWindowAndRetainsApprovedEnd() async throws {
        let fixture = try BridgeFixture(open: false)
        let formatter = ISO8601DateFormatter(); formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        let end = Date().addingTimeInterval(50)
        let encodedEnd = formatter.string(from: end)
        let parsedEnd = formatter.date(from: encodedEnd)!
        var stateReads = 0
        BridgeProtocol.handler = { [self] transport, request in
            Task { @MainActor in
                switch request.url!.path {
                case "/device/state": stateReads += 1; transport.reply(200, state(pending: stateReads == 1))
                case "/device/redeem": transport.reply(200, ["grantId": "new-grant", "windowSeconds": 60, "endsAt": encodedEnd])
                default: XCTAssertEqual(request.url!.path, "/device/report"); transport.reply(401, ["error": "Revoked"])
                }
            }
        }
        _ = await syncFailure(fixture.bridge())
        XCTAssertEqual(fixture.grantCalls, 1)
        XCTAssertEqual(fixture.closeCalls, 1)
        XCTAssertNil(fixture.expiry)
        XCTAssertEqual(fixture.lastWindowEnd, parsedEnd)
    }
    func testStale401CannotCloseRotatedOrSwitchedConnectionAtAnyEndpoint() async throws {
        for endpoint in ["/device/state", "/device/redeem", "/device/report"] {
            for switchOrigin in [false, true] {
                let fixture = try BridgeFixture(open: endpoint != "/device/redeem")
                let newEnd = Date().addingTimeInterval(200)
                BridgeProtocol.handler = { [self] transport, request in
                    Task { @MainActor in
                        if request.url!.path == endpoint {
                            let old = fixture.configuration!
                            fixture.configuration = try! BridgeConfiguration(address: switchOrigin ? "https://personal.example.com" : old.baseURL.absoluteString,
                                token: switchOrigin ? old.token : String(repeating: "r", count: 64), hosted: !switchOrigin)
                            fixture.accountToken = fixture.configuration!.token
                            fixture.expiry = newEnd
                            transport.reply(401, ["error": "Old credential revoked"])
                        } else { transport.reply(200, state(pending: endpoint == "/device/redeem")) }
                    }
                }
                _ = await syncFailure(fixture.bridge())
                XCTAssertEqual(fixture.expiry, newEnd, "Stale \(endpoint) 401 must not affect the replacement setup")
                XCTAssertEqual(fixture.closeCalls, 0)
            }
        }
    }
    func testNetworkAndServerFailuresPreserveValidOfflineTimer() async throws {
        for endpoint in ["/device/state", "/device/report"] {
            for status in [0, 500, 503, 429, 403] {
                let fixture = try BridgeFixture(open: true)
                let expiry = fixture.expiry
                let approvedEnd = fixture.lastWindowEnd
                BridgeProtocol.handler = { [self] transport, request in
                    if request.url!.path == endpoint {
                        if status == 0 { transport.fail() }
                        else { transport.reply(status, ["error": "Temporary service failure"]) }
                    } else { transport.reply(200, state()) }
                }
                _ = await syncFailure(fixture.bridge())
                XCTAssertEqual(fixture.expiry, expiry)
                XCTAssertEqual(fixture.lastWindowEnd, approvedEnd)
                XCTAssertEqual(fixture.closeCalls, 0, "HTTP \(status) must not be treated as device revocation")
            }
        }
    }
    func testStale401CannotCloseWindowWhenAccountRotatedBeforeConnectorWrite() async throws {
        let fixture = try BridgeFixture(open: true)
        let newEnd = Date().addingTimeInterval(200)
        BridgeProtocol.handler = { transport, _ in
            Task { @MainActor in
                // Account/session persistence is atomic; the separate device Keychain
                // write can lag or fail. The old connector must not revoke this setup.
                fixture.accountToken = String(repeating: "r", count: 64)
                fixture.expiry = newEnd
                transport.reply(401, ["error": "Old device credential revoked"])
            }
        }
        _ = await syncFailure(fixture.bridge())
        XCTAssertEqual(fixture.expiry, newEnd)
        XCTAssertEqual(fixture.closeCalls, 0)
    }

    nonisolated private func reportBody(_ request: URLRequest) throws -> [String: Any] {
        var data = request.httpBody ?? Data()
        if let stream = request.httpBodyStream {
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
    func testForeignPersistedGrantDoesNotBreakReportingAfterConnectionTransition() async throws {
        let cases: [(String, String?)] = [("personal-server-grant", nil),
            ("previous-account-grant", "current-account-grant"), ("previous-device-grant", "current-device-grant")]
        for open in [false, true] {
            for (foreignID, ownedID) in cases {
                let fixture = try BridgeFixture(open: open)
                fixture.remoteGrantId = foreignID
                let expiry = fixture.expiry
                let grantedAt = fixture.lastGrant
                let approvedEnd = fixture.lastWindowEnd
                var report: [String: Any]?
                BridgeProtocol.handler = { [self] transport, request in
                    Task { @MainActor in
                        if request.url!.path == "/device/state" {
                            // The new scope either has no grants or has a different owned grant.
                            transport.reply(200, ["pendingGrantId": NSNull(), "lastGrantId": ownedID.map { $0 as Any } ?? NSNull(), "lastGrantRevoked": false])
                        } else {
                            XCTAssertEqual(request.url!.path, "/device/report")
                            report = try! reportBody(request)
                            // Mirror the server's user/device grant-ownership check.
                            if report?["grantId"] != nil { transport.reply(404, ["error": "Grant was not found.", "code": "not_found"]) }
                            else { transport.reply(200, ["received": true]) }
                        }
                    }
                }
                do { try await fixture.bridge().sync() }
                catch { XCTFail("An old \(foreignID) must not cause sync to fail: \(error)") }
                XCTAssertNotNil(report)
                XCTAssertNil(report?["grantId"])
                XCTAssertEqual(report?["state"] as? String, open ? "window_open" : "shielded")
                XCTAssertEqual(fixture.expiry, expiry)
                XCTAssertEqual(fixture.lastGrant, grantedAt)
                XCTAssertEqual(fixture.lastWindowEnd, approvedEnd)
                XCTAssertEqual(fixture.closeCalls, 0)
                XCTAssertEqual(fixture.grantCalls, 0)
            }
        }
    }
    func testOwnedActiveGrantStillReportsAfterSameAccountCredentialRotation() async throws {
        let fixture = try BridgeFixture(open: true)
        fixture.configuration = try BridgeConfiguration(address: "https://api.example.com", token: String(repeating: "r", count: 64), hosted: true)
        fixture.accountToken = fixture.configuration!.token
        let expiry = fixture.expiry
        let approvedEnd = fixture.lastWindowEnd
        let grantedAt = fixture.lastGrant
        var report: [String: Any]?
        BridgeProtocol.handler = { [self] transport, request in
            Task { @MainActor in
                if request.url!.path == "/device/state" {
                    transport.reply(200, ["pendingGrantId": NSNull(), "lastGrantId": "prior-grant", "lastGrantRevoked": false])
                } else {
                    XCTAssertEqual(request.url!.path, "/device/report")
                    report = try! reportBody(request)
                    transport.reply(200, ["received": true])
                }
            }
        }
        try await fixture.bridge().sync()
        XCTAssertEqual(report?["grantId"] as? String, "prior-grant")
        XCTAssertEqual(report?["state"] as? String, "window_open")
        XCTAssertEqual(report?["localExpiry"] as? String, ISO8601DateFormatter().string(from: expiry!))
        XCTAssertEqual(fixture.expiry, expiry)
        XCTAssertEqual(fixture.lastWindowEnd, approvedEnd)
        XCTAssertEqual(fixture.lastGrant, grantedAt)
        XCTAssertEqual(fixture.closeCalls, 0)
    }
    func testRedeemedGrantReportUsesPostRedemptionOwnershipCheck() async throws {
        let fixture = try BridgeFixture(open: false)
        fixture.remoteGrantId = "previous-account-grant"
        let formatter = ISO8601DateFormatter(); formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        let end = formatter.string(from: Date().addingTimeInterval(50))
        var stateReads = 0
        var report: [String: Any]?
        BridgeProtocol.handler = { [self] transport, request in
            Task { @MainActor in
                switch request.url!.path {
                case "/device/state":
                    stateReads += 1
                    transport.reply(200, state(pending: stateReads == 1))
                case "/device/redeem": transport.reply(200, ["grantId": "new-grant", "windowSeconds": 60, "endsAt": end])
                default:
                    XCTAssertEqual(request.url!.path, "/device/report")
                    report = try! reportBody(request)
                    transport.reply(200, ["received": true])
                }
            }
        }
        try await fixture.bridge().sync()
        XCTAssertEqual(report?["grantId"] as? String, "new-grant")
        XCTAssertEqual(report?["state"] as? String, "window_open")
        XCTAssertEqual(stateReads, 2)
        XCTAssertEqual(fixture.grantCalls, 1)
        XCTAssertEqual(fixture.closeCalls, 0)
    }

}
