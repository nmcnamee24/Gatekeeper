import Foundation
import SwiftUI
import Security
import CryptoKit
import AuthenticationServices
import StoreKit
import UIKit

// The Apple identifier and complete rotating session share one atomic Keychain item.
// Neither is written to preferences, app-group storage, logs, or external-agent JSON.
enum AccountKeychain {
    private struct StoredAccount: Codable { let session: HostedSession; let appleIdentifier: String? }
    private static let query: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: "com.noah.gatekeeper.account", kSecAttrAccount as String: "hosted-session"]
    private static func data() throws -> Data? {
        var lookup = query; lookup[kSecReturnData as String] = true; lookup[kSecMatchLimit as String] = kSecMatchLimitOne
        var result: CFTypeRef?
        let status = SecItemCopyMatching(lookup as CFDictionary, &result)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess, let data = result as? Data else { throw HostedError("Your secure account session could not be read.") }
        return data
    }
    static func load() throws -> HostedSession? {
        guard let data = try data() else { return nil }
        if let stored = try? JSONDecoder().decode(StoredAccount.self, from: data) { return stored.session }
        return try JSONDecoder().decode(HostedSession.self, from: data)
    }
    static func loadAppleIdentifier() throws -> String? {
        guard let data = try data() else { return nil }
        // Older sessions without the identifier require a fresh native Apple sign-in.
        return try? JSONDecoder().decode(StoredAccount.self, from: data).appleIdentifier
    }
    static func save(_ session: HostedSession, appleIdentifier: String? = nil) throws {
        let identifier = try appleIdentifier ?? loadAppleIdentifier()
        guard let identifier, !identifier.isEmpty, identifier.count <= 512 else {
            throw HostedError("Sign in with Apple again before saving this account session.")
        }
        let data = try JSONEncoder().encode(StoredAccount(session: session, appleIdentifier: identifier))
        let status = SecItemUpdate(query as CFDictionary, [kSecValueData as String: data] as CFDictionary)
        if status == errSecSuccess { return }
        guard status == errSecItemNotFound else { throw HostedError("Your secure account session could not be updated.") }
        var item = query; item[kSecValueData as String] = data
        item[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        guard SecItemAdd(item as CFDictionary, nil) == errSecSuccess else { throw HostedError("Your account session could not be saved securely.") }
    }
    static func clear() throws {
        var allAccountItems = query; allAccountItems.removeValue(forKey: kSecAttrAccount as String)
        let status = SecItemDelete(allAccountItems as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else { throw HostedError("Your account session could not be removed from Keychain.") }
    }
}
@MainActor
final class HostedAccount: ObservableObject {
    @Published private(set) var session: HostedSession?
    @Published private(set) var account: AccountSnapshot?
    @Published private(set) var challenge: AuthChallenge?
    @Published private(set) var messages: [ConversationMessage] = []
    @Published private(set) var approvalPending = false
    @Published private(set) var agents: [HostedAgent] = []
    @Published var agentRequest: AgentAuthorizationRequest?
    @Published var agentReturnNotice: String?
    @Published private(set) var products: [Product] = []
    @Published private(set) var betaAccess = false
    @Published var busy = false
    @Published var error: String?
    @Published var notice: String?
    @Published private(set) var appleVerificationMessage: String?
    private var sessionGeneration = UUID()
    private var appleGate: AppleCredentialGate?
    private var pendingDeadline: Date?
    private var refreshFlight: Task<HostedSession, Error>?
    private var updates: Task<Void, Never>?
    private let storeProof: StoreEnvironmentProof
    private var storeProofReceipt: StoreProofReceipt?
    let origin: URL?
    private var injectedClient: HostedClient?
    private var injectedPersistence: ((HostedSession) throws -> Void)?
    private var injectedClear: (() throws -> Void)?
    private var injectedCloseProtection: (() -> Void)?
    var client: HostedClient? { injectedClient ?? origin.map { HostedClient(origin: $0) } }
    var hasConsent: Bool { account?.aiConsentVersion == "2026-10-08-openai-v1" }
    var hasAccess: Bool {
        guard appleGate?.authorized ?? true else { return false }
        guard let entitlement = account?.entitlement else { return betaAccess }
        if entitlement.access?.mode == "sandbox_test" {
            return entitlement.hasAccess && entitlement.access?.deviceId == session?.device.id &&
                storeProof.localEnvironment == "Sandbox" && storeProofReceipt?.environment == "Sandbox" &&
                (storeProofReceipt?.expiry.map { $0 > Date() } ?? false)
        }
        return entitlement.hasAccess
    }
    static var installationID: String {
        if let value = UserDefaults.standard.string(forKey: "hostedInstallationID") { return value }
        let value = UUID().uuidString; UserDefaults.standard.set(value, forKey: "hostedInstallationID"); return value
    }
    init() {
        storeProof = StoreEnvironmentProof()
        appleGate = .shared
        origin = try? HostedOrigin(Bundle.main.object(forInfoDictionaryKey: "GATEKEEPER_API_ORIGIN") as? String ?? "").url
        do {
            if let origin, let saved = try AccountKeychain.load() {
                try saved.validate(expectedOrigin: origin)
                session = saved
                if !UserDefaults.standard.bool(forKey: "personalServerMode") {
                    try ConnectorKeychain.save(BridgeConfiguration(address: saved.apiOrigin, token: saved.device.token, hosted: true))
                }
            }
        } catch { self.error = error.localizedDescription }
        observeAppleGate()
        updates = Task { [weak self] in
            for await result in StoreKit.Transaction.updates {
                guard !Task.isCancelled else { return }
                guard let self, self.session != nil, !UserDefaults.standard.bool(forKey: "personalServerMode") else { continue }
                await self.submitTransaction(result)
            }
        }
    }
    // Dependency injection exercises the real refresh coordinator without Keychain or StoreKit side effects.
    init(origin: URL, session: HostedSession?, client: HostedClient,
         persist: @escaping (HostedSession) throws -> Void, clear: @escaping () throws -> Void,
         closeProtection: @escaping () -> Void = {}, appleGate: AppleCredentialGate? = nil, storeProof: StoreEnvironmentProof? = nil) {
        self.storeProof = storeProof ?? StoreEnvironmentProof()
        self.origin = origin; self.session = session; injectedClient = client
        injectedPersistence = persist; injectedClear = clear; injectedCloseProtection = closeProtection
        self.appleGate = appleGate; observeAppleGate()
    }
    deinit { updates?.cancel() }
    private func observeAppleGate() {
        appleGate?.observe { [weak self] message, definitive in
            guard let self else { return }
            self.appleVerificationMessage = message
            if definitive { self.resetMemory(); self.error = message; Task { await self.prepareSignIn() } }
        }
    }
    private func invalidateGeneration() {
        sessionGeneration = UUID(); refreshFlight?.cancel(); refreshFlight = nil
    }
    private func resetMemory() {
        invalidateGeneration()
        session = nil; account = nil; messages = []; products = []; betaAccess = false
        storeProofReceipt = nil
        approvalPending = false; pendingDeadline = nil; agents = []; agentRequest = nil; agentReturnNotice = nil
    }
    private func ensureContext(_ generation: UUID, user: UUID) throws {
        guard generation == sessionGeneration, session?.user.id == user, appleGate?.authorized ?? true else {
            throw HostedError("Your account authorization changed. The previous response was discarded.")
        }
    }
    func activatePersonal() -> Bool {
        invalidateGeneration()
        do {
            Protection.close()
            if let personal = try ConnectorKeychain.load(account: "personal-server") {
                try ConnectorKeychain.save(personal)
            } else if session == nil, let existing = try ConnectorKeychain.load() {
                try ConnectorKeychain.save(existing, account: "personal-server")
            } else { try ConnectorKeychain.clear() }
            return true
        } catch { self.error = error.localizedDescription; return false }
    }
    func activateHosted() async -> Bool {
        invalidateGeneration()
        do {
            Protection.close()
            if session != nil {
                let current = try await credentials()
                try ConnectorKeychain.save(BridgeConfiguration(address: current.apiOrigin, token: current.device.token, hosted: true))
            } else { try ConnectorKeychain.clear() }
            return true
        } catch { self.error = error.localizedDescription; return false }
    }
    func prepareSignIn() async {
        guard session == nil, let client else { return }
        do { challenge = try await client.challenge() }
        catch { self.error = error.localizedDescription }
    }
    func configureApple(_ request: ASAuthorizationAppleIDRequest) {
        request.requestedScopes = []
        guard let challenge else { return }
        request.nonce = SHA256.hash(data: Data(challenge.nonce.utf8)).map { String(format: "%02x", $0) }.joined()
    }
    func completeApple(_ result: Result<ASAuthorization, Error>) async {
        busy = true; error = nil
        let generation = sessionGeneration
        let appleGeneration = appleGate?.generation
        defer { busy = false }
        do {
            guard let client, let challenge, let expiry = HostedDate.parse(challenge.expiresAt), expiry > Date() else {
                throw HostedError("Your sign-in challenge expired. Try signing in again.")
            }
            let authorization = try result.get()
            guard let credential = authorization.credential as? ASAuthorizationAppleIDCredential,
                  let identity = credential.identityToken.flatMap({ String(data: $0, encoding: .utf8) }),
                  let code = credential.authorizationCode.flatMap({ String(data: $0, encoding: .utf8) }) else {
                throw HostedError("Apple did not return the credentials needed to sign in.")
            }
            let saved: HostedSession = try await client.send("v1/auth/apple", body: AppleLoginRequest(challengeId: challenge.challengeId,
                identityToken: identity, authorizationCode: code, deviceName: UIDevice.current.name, installationId: Self.installationID))
            guard generation == sessionGeneration, appleGeneration == appleGate?.generation else { throw HostedError("Apple authorization changed while signing in. Please try again.") }
            try saved.validate(expectedOrigin: client.origin)
            try install(saved, appleIdentifier: credential.user)
            self.challenge = nil
            await reload()
            try? await BackgroundBridge.shared.sync()
            try? await BackgroundBridge.shared.registerToken()
        } catch {
            if (error as? ASAuthorizationError)?.code != .canceled { self.error = error.localizedDescription }
            self.challenge = nil
            await prepareSignIn()
        }
    }
    private func install(_ saved: HostedSession, appleIdentifier: String? = nil) throws {
        guard let origin else { throw HostedError("Rook is unavailable in this build.") }
        try saved.validate(expectedOrigin: origin)
        guard let expiry = saved.expiry, expiry > Date() else { throw HostedError("The service returned an expired session. Please sign in again.") }
        // Persist the complete refresh result before any further authenticated request.
        if let injectedPersistence { try injectedPersistence(saved); session = saved; return }
        if session == nil, let existing = try ConnectorKeychain.load() {
            try ConnectorKeychain.save(existing, account: "personal-server")
        }
        try AccountKeychain.save(saved, appleIdentifier: appleIdentifier)
        session = saved
        if let appleIdentifier { appleGate?.recordSuccessfulSignIn(identifier: appleIdentifier) }
        if !UserDefaults.standard.bool(forKey: "personalServerMode") {
            try ConnectorKeychain.save(BridgeConfiguration(address: saved.apiOrigin, token: saved.device.token, hosted: true))
        }
    }
    private func credentials(forceRefresh: Bool = false) async throws -> HostedSession {
        if let appleGate { try await appleGate.requireAuthorization() }
        if let refreshFlight { return try await refreshFlight.value }
        guard let saved = session, let client else { throw HostedError("Sign in to continue.") }
        if !forceRefresh, let expiry = saved.expiry, expiry.timeIntervalSinceNow > 60 { return saved }
        let generation = sessionGeneration
        let task = Task { @MainActor in
            let rotated: HostedSession = try await client.send("v1/auth/refresh", body: RefreshRequest(refreshToken: saved.refreshToken))
            try Task.checkCancellation()
            if let appleGate = self.appleGate { try await appleGate.requireAuthorization() }
            try Task.checkCancellation()
            try self.ensureContext(generation, user: saved.user.id)
            guard rotated.user.id == saved.user.id, rotated.device.id == saved.device.id else {
                try self.forget()
                throw HostedError("The refreshed session changed account or device identity. Access remains blocked.")
            }
            try self.install(rotated)
            return rotated
        }
        refreshFlight = task
        defer { if generation == sessionGeneration { refreshFlight = nil } }
        do { return try await task.value }
        catch {
            if generation == sessionGeneration, (error as? HostedError)?.status == 401 {
                try? forget()
                self.error = "Your session has ended. Sign in with Apple again. Local protection remains in effect."
            }
            throw error
        }
    }
    private func authenticated<T>(_ operation: (HostedClient, HostedSession) async throws -> T) async throws -> T {
        guard let client else { throw HostedError("Rook is unavailable in this build.") }
        let generation = sessionGeneration
        let saved = try await credentials()
        try ensureContext(generation, user: saved.user.id)
        do {
            let response = try await operation(client, saved)
            if let appleGate { try await appleGate.requireAuthorization() }
            try ensureContext(generation, user: saved.user.id)
            return response
        } catch let error as HostedError where error.status == 401 {
            try ensureContext(generation, user: saved.user.id)
            let current = try await credentials(forceRefresh: session?.accountToken == saved.accountToken)
            try ensureContext(generation, user: current.user.id)
            let response = try await operation(client, current)
            if let appleGate { try await appleGate.requireAuthorization() }
            try ensureContext(generation, user: current.user.id)
            return response
        }
    }
    func reload() async {
        guard session != nil else { await prepareSignIn(); return }
        storeProofReceipt = nil
        do {
            if let appleGate { try await appleGate.requireAuthorization(force: true) }
            account = try await authenticated { client, session in try await client.get("v1/account", token: session.accountToken) }
            let history: ConversationHistory = try await authenticated { client, session in try await client.get("v1/conversation", token: session.accountToken) }
            messages = history.messages
            let offerings: BillingProducts = try await authenticated { client, session in try await client.get("v1/billing/products", token: session.accountToken) }
            betaAccess = offerings.betaAccess
            if !offerings.betaAccess {
                do {
                    storeProofReceipt = try await authenticated { client, session in
                        try await self.storeProof.establish(client: client, session: session)
                    }
                    account = try await authenticated { client, session in try await client.get("v1/account", token: session.accountToken) }
                } catch {
                    // Production paid access does not depend on a Sandbox test lease.
                    // An unavailable proof never authorizes new Sandbox work.
                    if self.account?.entitlement.active != true { self.error = error.localizedDescription }
                }
            }
            let connections: AgentConnections = try await authenticated { client, session in try await client.get("v1/agents", token: session.accountToken) }
            agents = connections.connections
            let generation = sessionGeneration
            let fetchedProducts = try await Product.products(for: offerings.productIds)
            guard generation == sessionGeneration, session != nil else { return }
            products = fetchedProducts
        } catch { self.error = error.localizedDescription }
    }
    func consent() async {
        await perform {
            let receipt: HostedReceipt = try await self.authenticated { client, session in try await client.send("v1/account/consent", token: session.accountToken, body: ConsentRequest()) }
            guard receipt.received else { throw HostedError("Consent was not recorded. Please try again.") }
            await self.reload()
        }
    }
    func send(_ message: String, minutes: Int) async -> Bool {
        guard !busy, hasConsent, hasAccess else { return false }
        busy = true; error = nil; notice = nil
        defer { busy = false }
        do {
            let requestID = UUID()
            let reply: ConversationReply = try await authenticated { client, session in
                try await client.send("v1/conversation", token: session.accountToken,
                    body: ConversationRequest(requestId: requestID, message: message, durationMinutes: minutes, deviceId: session.device.id))
            }
            let createdAt = ISO8601DateFormatter().string(from: Date())
            messages.append(ConversationMessage(id: "local-user-\(requestID)", role: "user", content: message, createdAt: createdAt))
            messages.append(ConversationMessage(id: "local-muse-\(requestID)", role: "assistant", content: reply.reply, createdAt: createdAt))
            approvalPending = reply.decision == .approve
            pendingDeadline = reply.approval?.redeemBy.flatMap(HostedDate.parse)
            if approvalPending {
                notice = "Rook approved your request. Waiting for this iPhone to verify and start access."
                do { try await BackgroundBridge.shared.sync() }
                catch {
                    if let expiry = Protection.expiry, expiry > Date() {
                        self.error = "Access started on this iPhone, but the service could not finish syncing: \(error.localizedDescription) The local timer remains in effect."
                    } else { self.error = "Approval received, but access has not been confirmed: \(error.localizedDescription)" }
                }
            }
            await reload()
            confirmLocalAccess()
            return true
        } catch { self.error = error.localizedDescription; return false }
    }
    func confirmLocalAccess() {
        if let expiry = Protection.expiry, expiry > Date() {
            approvalPending = false
            pendingDeadline = nil
            notice = "This iPhone started access. Apps will block again when the local timer ends."
        } else if approvalPending, let pendingDeadline, pendingDeadline <= Date() {
            approvalPending = false
            self.pendingDeadline = nil
            notice = "This approval expired before access started. Your apps remain protected."
        }
    }
    func withdrawConsent() async {
        await perform {
            let receipt: HostedReceipt = try await self.authenticated { client, session in try await client.delete("v1/account/consent", token: session.accountToken) }
            guard receipt.received else { throw HostedError("Consent withdrawal was not confirmed.") }
            self.approvalPending = false
            await self.reload()
            self.notice = "AI consent withdrawn. Rook will ask for your consent before processing another message."
        }
    }
    func loadAgentRequest(_ id: UUID) async {
        await perform {
            self.agentReturnNotice = nil
            self.agentRequest = try await self.authenticated { client, session in try await client.get("v1/agents/requests/\(id.uuidString)", token: session.accountToken) }
        }
    }
    func decideAgent(approve: Bool) async -> URL? {
        guard let request = agentRequest else { return nil }
        busy = true; error = nil
        defer { busy = false }
        do {
            let decision: AgentDecisionReceipt = try await authenticated { client, session in try await client.send("v1/agents/requests/\(request.id)/decision", token: session.accountToken, body: AgentDecisionRequest(approve: approve)) }
            guard let callback = URLComponents(string: decision.redirectURL), let expected = URLComponents(string: request.redirectURI),
                  callback.scheme == expected.scheme, callback.host == expected.host, callback.port == expected.port, callback.path == expected.path,
                  callback.user == nil, callback.password == nil, callback.fragment == expected.fragment,
                  let scheme = callback.scheme,
                  scheme == "https" || (scheme == "http" && ["localhost", "127.0.0.1", "::1", "[::1]"].contains(callback.host?.lowercased() ?? "")),
                  let url = callback.url else {
                throw HostedError("The agent returned an invalid callback URL.")
            }
            let isLoopback = ["localhost", "127.0.0.1", "::1", "[::1]"].contains(callback.host?.lowercased() ?? "")
            if decision.requiresOriginalBrowser == true || isLoopback {
                self.agentReturnNotice = approve ? "Approved. Return to your agent on the device where you started connecting." : "Connection denied. Return to the device where you started connecting."
                await reload()
                return nil
            }
            self.agentRequest = nil
            await reload()
            return url
        } catch { self.error = error.localizedDescription; return nil }
    }
    func revokeAgent(_ agent: HostedAgent) async {
        await perform {
            let receipt: RevokedReceipt = try await self.authenticated { client, session in try await client.delete("v1/agents/\(agent.id)", token: session.accountToken) }
            guard receipt.revoked else { throw HostedError("Agent disconnection was not confirmed.") }
            await self.reload()
        }
    }
    func clearHistory() async {
        await perform {
            let receipt: DeletedReceipt = try await self.authenticated { client, session in try await client.delete("v1/conversation", token: session.accountToken) }
            guard receipt.deleted else { throw HostedError("History was not cleared.") }
            self.messages = []
        }
    }
    func endAccess() async {
        if let injectedCloseProtection { injectedCloseProtection() } else { Protection.close() }
        approvalPending = false
        // Ending a local window must not wait behind a purchase or history operation.
        do {
            let receipt: EndReceipt = try await authenticated { client, session in try await client.send("v1/access/end", token: session.accountToken, body: DeviceRequest(deviceId: session.device.id)) }
            guard receipt.status == "end_requested" else { throw HostedError("The service did not confirm the end request.") }
            notice = "Access ended on this iPhone. Your original cooldown still applies."
            do { try await BackgroundBridge.shared.sync() }
            catch { self.error = "Access ended locally and the service accepted the end request, but syncing could not finish: \(error.localizedDescription)" }
        } catch {
            self.error = "Access ended locally, but the service could not confirm it: \(error.localizedDescription) Your original cooldown still applies."
        }
    }
    func revoke(_ device: HostedDevice) async {
        await perform {
            let receipt: RevokedReceipt = try await self.authenticated { client, session in try await client.delete("v1/devices/\(device.id)", token: session.accountToken) }
            guard receipt.revoked else { throw HostedError("Device revocation was not confirmed.") }
            if device.id == self.session?.device.id { try self.forget() } else { await self.reload() }
        }
    }
    func deleteAccount() async {
        await perform {
            let receipt: DeletedReceipt = try await self.authenticated { client, session in try await client.delete("v1/account", token: session.accountToken) }
            guard receipt.deleted else { throw HostedError("Account deletion was not confirmed.") }
            try self.forget()
            self.notice = "Your account and its records were deleted. Your selected apps remain protected locally."
        }
    }
    private func forget() throws {
        resetMemory(); appleGate?.invalidateLocalSession()
        if let injectedClear { try injectedClear() }
        else {
            Protection.close()
            try AccountKeychain.clear()
            if !UserDefaults.standard.bool(forKey: "personalServerMode") { try ConnectorKeychain.clear() }
        }
    }
    private func perform(_ action: () async throws -> Void) async {
        guard !busy else { return }
        busy = true; error = nil
        defer { busy = false }
        do { try await action() } catch { self.error = error.localizedDescription }
    }
    func purchase(_ product: Product) async {
        await perform {
            let current = try await self.credentials()
            guard let token = self.purchaseAccountToken, self.session?.user.id == current.user.id else {
                throw HostedError("Your purchase identity is not ready. Refresh your account or sign in again before buying.")
            }
            switch try await product.purchase(options: [.appAccountToken(token)]) {
            case .success(let result): await self.submitTransaction(result)
            case .pending: self.notice = "Your purchase is pending Apple approval. Access updates after verification."
            case .userCancelled: break
            @unknown default: break
            }
        }
    }
    var purchaseAccountToken: UUID? {
        guard let session else { return nil }
        if let account, account.user.id == session.user.id, let token = account.user.purchaseAccountToken { return token }
        return session.user.purchaseAccountToken
    }
    private func submitTransaction(_ result: VerificationResult<StoreKit.Transaction>) async {
        do {
            guard case .verified(let transaction) = result else { throw HostedError("Apple could not verify this purchase.") }
            guard let token = purchaseAccountToken, transaction.appAccountToken == token, session != nil else {
                throw HostedError("This purchase is not associated with the signed-in Rook account. Sign in with the account used for the purchase.")
            }
            let entitlement: HostedEntitlement = try await authenticated { client, session in
                // Apple may keep its purchase sheet open longer than our test
                // lease. Renew after Apple succeeds, before delivering access.
                if transaction.environment == .sandbox { try await self.refreshSandboxPurchaseProof(client: client, session: session) }
                return try await client.send("v1/billing/transaction", token: session.accountToken, body: TransactionRequest(signedTransaction: result.jwsRepresentation))
            }
            // The server owns entitlement. Never unlock from a local purchase result.
            await transaction.finish()
            notice = entitlement.hasAccess ? "Your purchase was verified. Access is available." : "Your purchase was received. No active entitlement is available yet."
            await reload()
        } catch { self.error = error.localizedDescription }
    }
    func refreshSandboxPurchaseProof(client: HostedClient, session: HostedSession) async throws {
        let generation = sessionGeneration
        let receipt = try await storeProof.establish(client: client, session: session)
        try ensureContext(generation, user: session.user.id)
        guard receipt.environment == "Sandbox", storeProof.localEnvironment == "Sandbox" else {
            throw HostedError("This installation cannot use sandbox purchases.")
        }
        storeProofReceipt = receipt
    }
    func renewSandboxAccessIfNeeded() async {
        guard !busy, session != nil, account?.entitlement.access?.mode == "sandbox_test",
              (storeProofReceipt?.expiry.map { $0 <= Date().addingTimeInterval(60) } ?? true) else { return }
        do {
            try await authenticated { client, session in try await self.refreshSandboxPurchaseProof(client: client, session: session) }
            account = try await authenticated { client, session in try await client.get("v1/account", token: session.accountToken) }
        } catch { storeProofReceipt = nil; self.error = error.localizedDescription }
    }
    func restore() async {
        await perform {
            try await AppStore.sync()
            for await result in StoreKit.Transaction.currentEntitlements { await self.submitTransaction(result) }
            await self.reload()
            self.notice = self.hasAccess ? "Access is available for this account." : "No active purchase was found for this account."
        }
    }
}
