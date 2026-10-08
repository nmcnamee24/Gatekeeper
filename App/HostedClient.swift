import Foundation

enum HostedDate {
    static func parse(_ value: String) -> Date? {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return formatter.date(from: value) ?? ISO8601DateFormatter().date(from: value)
    }
}
struct HostedOrigin {
    let url: URL
    init(_ value: String) throws {
        guard let parts = URLComponents(string: value.trimmingCharacters(in: .whitespacesAndNewlines)),
              parts.scheme == "https", let host = parts.host, !host.isEmpty,
              parts.user == nil, parts.password == nil, parts.query == nil, parts.fragment == nil,
              parts.path.isEmpty || parts.path == "/", let url = parts.url else {
            throw HostedError("Rook is not configured for this build. Your existing protection remains available.")
        }
        self.url = url
    }
}
struct HostedError: LocalizedError {
    let message: String
    let code: String?
    let status: Int?
    init(_ message: String, code: String? = nil, status: Int? = nil) { self.message = message; self.code = code; self.status = status }
    var errorDescription: String? { message }
}
struct HostedUser: Codable { let id: UUID; let displayName: String? }
struct HostedDeviceCredential: Codable { let id: String; let token: String; let name: String }
struct HostedSession: Codable {
    let user: HostedUser
    let accountToken: String
    let refreshToken: String
    let expiresAt: String
    let device: HostedDeviceCredential
    let apiOrigin: String
    var expiry: Date? { HostedDate.parse(expiresAt) }
    func validate(expectedOrigin: URL) throws {
        let actual = try HostedOrigin(apiOrigin).url
        guard actual.host == expectedOrigin.host, actual.port == expectedOrigin.port,
              accountToken.count >= 32, refreshToken.count >= 32, device.token.count >= 32,
              !device.id.isEmpty, expiry != nil,
              [accountToken, refreshToken, device.token].allSatisfy({ $0.rangeOfCharacter(from: .whitespacesAndNewlines) == nil }) else {
            throw HostedError("The service returned an invalid account session. Please sign in again.")
        }
    }
}
struct AuthChallenge: Decodable { let challengeId: String; let nonce: String; let expiresAt: String }
struct AppleLoginRequest: Encodable {
    let challengeId: String; let identityToken: String; let authorizationCode: String
    let deviceName: String; let installationId: String
}
struct RefreshRequest: Encodable { let refreshToken: String }
struct ConsentRequest: Encodable { let version = "2026-10-08" }
struct DeviceRequest: Encodable { let deviceId: String }
struct TransactionRequest: Encodable { let signedTransaction: String }
struct HostedAgent: Decodable, Identifiable {
    let id: String; let clientName: String; let scopes: [String]; let createdAt: String; let lastUsedAt: String?
}
struct AgentConnections: Decodable { let connections: [HostedAgent] }
struct AgentAuthorizationRequest: Decodable, Identifiable {
    let id: String; let clientName: String; let redirectURI: String; let scopes: [String]
}
struct AgentDecisionRequest: Encodable { let approve: Bool }
struct AgentDecisionReceipt: Decodable { let redirectURL: String; let requiresOriginalBrowser: Bool? }
struct HostedReceipt: Decodable { let received: Bool }
struct DeletedReceipt: Decodable { let deleted: Bool }
struct RevokedReceipt: Decodable { let revoked: Bool }
struct EndReceipt: Decodable { let status: String }
struct HostedDevice: Decodable, Identifiable {
    let id: String; let name: String; let lastSeenAt: String?; let revokedAt: String?
}
struct HostedEntitlement: Decodable {
    let active: Bool; let betaAccess: Bool
    let productId: String?; let expiresAt: String?
    var hasAccess: Bool { active || betaAccess }
}
struct AccountSnapshot: Decodable {
    let user: HostedUser; let devices: [HostedDevice]
    let aiConsentVersion: String?; let entitlement: HostedEntitlement
}
struct BillingProducts: Decodable { let productIds: [String]; let betaAccess: Bool }
struct ConversationMessage: Decodable, Identifiable {
    let id: String; let role: String; let content: String; let createdAt: String
}
struct ConversationHistory: Decodable { let messages: [ConversationMessage] }
struct ConversationRequest: Encodable {
    let requestId: String; let message: String; let durationMinutes: Int; let deviceId: String
    init(requestId: UUID = UUID(), message: String, durationMinutes: Int, deviceId: String) throws {
        guard (1...15).contains(durationMinutes), !message.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty, !deviceId.isEmpty else {
            throw HostedError("Choose 1–15 minutes and explain your purpose and exit plan.")
        }
        self.requestId = requestId.uuidString; self.message = message; self.durationMinutes = durationMinutes; self.deviceId = deviceId
    }
}
enum MuseDecision: String, Decodable { case ask, deny, approve }
struct HostedApproval: Decodable {
    let grantId: String; let status: String; let redeemBy: String?; let windowSeconds: Int?
    let endsAt: String?; let deviceId: String?; let openAppURL: String?; let instruction: String?
}
struct ConversationReply: Decodable { let reply: String; let decision: MuseDecision; let approval: HostedApproval? }
private struct HostedServiceError: Decodable { let error: String; let code: String? }
private final class HostedNoRedirects: NSObject, URLSessionTaskDelegate {
    func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse,
                    newRequest request: URLRequest, completionHandler: @escaping (URLRequest?) -> Void) { completionHandler(nil) }
}
struct HostedClient {
    let origin: URL
    let session: URLSession
    private static let defaultSession: URLSession = {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.urlCache = nil
        return URLSession(configuration: configuration, delegate: HostedNoRedirects(), delegateQueue: nil)
    }()
    init(origin: URL, session: URLSession? = nil) {
        self.origin = origin
        self.session = session ?? Self.defaultSession
    }
    func get<Reply: Decodable>(_ path: String, token: String) async throws -> Reply {
        try await request(path, method: "GET", token: token, body: nil)
    }
    func delete<Reply: Decodable>(_ path: String, token: String) async throws -> Reply {
        try await request(path, method: "DELETE", token: token, body: nil)
    }
    func send<Body: Encodable, Reply: Decodable>(_ path: String, method: String = "POST", token: String? = nil, body: Body) async throws -> Reply {
        try await request(path, method: method, token: token, body: JSONEncoder().encode(body))
    }
    func challenge() async throws -> AuthChallenge {
        try await request("v1/auth/challenge", method: "POST", token: nil, body: Data("{}".utf8))
    }
    private func request<Reply: Decodable>(_ path: String, method: String, token: String?, body: Data?) async throws -> Reply {
        _ = try HostedOrigin(origin.absoluteString)
        guard !path.contains(".."), !path.contains("?"), !path.contains("#") else { throw HostedError("Invalid service endpoint.") }
        var request = URLRequest(url: origin.appendingPathComponent(path))
        request.httpMethod = method; request.httpBody = body; request.timeoutInterval = 30
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        if let token { request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization") }
        let (data, response) = try await session.data(for: request)
        guard let http = response as? HTTPURLResponse else { throw HostedError("Rook did not return a response.") }
        guard http.statusCode == 200 else {
            let problem = try? JSONDecoder().decode(HostedServiceError.self, from: data)
            throw HostedError(problem?.error ?? "Rook returned HTTP \(http.statusCode). Try again when your connection is available.", code: problem?.code, status: http.statusCode)
        }
        return try JSONDecoder().decode(Reply.self, from: data)
    }
}
