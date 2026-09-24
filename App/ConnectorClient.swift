import Foundation
import Security

struct BridgeConfiguration: Codable {
    let baseURL: URL
    let token: String
    init(address: String, token: String) throws {
        guard let parts = URLComponents(string: address.trimmingCharacters(in: .whitespacesAndNewlines)),
              parts.scheme == "https", let host = parts.host, !host.isEmpty,
              parts.user == nil, parts.password == nil, parts.query == nil, parts.fragment == nil,
              parts.path.isEmpty || parts.path == "/", let url = parts.url,
              token.count >= 32, token.rangeOfCharacter(from: .whitespacesAndNewlines) == nil else {
            throw ConnectorError.message("Enter an HTTPS service origin, without a path, and the device token (not Muse’s token).")
        }
        baseURL = url
        self.token = token
    }
}
enum ConnectorError: LocalizedError {
    case message(String)
    var errorDescription: String? { if case let .message(text) = self { return text }; return nil }
}
enum ConnectorKeychain {
    private static var query: [String: Any] {
        [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: "com.noah.gatekeeper.connector", kSecAttrAccount as String: "paired-device"]
    }
    static func load() throws -> BridgeConfiguration? {
        var lookup = query
        lookup[kSecReturnData as String] = true
        lookup[kSecMatchLimit as String] = kSecMatchLimitOne
        var result: CFTypeRef?
        let status = SecItemCopyMatching(lookup as CFDictionary, &result)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess, let data = result as? Data else { throw ConnectorError.message("Could not read connector configuration from Keychain.") }
        return try JSONDecoder().decode(BridgeConfiguration.self, from: data)
    }
    static func save(_ configuration: BridgeConfiguration) throws {
        let data = try JSONEncoder().encode(configuration)
        let update = SecItemUpdate(query as CFDictionary, [kSecValueData as String: data] as CFDictionary)
        if update == errSecSuccess { return }
        guard update == errSecItemNotFound else { throw ConnectorError.message("Could not update Keychain.") }
        var item = query
        item[kSecValueData as String] = data
        item[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        guard SecItemAdd(item as CFDictionary, nil) == errSecSuccess else { throw ConnectorError.message("Could not save to Keychain.") }
    }
}

struct RemoteState: Decodable {
    let pendingGrantId: String?
    let lastGrantId: String?
    let lastGrantRevoked: Bool
}
struct RemoteLease: Decodable {
    let grantId: String
    let windowSeconds: Int
    let endsAt: String
    func validatedEnd(now: Date = Date()) throws -> Date {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        guard windowSeconds == Int(GatePolicy.window), let end = formatter.date(from: endsAt),
              end.timeIntervalSince(now) > 901, end.timeIntervalSince(now) <= GatePolicy.window else {
            throw ConnectorError.message("The pass arrived too late or has an invalid duration. Apps remain blocked.")
        }
        return end
    }
}
private struct GrantRequest: Encodable { let grantId: String }
struct PhoneReport: Encodable {
    let state: String
    let grantId: String?
    let localExpiry: String?
}
private struct Receipt: Decodable { let received: Bool }
private struct ServiceError: Decodable { let error: String }
private final class NoRedirects: NSObject, URLSessionTaskDelegate {
    func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse,
                    newRequest request: URLRequest, completionHandler: @escaping (URLRequest?) -> Void) {
        completionHandler(nil)
    }
}
struct ConnectorClient {
    let configuration: BridgeConfiguration
    private func send<Reply: Decodable>(_ path: String, body: Data? = nil) async throws -> Reply {
        let session = URLSession(configuration: .ephemeral, delegate: NoRedirects(), delegateQueue: nil)
        defer { session.invalidateAndCancel() }
        var request = URLRequest(url: configuration.baseURL.appendingPathComponent(path))
        request.httpMethod = body == nil ? "GET" : "POST"
        request.httpBody = body
        request.timeoutInterval = 5
        request.setValue("Bearer \(configuration.token)", forHTTPHeaderField: "Authorization")
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        let (data, response) = try await session.data(for: request)
        guard let http = response as? HTTPURLResponse else { throw ConnectorError.message("No response from Gatekeeper.") }
        guard http.statusCode == 200 else {
            if let problem = try? JSONDecoder().decode(ServiceError.self, from: data) { throw ConnectorError.message(problem.error) }
            throw ConnectorError.message("Connector returned HTTP \(http.statusCode). Check the service address and device token.")
        }
        return try JSONDecoder().decode(Reply.self, from: data)
    }
    func registerPush(token: String, environment: String) async throws {
        let _: Receipt = try await send("device/push", body: JSONSerialization.data(withJSONObject: ["token": token, "environment": environment]))
    }
    func state() async throws -> RemoteState { try await send("device/state") }
    func redeem(_ grantId: String) async throws -> RemoteLease {
        try await send("device/redeem", body: JSONEncoder().encode(GrantRequest(grantId: grantId)))
    }
    func report(_ report: PhoneReport) async throws {
        let _: Receipt = try await send("device/report", body: JSONEncoder().encode(report))
    }
}
