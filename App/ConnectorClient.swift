import Foundation
import Security

struct BridgeConfiguration: Codable {
    let baseURL: URL
    let token: String
    let hosted: Bool?
    init(address: String, token: String, hosted: Bool = false) throws {
        guard let parts = URLComponents(string: address.trimmingCharacters(in: .whitespacesAndNewlines)),
              parts.scheme == "https", let host = parts.host, !host.isEmpty,
              parts.user == nil, parts.password == nil, parts.query == nil, parts.fragment == nil,
              parts.path.isEmpty || parts.path == "/", let url = parts.url,
              token.count >= 32, token.rangeOfCharacter(from: .whitespacesAndNewlines) == nil else {
            throw ConnectorError.message("Enter an HTTPS service origin, without a path, and the device token (not Muse’s token).")
        }
        baseURL = url
        self.token = token
        self.hosted = hosted ? true : nil
    }
}
enum ConnectorError: LocalizedError {
    case message(String)
    case http(status: Int, message: String, code: String?)
    var statusCode: Int? { if case .http(let status, _, _) = self { return status }; return nil }
    var serviceCode: String? { if case .http(_, _, let code) = self { return code }; return nil }
    var errorDescription: String? {
        switch self { case .message(let text), .http(_, let text, _): return text }
    }
}
enum ConnectorKeychain {
    private static func query(account: String = "paired-device") -> [String: Any] {
        [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: "com.noah.gatekeeper.connector", kSecAttrAccount as String: account]
    }
    static func load(account: String = "paired-device") throws -> BridgeConfiguration? {
        var lookup = query(account: account)
        lookup[kSecReturnData as String] = true
        lookup[kSecMatchLimit as String] = kSecMatchLimitOne
        var result: CFTypeRef?
        let status = SecItemCopyMatching(lookup as CFDictionary, &result)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess, let data = result as? Data else { throw ConnectorError.message("Could not read connector configuration from Keychain.") }
        return try JSONDecoder().decode(BridgeConfiguration.self, from: data)
    }
    static func clear(account: String = "paired-device") throws {
        let status = SecItemDelete(query(account: account) as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else { throw ConnectorError.message("Could not remove the paired device from Keychain.") }
    }
    static func save(_ configuration: BridgeConfiguration, account: String = "paired-device") throws {
        let data = try JSONEncoder().encode(configuration)
        let update = SecItemUpdate(query(account: account) as CFDictionary, [kSecValueData as String: data] as CFDictionary)
        if update == errSecSuccess { return }
        guard update == errSecItemNotFound else { throw ConnectorError.message("Could not update Keychain.") }
        var item = query(account: account)
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
        guard windowSeconds >= 60, windowSeconds <= Int(GatePolicy.window), windowSeconds % 60 == 0,
              let end = formatter.date(from: endsAt),
              end.timeIntervalSince(now) > 0, end.timeIntervalSince(now) <= Double(windowSeconds) else {
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
private struct ServiceError: Decodable { let error: String; let code: String? }
private final class NoRedirects: NSObject, URLSessionTaskDelegate {
    func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse,
                    newRequest request: URLRequest, completionHandler: @escaping (URLRequest?) -> Void) {
        completionHandler(nil)
    }
}
struct ConnectorClient {
    let configuration: BridgeConfiguration
    private let injectedSession: URLSession?
    init(configuration: BridgeConfiguration, session: URLSession? = nil) {
        self.configuration = configuration; injectedSession = session
    }
    private func send<Reply: Decodable>(_ path: String, body: Data? = nil) async throws -> Reply {
        let session = injectedSession ?? URLSession(configuration: .ephemeral, delegate: NoRedirects(), delegateQueue: nil)
        defer { if injectedSession == nil { session.invalidateAndCancel() } }
        var request = URLRequest(url: configuration.baseURL.appendingPathComponent(path))
        request.httpMethod = body == nil ? "GET" : "POST"
        request.httpBody = body
        request.timeoutInterval = 5
        request.setValue("Bearer \(configuration.token)", forHTTPHeaderField: "Authorization")
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        let (data, response) = try await session.data(for: request)
        guard let http = response as? HTTPURLResponse else { throw ConnectorError.message("No response from Gatekeeper.") }
        guard http.statusCode == 200 else {
            let problem = try? JSONDecoder().decode(ServiceError.self, from: data)
            throw ConnectorError.http(status: http.statusCode,
                message: problem?.error ?? "Connector returned HTTP \(http.statusCode). Check the service address and device token.", code: problem?.code)
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
