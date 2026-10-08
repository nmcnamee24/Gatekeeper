import Foundation

final class HostedStub: URLProtocol {
    static var handler: ((URLRequest) throws -> (Int, Data))?
    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }
    override func startLoading() {
        do {
            let (status, data) = try Self.handler!(request)
            let response = HTTPURLResponse(url: request.url!, statusCode: status, httpVersion: nil, headerFields: ["Content-Type": "application/json"])!
            client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
            client?.urlProtocol(self, didLoad: data)
            client?.urlProtocolDidFinishLoading(self)
        } catch { client?.urlProtocol(self, didFailWithError: error) }
    }
    override func stopLoading() {}
}
@main struct VerifyHostedClient {
    static func main() async throws {
        var checks = 0
        for value in ["http://example.com", "https://u@example.com", "https://example.com/path", "https://example.com?q=x", "$(GATEKEEPER_API_ORIGIN)", ""] {
            do { _ = try HostedOrigin(value); fatalError("Accepted unsafe origin") } catch { checks += 1 }
        }
        let origin = try HostedOrigin("https://api.example.com")
        let config = URLSessionConfiguration.ephemeral
        config.protocolClasses = [HostedStub.self]
        let client = HostedClient(origin: origin.url, session: URLSession(configuration: config))
        HostedStub.handler = { request in
            precondition(request.url?.path == "/v1/conversation")
            precondition(request.httpMethod == "POST")
            precondition(request.value(forHTTPHeaderField: "Authorization") == "Bearer account-credential")
            var payload = request.httpBody ?? Data()
            if let stream = request.httpBodyStream {
                stream.open(); defer { stream.close() }
                var buffer = [UInt8](repeating: 0, count: 4096)
                while stream.hasBytesAvailable { let count = stream.read(&buffer, maxLength: buffer.count); if count <= 0 { break }; payload.append(buffer, count: count) }
            }
            let body = try JSONSerialization.jsonObject(with: payload) as! [String: Any]
            precondition(body["durationMinutes"] as? Int == 3)
            precondition(UUID(uuidString: body["requestId"] as! String) != nil)
            precondition(body["deviceId"] as? String == "phone")
            return (200, Data(#"{"reply":"Approved for your stated task.","decision":"approve","approval":{"grantId":"g","status":"pending","redeemBy":"2026-10-08T20:00:00.000Z","windowSeconds":180,"instruction":"Wait for phone","openAppURL":"gatekeeper://sync"}}"#.utf8))
        }
        let request = try ConversationRequest(message: "Send a message and leave", durationMinutes: 3, deviceId: "phone")
        let reply: ConversationReply = try await client.send("v1/conversation", method: "POST", token: "account-credential", body: request)
        precondition(reply.decision == .approve && reply.approval?.status == "pending"); checks += 1
        for minutes in [0, 16] {
            do { _ = try ConversationRequest(message: "Reason", durationMinutes: minutes, deviceId: "phone"); fatalError("Accepted bad minutes") } catch { checks += 1 }
        }
        HostedStub.handler = { _ in (401, Data(#"{"error":"Session expired","code":"unauthorized"}"#.utf8)) }
        do {
            let _: AccountSnapshot = try await client.get("v1/account", token: "expired")
            fatalError("Accepted unauthorized response")
        } catch let error as HostedError { precondition(error.status == 401 && error.code == "unauthorized"); checks += 1 }
        HostedStub.handler = { _ in (302, Data()) }
        do { let _: AccountSnapshot = try await client.get("v1/account", token: "x"); fatalError("Accepted redirect") } catch { checks += 1 }
        let sessionJSON = #"{"user":{"id":"12345678-1234-1234-1234-123456789ABC"},"accountToken":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","refreshToken":"rrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrr","expiresAt":"2099-10-08T20:00:00.000Z","device":{"id":"phone","token":"dddddddddddddddddddddddddddddddd","name":"iPhone"},"apiOrigin":"https://api.example.com"}"#
        let session = try JSONDecoder().decode(HostedSession.self, from: Data(sessionJSON.utf8))
        try session.validate(expectedOrigin: origin.url); checks += 1
        do { try session.validate(expectedOrigin: URL(string: "https://other.example.com")!); fatalError("Accepted cross-origin credentials") } catch { checks += 1 }
        precondition(HostedDate.parse("2026-10-08T20:00:00Z") != nil); checks += 1
        precondition(HostedDate.parse("2026-10-08T20:00:00.000Z") != nil); checks += 1
        let entitlement = try JSONDecoder().decode(HostedEntitlement.self, from: Data(#"{"active":false,"betaAccess":true}"#.utf8))
        precondition(entitlement.hasAccess); checks += 1
        print("Passed \(checks) hosted client contract and transport checks")
    }
}
