import Foundation
@main struct VerifyConnector {
    static func main() throws {
        var checks = 0
        func reject(_ action: () throws -> Void) {
            do { try action(); fatalError("Expected rejection for check \(checks + 1)") } catch { checks += 1 }
        }
        let now = Date(timeIntervalSince1970: 1_000_000_000)
        let format = ISO8601DateFormatter()
        format.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        func lease(_ delta: TimeInterval, seconds: Int = 960) -> RemoteLease {
            RemoteLease(grantId: "test", windowSeconds: seconds, endsAt: format.string(from: now.addingTimeInterval(delta)))
        }
        let end = try lease(960).validatedEnd(now: now)
        precondition(end.timeIntervalSince(now) == 960); checks += 1
        reject { _ = try lease(961).validatedEnd(now: now) }
        reject { _ = try lease(901).validatedEnd(now: now) }
        reject { _ = try lease(-1).validatedEnd(now: now) }
        reject { _ = try lease(960, seconds: 3600).validatedEnd(now: now) }
        reject { _ = try RemoteLease(grantId: "test", windowSeconds: 960, endsAt: "invalid").validatedEnd(now: now) }
        let token = String(repeating: "x", count: 64)
        let valid = try BridgeConfiguration(address: "https://gate.example", token: token)
        precondition(valid.baseURL.host == "gate.example"); checks += 1
        for address in ["http://gate.example", "https://person@host.example", "https://host.example/path", "https://host.example?token=x", "https://host.example#x", "https://"] {
            reject { _ = try BridgeConfiguration(address: address, token: token) }
        }
        reject { _ = try BridgeConfiguration(address: "https://gate.example", token: "short") }
        reject { _ = try BridgeConfiguration(address: "https://gate.example", token: token + "\r\n") }
        print("Passed \(checks) connector validation checks")
    }
}
