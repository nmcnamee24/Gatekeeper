import Foundation

public struct GatePolicy: Sendable {
    public static let window: TimeInterval = 16 * 60
    public static let cooldown: TimeInterval = 30 * 60
    public static func eligible(now: Date, lastGrant: Date?) -> Bool {
        guard let lastGrant else { return true }
        return now.timeIntervalSince(lastGrant) >= window + cooldown
    }
    public static func isOpen(now: Date, expiry: Date?) -> Bool {
        guard let expiry else { return false }
        return now < expiry
    }
    public static func approves(approved: Bool, concretePurpose: Bool, exitPlan: Bool) -> Bool {
        approved && concretePurpose && exitPlan
    }
}
