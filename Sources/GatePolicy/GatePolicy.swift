import Foundation

public struct GatePolicy: Sendable {
    public static let window: TimeInterval = 15 * 60
    public static let cooldown: TimeInterval = 30 * 60
    public static func eligible(now: Date, lastGrant: Date?, lastWindowEnd: Date? = nil) -> Bool {
        guard let lastGrant else { return true }
        // Older installations stored only the start of their fixed 16-minute window.
        let end = lastWindowEnd ?? lastGrant.addingTimeInterval(16 * 60)
        return now >= lastGrant && now >= end.addingTimeInterval(cooldown)
    }
    public struct RelockSchedule: Sendable {
        public let expiry: Date
        public let intervalStart: Date
        public let intervalEnd: Date
    }
    public static func relockSchedule(now: Date, requestedEnd: Date) -> RelockSchedule? {
        let remaining = requestedEnd.timeIntervalSince(now)
        guard remaining > 0, remaining <= window else { return nil }
        let expiry = Date(timeIntervalSince1970: floor(requestedEnd.timeIntervalSince1970))
        guard expiry > now else { return nil }
        // iOS supports joining an ongoing interval. Keep its full span above
        // the minimum while its actual end remains the approved expiry.
        return RelockSchedule(expiry: expiry, intervalStart: expiry.addingTimeInterval(-16 * 60),
                              intervalEnd: expiry)
    }
    public static func isOpen(now: Date, expiry: Date?) -> Bool {
        guard let expiry else { return false }
        return now < expiry
    }
    public static func approves(approved: Bool, concretePurpose: Bool, exitPlan: Bool) -> Bool {
        approved && concretePurpose && exitPlan
    }
}
