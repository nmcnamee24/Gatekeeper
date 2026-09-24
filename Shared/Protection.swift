import Foundation
import FamilyControls
import ManagedSettings
import DeviceActivity

// Change this together with BOTH entitlement files before signing.
enum Protection {
    static let group = "group.com.noah.gatekeeper"
    static let defaults = UserDefaults(suiteName: group)!
    static let store = ManagedSettingsStore(named: .init("gatekeeper"))
    static let activity = DeviceActivityName("approved-window")
    static var selection: FamilyActivitySelection {
        get {
            guard let data = defaults.data(forKey: "selection"),
                  let value = try? JSONDecoder().decode(FamilyActivitySelection.self, from: data)
            else { return FamilyActivitySelection() }
            return value
        }
        set { defaults.set(try? JSONEncoder().encode(newValue), forKey: "selection") }
    }
    static var expiry: Date? {
        get { defaults.object(forKey: "expiry") as? Date }
        set { defaults.set(newValue, forKey: "expiry") }
    }
    static var lastGrant: Date? {
        get { defaults.object(forKey: "lastGrant") as? Date }
        set { defaults.set(newValue, forKey: "lastGrant") }
    }
    static func shield() {
        let picked = selection
        store.shield.applications = picked.applicationTokens.isEmpty ? nil : picked.applicationTokens
        store.shield.applicationCategories = picked.categoryTokens.isEmpty ? nil : .specific(picked.categoryTokens)
        store.shield.webDomains = picked.webDomainTokens.isEmpty ? nil : picked.webDomainTokens
        store.shield.webDomainCategories = picked.categoryTokens.isEmpty ? nil : .specific(picked.categoryTokens)
    }
    static func close() {
        shield()
        expiry = nil
    }
    static func reconcile() {
        if !GatePolicy.isOpen(now: Date(), expiry: expiry) { close() }
    }
    static func grant(until requestedEnd: Date? = nil) throws {
        let now = Date()
        guard GatePolicy.eligible(now: now, lastGrant: lastGrant) else { throw GateError.cooldown }
        let requested = requestedEnd ?? now.addingTimeInterval(GatePolicy.window)
        guard requested.timeIntervalSince(now) > 901, requested.timeIntervalSince(now) <= GatePolicy.window else {
            throw GateError.invalidWindow
        }
        let end = Date(timeIntervalSince1970: floor(requested.timeIntervalSince1970))
        let calendar = Calendar.current
        let components: Set<Calendar.Component> = [.year, .month, .day, .hour, .minute, .second]
        let schedule = DeviceActivitySchedule(
            intervalStart: calendar.dateComponents(components, from: now),
            intervalEnd: calendar.dateComponents(components, from: end), repeats: false)
        let center = DeviceActivityCenter()
        center.stopMonitoring([activity])
        // Never unshield unless iOS accepts the relock schedule.
        try center.startMonitoring(activity, during: schedule)
        expiry = end
        lastGrant = now
        store.clearAllSettings()
    }
}
enum GateError: LocalizedError {
    case cooldown, invalidWindow
    var errorDescription: String? {
        switch self {
        case .cooldown: return "Your next request is available 30 minutes after the previous window ends."
        case .invalidWindow: return "The approved window cannot be safely scheduled. Apps remain blocked."
        }
    }
}
