import DeviceActivity
import Foundation

final class ActivityMonitor: DeviceActivityMonitor {
    override func intervalDidEnd(for activity: DeviceActivityName) {
        super.intervalDidEnd(for: activity)
        guard activity == Protection.activity else { return }
        // A delayed callback from an old interval must not end a newer grant.
        if let expiry = Protection.expiry, expiry.timeIntervalSinceNow > 5 { return }
        Protection.close()
    }
}
