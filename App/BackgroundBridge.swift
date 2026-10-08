import UIKit
import UserNotifications
import FamilyControls

enum AppRuntime {
    static var isPreview: Bool {
        #if DEBUG
        return ProcessInfo.processInfo.arguments.contains("-gatekeeper-preview")
        #else
        return false
        #endif
    }
}

// All entry points share one task, so a foreground refresh and a push cannot redeem twice.
@MainActor
final class BackgroundBridge {
    static let shared = BackgroundBridge()
    private var flight: Task<Void, Error>?
    func sync() async throws {
        guard !AppRuntime.isPreview else { return }
        if let flight { return try await flight.value }
        let task = Task { @MainActor in try await self.performSync() }
        flight = task
        defer { flight = nil }
        try await task.value
    }
    private func performSync() async throws {
        guard let configuration = try ConnectorKeychain.load() else { return }
        if configuration.hosted == true { try await AppleCredentialGate.shared.requireAuthorization() }
        try validateActive(configuration)
        let client = ConnectorClient(configuration: configuration)
        let authorized = AuthorizationCenter.shared.authorizationStatus == .approved
        if authorized { Protection.reconcile() }
        let selection = Protection.selection
        let selected = !selection.applicationTokens.isEmpty || !selection.categoryTokens.isEmpty || !selection.webDomainTokens.isEmpty
        let state = try await client.state()
        try validateActive(configuration)
        if state.lastGrantRevoked { Protection.close() }
        if authorized, selected, Protection.expiry == nil, let id = state.pendingGrantId {
            guard GatePolicy.eligible(now: Date(), lastGrant: Protection.lastGrant, lastWindowEnd: Protection.lastWindowEnd) else { throw GateError.cooldown }
            let lease = try await client.redeem(id)
            try validateActive(configuration)
            guard AuthorizationCenter.shared.authorizationStatus == .approved, lease.grantId == id else {
                throw ConnectorError.message("Protection permission changed. Apps have not been unlocked.")
            }
            // Revalidate after network I/O. The push carries no authority to unlock.
            let current = try await client.state()
            try validateActive(configuration)
            guard !current.lastGrantRevoked, current.lastGrantId == id else {
                throw ConnectorError.message("Muse cancelled this approval. Apps remain blocked.")
            }
            // An account/device switch, revocation, or picker change during the final
            // network request must not apply an approval to a different local setup.
            guard AuthorizationCenter.shared.authorizationStatus == .approved,
                  let active = try ConnectorKeychain.load(), active.token == configuration.token,
                  active.baseURL == configuration.baseURL, Protection.selection == selection else {
                throw ConnectorError.message("Your account or protection settings changed. Access has not started.")
            }
            try Protection.grant(until: lease.validatedEnd())
            Protection.defaults.set(id, forKey: "remoteGrantId")
            UNUserNotificationCenter.current().removeAllDeliveredNotifications()
        }
        let status = !authorized ? "permission_missing" : !selected ? "selection_missing" : Protection.expiry != nil ? "window_open" : "shielded"
        try await client.report(PhoneReport(state: status, grantId: Protection.defaults.string(forKey: "remoteGrantId"), localExpiry: Protection.expiry.map { ISO8601DateFormatter().string(from: $0) }))
    }
    private func validateActive(_ configuration: BridgeConfiguration) throws {
        if configuration.hosted == true {
            guard let account = try AccountKeychain.load(), account.device.token == configuration.token,
                  account.apiOrigin == configuration.baseURL.absoluteString || URL(string: account.apiOrigin) == configuration.baseURL else {
                throw ConnectorError.message("The hosted account and device credentials no longer match. Access has not started.")
            }
        }
        guard let active = try ConnectorKeychain.load(), active.token == configuration.token, active.baseURL == configuration.baseURL,
              configuration.hosted != true || AppleCredentialGate.shared.authorized else {
            throw ConnectorError.message("The account or Apple authorization changed. The previous device response was discarded.")
        }
    }
    func registerToken() async throws {
        guard !AppRuntime.isPreview else { return }
        guard let configuration = try ConnectorKeychain.load(), let token = UserDefaults.standard.string(forKey: "apnsToken") else { return }
        if configuration.hosted == true { try await AppleCredentialGate.shared.requireAuthorization(); try validateActive(configuration) }
        #if DEBUG
        let environment = "sandbox"
        #else
        let environment = "production"
        #endif
        try await ConnectorClient(configuration: configuration).registerPush(token: token, environment: environment)
    }
}

@MainActor
final class GateAppDelegate: NSObject, UIApplicationDelegate, @preconcurrency UNUserNotificationCenterDelegate {
    func application(_ application: UIApplication, didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]? = nil) -> Bool {
        let center = UNUserNotificationCenter.current()
        center.delegate = self
        let start = UNNotificationAction(identifier: "START_ACCESS", title: "Start access", options: [.authenticationRequired])
        center.setNotificationCategories([UNNotificationCategory(identifier: "GATEKEEPER_APPROVAL", actions: [start], intentIdentifiers: [])])
        if !AppRuntime.isPreview { application.registerForRemoteNotifications() }
        return true
    }
    func application(_ application: UIApplication, didRegisterForRemoteNotificationsWithDeviceToken deviceToken: Data) {
        UserDefaults.standard.set(deviceToken.map { String(format: "%02x", $0) }.joined(), forKey: "apnsToken")
        Task { try? await BackgroundBridge.shared.registerToken() }
    }
    func application(_ application: UIApplication, didFailToRegisterForRemoteNotificationsWithError error: Error) {
        UserDefaults.standard.set("Push registration failed. Reopen Gatekeeper to retry.", forKey: "pushError")
    }
    func application(_ application: UIApplication, didReceiveRemoteNotification userInfo: [AnyHashable: Any], fetchCompletionHandler completionHandler: @escaping (UIBackgroundFetchResult) -> Void) {
        Task {
            do { try await BackgroundBridge.shared.sync(); completionHandler(.newData) }
            catch { completionHandler(.failed) }
        }
    }
    func userNotificationCenter(_ center: UNUserNotificationCenter, didReceive response: UNNotificationResponse, withCompletionHandler completionHandler: @escaping () -> Void) {
        Task {
            do { try await BackgroundBridge.shared.sync() }
            catch {
                let content = UNMutableNotificationContent()
                content.title = "Access hasn’t started"
                content.body = "Open Rook to check your connection and approval."
                try? await center.add(UNNotificationRequest(identifier: "sync-failed", content: content, trigger: nil))
            }
            completionHandler()
        }
    }
    func userNotificationCenter(_ center: UNUserNotificationCenter, willPresent notification: UNNotification, withCompletionHandler completionHandler: @escaping (UNNotificationPresentationOptions) -> Void) {
        completionHandler([.banner, .list])
    }
}
