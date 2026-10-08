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
    struct LocalState {
        let authorized: Bool
        let selected: Bool
        let selection: FamilyActivitySelection
        let expiry: Date?
        let lastGrant: Date?
        let lastWindowEnd: Date?
        let remoteGrantId: String?
    }
    @MainActor struct Environment {
        let configuration: () throws -> BridgeConfiguration?
        let requireApple: (BridgeConfiguration) async throws -> Void
        let matchesAccount: (BridgeConfiguration) throws -> Bool
        let validateHosted: (BridgeConfiguration) throws -> Void
        let localState: () -> LocalState
        let reconcile: () -> Void
        let close: () -> Void
        let grant: (Date, String) throws -> Void
        let client: (BridgeConfiguration) -> ConnectorClient
        static var live: Environment {
            Environment(configuration: { try ConnectorKeychain.load() }, requireApple: { configuration in
                if configuration.hosted == true { try await AppleCredentialGate.shared.requireAuthorization() }
            }, matchesAccount: { configuration in
                guard configuration.hosted == true else { return true }
                guard let account = try AccountKeychain.load() else { return false }
                return account.device.token == configuration.token && URL(string: account.apiOrigin) == configuration.baseURL
            }, validateHosted: { configuration in
                if configuration.hosted == true, !AppleCredentialGate.shared.authorized {
                    throw ConnectorError.message("Apple authorization changed. Access has not started.")
                }
            }, localState: {
                let selection = Protection.selection
                return LocalState(authorized: AuthorizationCenter.shared.authorizationStatus == .approved,
                    selected: !selection.applicationTokens.isEmpty || !selection.categoryTokens.isEmpty || !selection.webDomainTokens.isEmpty,
                    selection: selection, expiry: Protection.expiry, lastGrant: Protection.lastGrant,
                    lastWindowEnd: Protection.lastWindowEnd, remoteGrantId: Protection.defaults.string(forKey: "remoteGrantId"))
            }, reconcile: { Protection.reconcile() }, close: { Protection.close() }, grant: { end, id in
                try Protection.grant(until: end)
                Protection.defaults.set(id, forKey: "remoteGrantId")
                UNUserNotificationCenter.current().removeAllDeliveredNotifications()
            }, client: { ConnectorClient(configuration: $0) })
        }
    }
    private let environment: Environment
    private var flight: Task<Void, Error>?
    init(environment: Environment? = nil) { self.environment = environment ?? .live }
    func sync() async throws {
        guard !AppRuntime.isPreview else { return }
        if let flight { return try await flight.value }
        let task = Task { @MainActor in try await self.performSync() }
        flight = task
        defer { flight = nil }
        try await task.value
    }
    private func performSync() async throws {
        guard let configuration = try environment.configuration() else { return }
        try await environment.requireApple(configuration)
        try validateActive(configuration)
        let client = environment.client(configuration)
        do {
            let initial = environment.localState()
            if initial.authorized { environment.reconcile() }
            let state = try await client.state()
            try validateActive(configuration)
            var latestOwnedGrantId = state.lastGrantId
            if state.lastGrantRevoked { environment.close() }
            let local = environment.localState()
            if initial.authorized, initial.selected, local.expiry == nil, let id = state.pendingGrantId {
                guard GatePolicy.eligible(now: Date(), lastGrant: local.lastGrant, lastWindowEnd: local.lastWindowEnd) else { throw GateError.cooldown }
                let lease = try await client.redeem(id)
                try validateActive(configuration)
                guard environment.localState().authorized, lease.grantId == id else {
                    throw ConnectorError.message("Protection permission changed. Apps have not been unlocked.")
                }
                let current = try await client.state()
                try validateActive(configuration)
                guard !current.lastGrantRevoked, current.lastGrantId == id else {
                    throw ConnectorError.message("Muse cancelled this approval. Apps remain blocked.")
                }
                latestOwnedGrantId = current.lastGrantId
                let beforeGrant = environment.localState()
                guard beforeGrant.authorized, beforeGrant.selection == initial.selection else {
                    throw ConnectorError.message("Your account or protection settings changed. Access has not started.")
                }
                try environment.grant(lease.validatedEnd(), id)
            }
            let report = environment.localState()
            let status = !report.authorized ? "permission_missing" : !report.selected ? "selection_missing" : report.expiry != nil ? "window_open" : "shielded"
            // The app-group ID can outlive a personal server, account or device switch.
            // Attach it only when authenticated state confirms ownership in this scope.
            let grantId = report.remoteGrantId == latestOwnedGrantId ? report.remoteGrantId : nil
            try await client.report(PhoneReport(state: status, grantId: grantId, localExpiry: report.expiry.map { ISO8601DateFormatter().string(from: $0) }))
        } catch let error as ConnectorError {
            relockIfUnauthorized(error, configuration: configuration)
            throw error
        }
    }

    private func relockIfUnauthorized(_ error: ConnectorError, configuration: BridgeConfiguration) {
        // A 401 is authoritative for this bearer, even when state cannot be read.
        // Bind it to both current Keychain records so a delayed old response cannot
        // close a new account's window or a legitimately rotated offline timer.
        if error.statusCode == 401, (try? matchesActiveCredentials(configuration)) == true {
            environment.close()
        }
    }
    private func matchesActiveCredentials(_ configuration: BridgeConfiguration) throws -> Bool {
        guard let active = try environment.configuration(), active.token == configuration.token,
              active.baseURL == configuration.baseURL, active.hosted == configuration.hosted else { return false }
        return try environment.matchesAccount(configuration)
    }
    private func validateActive(_ configuration: BridgeConfiguration) throws {
        guard try matchesActiveCredentials(configuration) else {
            throw ConnectorError.message("The account or Apple authorization changed. The previous device response was discarded.")
        }
        try environment.validateHosted(configuration)
    }
    func registerToken() async throws {
        guard !AppRuntime.isPreview else { return }
        guard let configuration = try environment.configuration(), let token = UserDefaults.standard.string(forKey: "apnsToken") else { return }
        try await environment.requireApple(configuration)
        try validateActive(configuration)
        #if DEBUG
        let pushEnvironment = "sandbox"
        #else
        let pushEnvironment = "production"
        #endif
        do {
            try await environment.client(configuration).registerPush(token: token, environment: pushEnvironment)
        } catch let error as ConnectorError {
            relockIfUnauthorized(error, configuration: configuration)
            throw error
        }
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
