import Foundation
import AuthenticationServices

// Apple identity stays in the app's private Keychain, never in account/device HTTP JSON.
@MainActor
final class AppleCredentialGate {
    static let shared = AppleCredentialGate(
        loadIdentifier: { try AccountKeychain.loadAppleIdentifier() },
        clearCredentials: {
            try AccountKeychain.clear()
            if !UserDefaults.standard.bool(forKey: "personalServerMode") { try ConnectorKeychain.clear() }
        },
        closeProtection: { if !UserDefaults.standard.bool(forKey: "personalServerMode") { Protection.close() } },
        check: { try await ASAuthorizationAppleIDProvider().credentialState(forUserID: $0) },
        observeNotifications: true)

    private let loadIdentifier: () throws -> String?
    private let clearCredentials: () throws -> Void
    private let closeProtection: () -> Void
    private let check: (String) async throws -> ASAuthorizationAppleIDProvider.CredentialState
    private var flight: (id: UUID, task: Task<Void, Error>)?
    private var requiresNewSignIn = false
    private var verifiedIdentifier: String?
    private var verifiedAt: Date?
    private var observer: NSObjectProtocol?
    private var handlers: [(String?, Bool) -> Void] = []
    private(set) var generation = UUID()
    private(set) var message: String?
    var authorized: Bool { verifiedIdentifier != nil && message == nil }

    init(loadIdentifier: @escaping () throws -> String?, clearCredentials: @escaping () throws -> Void,
         closeProtection: @escaping () -> Void,
         check: @escaping (String) async throws -> ASAuthorizationAppleIDProvider.CredentialState,
         observeNotifications: Bool = false) {
        self.loadIdentifier = loadIdentifier; self.clearCredentials = clearCredentials
        self.closeProtection = closeProtection; self.check = check
        if observeNotifications {
            observer = NotificationCenter.default.addObserver(forName: ASAuthorizationAppleIDProvider.credentialRevokedNotification, object: nil, queue: .main) { [weak self] _ in
                // The notification itself is an Apple sign-out signal, not a network failure.
                MainActor.assumeIsolated { self?.credentialRevoked() }
            }
        }
    }
    deinit { if let observer { NotificationCenter.default.removeObserver(observer) } }
    func observe(_ handler: @escaping (String?, Bool) -> Void) { handlers.append(handler) }
    private func publish(_ message: String?, definitive: Bool = false) {
        self.message = message
        for handler in handlers { handler(message, definitive) }
    }
    func recordSuccessfulSignIn(identifier: String) {
        generation = UUID(); flight?.task.cancel(); flight = nil; requiresNewSignIn = false
        verifiedIdentifier = identifier; verifiedAt = Date(); publish(nil)
    }
    func invalidateLocalSession() {
        requiresNewSignIn = true; generation = UUID(); flight?.task.cancel(); flight = nil
        verifiedIdentifier = nil; verifiedAt = nil; publish("Sign in with Apple again to continue.")
    }
    func credentialRevoked() {
        block("Your Apple sign-in authorization was revoked. Sign in again to continue.", definitive: true)
    }
    private func block(_ reason: String, definitive: Bool) {
        generation = UUID(); verifiedIdentifier = nil; verifiedAt = nil
        requiresNewSignIn = definitive
        flight?.task.cancel(); flight = nil
        closeProtection()
        // Invalidate in-memory account generations before any secure deletion can fail.
        publish(reason, definitive: definitive)
        if definitive {
            do { try clearCredentials() }
            catch { publish(reason + " Local credentials could not be removed from Keychain; access remains blocked.", definitive: true) }
        }
    }
    func requireAuthorization(force: Bool = false) async throws {
        guard !requiresNewSignIn else { throw HostedError(message ?? "Sign in with Apple again to continue.") }
        if let flight { return try await flight.task.value }
        let identifier: String
        do {
            guard let saved = try loadIdentifier(), !saved.isEmpty else {
                block("Sign in with Apple again to verify this account on this iPhone.", definitive: true)
                throw HostedError(message!)
            }
            identifier = saved
        } catch {
            if message == nil { block("Apple sign-in could not be verified from Keychain. Access remains blocked. Unlock your iPhone and try again.", definitive: false) }
            throw error
        }
        if !force, verifiedIdentifier == identifier, let verifiedAt, Date().timeIntervalSince(verifiedAt) < 60, message == nil { return }
        let epoch = generation
        verifiedIdentifier = nil; verifiedAt = nil
        publish("Checking your Apple sign-in authorization…")
        let id = UUID()
        let task = Task { @MainActor in
            do {
                let state = try await self.check(identifier)
                try Task.checkCancellation()
                guard self.generation == epoch, try self.loadIdentifier() == identifier else { throw CancellationError() }
                switch state {
                case .authorized:
                    self.verifiedIdentifier = identifier; self.verifiedAt = Date(); self.publish(nil)
                case .revoked:
                    self.block("Your Apple sign-in authorization was revoked. Sign in again to continue.", definitive: true)
                    throw HostedError(self.message!)
                case .notFound:
                    self.block("Apple could not find this sign-in relationship. Sign in again to continue.", definitive: true)
                    throw HostedError(self.message!)
                case .transferred:
                    self.block("This Apple account needs an identifier migration after an app transfer. Access is blocked; contact support before signing in again.", definitive: true)
                    throw HostedError(self.message!)
                @unknown default:
                    self.block("Apple returned an unsupported authorization state. Access is blocked. Update the app or contact support.", definitive: false)
                    throw HostedError(self.message!)
                }
            } catch {
                if self.generation == epoch {
                    self.block("Apple sign-in could not be verified. Access remains blocked. Check your connection and try again.", definitive: false)
                }
                throw error
            }
        }
        flight = (id, task)
        defer { if flight?.id == id { flight = nil } }
        try await task.value
    }
}
