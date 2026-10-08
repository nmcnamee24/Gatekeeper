import SwiftUI
import AuthenticationServices
import FamilyControls
import StoreKit

private func agentPermissionName(_ scope: String) -> String {
    switch scope {
    case "gatekeeper:status": return "View protection status and cooldown"
    case "gatekeeper:approve": return "Approve time-limited access"
    case "gatekeeper:end": return "End an access window"
    default: return scope
    }
}
private let gateGreen = Color(uiColor: UIColor { traits in
    traits.userInterfaceStyle == .dark ? UIColor(red: 0.69, green: 0.88, blue: 0.79, alpha: 1) : UIColor(red: 0.14, green: 0.34, blue: 0.28, alpha: 1)
})
private let gateFill = Color(red: 0.14, green: 0.34, blue: 0.28)

struct HostedApplicationView: View {
    var body: some View {
        #if DEBUG
        if AppRuntime.isPreview { HostedPreviewView() }
        else { HostedRootView() }
        #else
        HostedRootView()
        #endif
    }
}
struct HostedRootView: View {
    @StateObject private var account = HostedAccount()
    @Environment(\.scenePhase) private var scenePhase
    @AppStorage("personalServerMode") private var personalMode = false
    @State private var tab = 0
    @State private var pendingAgent: UUID?
    @Environment(\.openURL) private var openURL
    var body: some View {
        Group {
            if personalMode {
                GateView().safeAreaInset(edge: .top) {
                    HStack {
                        Label("Personal server", systemImage: "server.rack").font(.caption.weight(.semibold))
                        Spacer()
                        Button("Use Rook") { Task { if await account.activateHosted() { personalMode = false } } }.font(.caption)
                    }.padding().background(.regularMaterial)
                }
            } else if account.session == nil {
                HostedWelcomeView(account: account, personalMode: $personalMode)
            } else {
                TabView(selection: $tab) {
                    GateView(hosted: true, onMuse: { tab = 1 }, onEndAccess: { await account.endAccess() })
                        .tabItem { Label("Protection", systemImage: "lock.shield") }.tag(0)
                    MuseView(account: account)
                        .tabItem { Label("Ask Rook", systemImage: "bubble.left.and.bubble.right") }.tag(1)
                    HostedSettingsView(account: account, personalMode: $personalMode)
                        .tabItem { Label("Settings", systemImage: "slider.horizontal.3") }.tag(2)
                }
            }
        }.tint(gateGreen)
        .task { if !personalMode { await account.reload() } }
        .onChange(of: scenePhase) { _, phase in
            if phase == .active && !personalMode {
                Task {
                    await account.reload()
                    if account.session != nil {
                        try? await BackgroundBridge.shared.sync()
                        account.confirmLocalAccess()
                    }
                }
            }
        }
        .onChange(of: personalMode) { _, mode in if !mode { Task { await account.reload() } } }
        .onOpenURL { url in
            if url.scheme == "gatekeeper", url.host == "sync" {
                Task { do { try await BackgroundBridge.shared.sync(); account.confirmLocalAccess() } catch { account.error = error.localizedDescription } }
                return
            }
            guard url.scheme == "gatekeeper", url.host == "connect-agent",
                  let parts = URLComponents(url: url, resolvingAgainstBaseURL: false),
                  let raw = parts.queryItems?.first(where: { $0.name == "request" })?.value,
                  let id = UUID(uuidString: raw) else { return }
            pendingAgent = id
            if personalMode { Task { if await account.activateHosted() { personalMode = false } } }
            if account.session != nil { Task { await account.loadAgentRequest(id) } }
        }
        .onChange(of: account.session?.user.id) { _, id in
            if id != nil, let pendingAgent { Task { await account.loadAgentRequest(pendingAgent) } }
        }
        .onChange(of: account.agentRequest?.id) { _, id in if id == nil { pendingAgent = nil } }
        .sheet(item: $account.agentRequest) { request in
            AgentConsentView(account: account, request: request) { url in openURL(url); pendingAgent = nil }
        }
    }
}

private struct HostedWelcomeView: View {
    @Environment(\.colorScheme) private var colorScheme
    @ObservedObject var account: HostedAccount
    @Binding var personalMode: Bool
    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(alignment: .leading, spacing: 28) {
                    HStack { Image(systemName: "door.left.hand.closed"); Text("Rook").font(.headline) }.foregroundStyle(gateGreen)
                    ZStack {
                        Circle().fill(gateGreen.opacity(0.08)).frame(width: 132, height: 132)
                        Circle().stroke(gateGreen.opacity(0.2), lineWidth: 1).frame(width: 108, height: 108)
                        Image(systemName: "door.left.hand.closed").font(.system(size: 46, weight: .ultraLight)).foregroundStyle(gateGreen)
                    }.frame(maxWidth: .infinity).padding(.vertical, 8).accessibilityHidden(true)
                    Text("A little space.\nOn your terms.")
                        .font(.system(.largeTitle, design: .rounded, weight: .semibold)).tracking(-0.8)
                    Text("Protect your attention. When you need to step in, Rook helps you choose a purpose, a time limit, and a way out.")
                        .font(.title3).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
                    VStack(alignment: .leading, spacing: 20) {
                        WelcomeStep(number: "1", title: "Choose your boundaries", detail: "Select apps with Apple’s private Screen Time picker.")
                        WelcomeStep(number: "2", title: "Make a small plan", detail: "Ask Rook for 1–15 minutes with a clear reason and exit plan.")
                        WelcomeStep(number: "3", title: "Let your phone keep time", detail: "Apps block again automatically, followed by a 30-minute cooldown.")
                    }.padding(20).background(Color(uiColor: .secondarySystemGroupedBackground), in: RoundedRectangle(cornerRadius: 20))

                }.padding(24)
            }.background(Color(uiColor: .systemGroupedBackground))
                .safeAreaInset(edge: .bottom) { signInFooter }
                .toolbar { ToolbarItem(placement: .topBarTrailing) {
                    Menu { Button("Use a personal server", systemImage: "server.rack") { if account.activatePersonal() { personalMode = true } } } label: { Image(systemName: "ellipsis.circle") }.accessibilityLabel("Advanced settings")
                } }
        }
    }
    private var signInFooter: some View {
        VStack(alignment: .leading, spacing: 10) {
            if account.origin != nil {
                SignInWithAppleButton(.continue, onRequest: account.configureApple) { result in
                    Task { await account.completeApple(result) }
                }.signInWithAppleButtonStyle(colorScheme == .dark ? .white : .black).frame(height: 54).clipShape(RoundedRectangle(cornerRadius: 14))
                    .disabled(account.challenge == nil || account.busy)
                if account.challenge == nil && !account.busy {
                    Button("Retry sign-in setup") { Task { await account.prepareSignIn() } }.frame(maxWidth: .infinity)
                }
                if account.busy { ProgressView("Signing in securely…").frame(maxWidth: .infinity) }
                Text("Your account pairs this iPhone automatically. No connection tokens to copy.").font(.caption).foregroundStyle(.secondary)
            } else {
                Label("Hosted sign-in is not available in this build.", systemImage: "wrench.and.screwdriver").font(.subheadline.weight(.semibold))
                Text("The release service has not been configured yet. You can use your own Gatekeeper server.").font(.caption).foregroundStyle(.secondary)
                Button("Use a personal server") { if account.activatePersonal() { personalMode = true } }.font(.subheadline.weight(.semibold))
            }
            AccountFeedback(account: account)
            HStack { PolicyLinks(); Spacer() }.font(.caption)
        }.padding(.horizontal, 24).padding(.vertical, 16).background(.regularMaterial)
    }
}
private struct WelcomeStep: View {
    let number: String; let title: String; let detail: String
    var body: some View {
        HStack(alignment: .top, spacing: 14) {
            Text(number).font(.caption.weight(.semibold)).foregroundStyle(gateGreen)
                .frame(width: 28, height: 28).background(gateGreen.opacity(0.08), in: Circle()).accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 4) {
                Text(title).font(.subheadline.weight(.semibold))
                Text(detail).font(.footnote).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            }
        }
    }
}
private struct AccountFeedback: View {
    @ObservedObject var account: HostedAccount
    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            if let error = account.error {
                Label(error, systemImage: "exclamationmark.circle").foregroundStyle(.red).font(.footnote).fixedSize(horizontal: false, vertical: true)
            }
            if let notice = account.notice {
                Label(notice, systemImage: account.approvalPending ? "clock" : "checkmark.circle").font(.footnote).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            }
        }.accessibilityElement(children: .combine)
    }
}
struct MuseView: View {
    @ObservedObject var account: HostedAccount
    @State private var draft = ""
    @State private var minutes = 5
    @State private var clearHistory = false
    @State private var localExpiry: Date?
    @State private var now = Date()
    @FocusState private var focused: Bool
    private var protectedSelection: Bool {
        let selection = Protection.selection
        return !selection.applicationTokens.isEmpty || !selection.categoryTokens.isEmpty || !selection.webDomainTokens.isEmpty
    }
    private var ready: Bool { AuthorizationCenter.shared.authorizationStatus == .approved && protectedSelection }
    private var isOpen: Bool { localExpiry.map { $0 > now } ?? false }
    var body: some View {
        NavigationStack {
            ScrollViewReader { proxy in
                ScrollView {
                    VStack(alignment: .leading, spacing: 22) {
                        VStack(alignment: .leading, spacing: 8) {
                            Text("A reason to step in.").font(.system(.title, design: .rounded, weight: .semibold))
                            Text("Tell me what you need to do, and how you’ll know you’re done.").foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
                        }.padding(.top, 8)
                        if !account.hasConsent { consentCard }
                        else if let verification = account.appleVerificationMessage {
                            Label(verification, systemImage: "person.crop.circle.badge.exclamationmark").font(.subheadline)
                            Button("Verify Apple sign-in again") { Task { await account.reload() } }
                        } else if !account.hasAccess { Label("Access requires an active subscription. Check Settings for available plans.", systemImage: "creditcard").font(.subheadline) }
                        if !ready {
                            Label("Enable Screen Time and choose your apps in Protection before asking for access.", systemImage: "lock.shield").font(.footnote).foregroundStyle(.secondary)
                        }
                        if account.messages.isEmpty {
                            VStack(alignment: .leading, spacing: 12) {
                                Image(systemName: "sparkle").foregroundStyle(gateGreen)
                                Text("Small task. Clear finish.").font(.headline)
                                Text("“I need to reply to Alex about dinner. I’ll leave as soon as the message is sent.”").font(.subheadline).foregroundStyle(.secondary)
                            }.padding(20).frame(maxWidth: .infinity, alignment: .leading)
                                .background(Color(uiColor: .secondarySystemGroupedBackground), in: RoundedRectangle(cornerRadius: 20))
                        }
                        ForEach(account.messages) { message in
                            VStack(alignment: .leading, spacing: 6) {
                                Text(message.role == "user" ? "YOU" : "ROOK").font(.caption2.weight(.semibold)).tracking(1).foregroundStyle(.secondary)
                                Text(message.content).font(.body).textSelection(.enabled).fixedSize(horizontal: false, vertical: true)
                            }.padding(18).frame(maxWidth: .infinity, alignment: .leading)
                                .background(message.role == "user" ? gateGreen.opacity(0.07) : Color(uiColor: .secondarySystemGroupedBackground), in: RoundedRectangle(cornerRadius: 18)).id(message.id)
                        }
                        if isOpen, let localExpiry {
                            VStack(alignment: .leading, spacing: 10) {
                                Label("Access confirmed on this iPhone", systemImage: "lock.open").font(.headline)
                                Text(localExpiry, style: .timer).monospacedDigit().font(.title2)
                                Button("End access & protect again") { Task { await account.endAccess(); self.localExpiry = nil } }.buttonStyle(.bordered)
                                Text("Your original 30-minute cooldown still applies if you finish early.").font(.footnote).foregroundStyle(.secondary)
                            }.padding(18).frame(maxWidth: .infinity, alignment: .leading).background(gateGreen.opacity(0.08), in: RoundedRectangle(cornerRadius: 18))
                        } else if account.approvalPending {
                            Label("Approval received · waiting for phone confirmation", systemImage: "clock").font(.subheadline.weight(.semibold))
                            Button("Check this iPhone") { Task { do { try await BackgroundBridge.shared.sync(); account.confirmLocalAccess() } catch { account.error = error.localizedDescription } } }.buttonStyle(.bordered)
                        }
                        AccountFeedback(account: account)
                        Color.clear.frame(height: 1).id("bottom")
                    }.padding(20)
                }.scrollDismissesKeyboard(.interactively)
                    .onChange(of: account.messages.count) { _, _ in withAnimation { proxy.scrollTo("bottom", anchor: .bottom) } }
                    .safeAreaInset(edge: .bottom) { composer }
            }.background(Color(uiColor: .systemGroupedBackground))
                .navigationTitle("Ask Rook").navigationBarTitleDisplayMode(.inline)
                .toolbar { ToolbarItem(placement: .topBarTrailing) {
                    Menu {
                        Button("Refresh conversation", systemImage: "arrow.clockwise") { Task { await account.reload() } }
                        Button("Clear conversation", systemImage: "trash", role: .destructive) { clearHistory = true }
                    } label: { Image(systemName: "ellipsis.circle") }.accessibilityLabel("Conversation options")
                } }
                .confirmationDialog("Clear your conversation?", isPresented: $clearHistory, titleVisibility: .visible) {
                    Button("Clear conversation", role: .destructive) { Task { await account.clearHistory() } }
                } message: { Text("Your conversation messages will be deleted. Timing records remain to preserve your cooldown.") }
                .task {
                    while !Task.isCancelled {
                        now = Date(); localExpiry = Protection.expiry; account.confirmLocalAccess()
                        try? await Task.sleep(for: .seconds(1))
                    }
                }
        }
    }
    private var consentCard: some View {
        VStack(alignment: .leading, spacing: 12) {
            Label("Before you talk to Rook", systemImage: "hand.raised").font(.headline)
            Text("When you send a request, Rook sends your message and limited recent conversation context through Vercel AI Gateway to OpenAI to consider your purpose and exit plan. Don’t include sensitive personal information. Your app selections and credentials stay out of AI requests.").font(.subheadline).foregroundStyle(.secondary)
            Text("You can clear your conversation or delete your account in Settings.").font(.footnote).foregroundStyle(.secondary)
            PolicyLinks().font(.footnote)
            Button("Agree & continue") { Task { await account.consent() } }.buttonStyle(.borderedProminent).tint(gateFill).disabled(account.busy)
        }.padding(20).background(Color(uiColor: .secondarySystemGroupedBackground), in: RoundedRectangle(cornerRadius: 20))
    }
    private var composer: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Label("Time to ask for", systemImage: "timer").font(.subheadline)
                Spacer()
                Picker("Requested minutes", selection: $minutes) { ForEach(1...15, id: \.self) { Text("\($0) min").tag($0) } }.pickerStyle(.menu)
            }
            HStack(alignment: .bottom, spacing: 12) {
                TextField("My purpose and exit plan…", text: $draft, axis: .vertical)
                    .lineLimit(2...5).focused($focused).padding(12).background(Color(uiColor: .secondarySystemGroupedBackground), in: RoundedRectangle(cornerRadius: 14))
                    .accessibilityLabel("Message to Rook: purpose and exit plan")
                Button {
                    let message = draft; focused = false
                    Task { if await account.send(message, minutes: minutes) { draft = "" } }
                } label: {
                    if account.busy { ProgressView().tint(.white).frame(width: 44, height: 44) }
                    else { Image(systemName: "arrow.up").font(.body.weight(.semibold)).frame(width: 44, height: 44) }
                }.foregroundStyle(.white).background(gateFill, in: Circle()).accessibilityLabel("Send request to Rook")
                    .disabled(account.busy || draft.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty || !account.hasConsent || !account.hasAccess || !ready || isOpen)
                    .opacity(account.hasConsent && account.hasAccess && ready && !isOpen ? 1 : 0.5)
            }
            Text("Approval starts access only after this iPhone verifies it.").font(.caption).foregroundStyle(.secondary)
        }.padding(.horizontal, 20).padding(.vertical, 14).background(.regularMaterial)
    }
}

struct HostedSettingsView: View {
    @ObservedObject var account: HostedAccount
    @Binding var personalMode: Bool
    @State private var deleting = false
    @State private var revoking: HostedDevice?
    @State private var clearing = false
    @State private var disconnecting: HostedAgent?
    @State private var connectingAgent = false
    @State private var enteredAgentRequest: UUID?
    var body: some View {
        NavigationStack {
            List {
                Section("Your account") {
                    Label(account.session?.user.displayName ?? "Signed in with Apple", systemImage: "person.crop.circle")
                    if let verification = account.appleVerificationMessage {
                        Text(verification).font(.footnote).foregroundStyle(.secondary)
                        Button("Verify Apple sign-in again") { Task { await account.reload() } }
                    }
                    Text("This iPhone is paired automatically. Your credentials are stored in Keychain.").font(.footnote).foregroundStyle(.secondary)
                }
                Section("Access") {
                    if account.betaAccess || account.account?.entitlement.betaAccess == true {
                        Label("Free beta access", systemImage: "sparkle")
                        Text("The beta is free. Subscription plans will be available at launch.").font(.footnote).foregroundStyle(.secondary)
                    } else if account.account?.entitlement.active == true {
                        Label("Subscription active", systemImage: "checkmark.seal")
                        if let expiry = account.account?.entitlement.expiresAt, let date = HostedDate.parse(expiry) { Text("Verified through \(date.formatted(date: .abbreviated, time: .omitted))").font(.footnote) }
                    } else { Text("No active subscription") }
                    ForEach(account.products, id: \.id) { product in
                        Button { Task { await account.purchase(product) } } label: {
                            VStack(alignment: .leading, spacing: 4) {
                                Text(product.displayName).font(.headline)
                                Text(product.description).font(.footnote).foregroundStyle(.secondary)
                                Text(product.displayPrice + subscriptionPeriod(product)).font(.subheadline)
                            }
                        }.disabled(account.busy)
                    }
                    Button("Restore purchases") { Task { await account.restore() } }.disabled(account.busy)
                    Link("Manage subscriptions", destination: URL(string: "https://apps.apple.com/account/subscriptions")!)
                    Text("Payment is charged to your Apple account. Subscriptions renew automatically unless canceled at least 24 hours before the current period ends. Manage or cancel in your Apple account settings.").font(.caption).foregroundStyle(.secondary)
                }
                Section("Your devices") {
                    ForEach(account.account?.devices ?? []) { device in
                        HStack {
                            VStack(alignment: .leading, spacing: 4) {
                                Text(device.name + (device.id == account.session?.device.id ? " · this iPhone" : ""))
                                if device.revokedAt != nil { Text("Revoked").font(.caption).foregroundStyle(.secondary) }
                                else if let seen = device.lastSeenAt, let date = HostedDate.parse(seen) { Text("Last seen \(date.formatted(date: .abbreviated, time: .shortened))").font(.caption).foregroundStyle(.secondary) }
                            }
                            Spacer()
                            if device.revokedAt == nil { Button("Revoke", role: .destructive) { revoking = device }.font(.subheadline).disabled(account.busy) }
                        }
                    }
                }
                Section("Privacy & help") {
                    PolicyLinks()
                    if account.hasConsent {
                        Button("Withdraw AI processing consent") { Task { await account.withdrawConsent() } }.disabled(account.busy)
                    }
                    Button("Clear conversation history", role: .destructive) { clearing = true }.disabled(account.busy)
                    Text("App selections stay on your phone. Conversation messages help Rook consider your requests; you can delete them at any time.").font(.footnote).foregroundStyle(.secondary)
                }
                Section("Connected agents") {
                    Button("Connect an agent", systemImage: "person.badge.key") { connectingAgent = true }.disabled(account.busy)
                    if account.agents.isEmpty { Text("No external agents connected").foregroundStyle(.secondary) }
                    ForEach(account.agents) { agent in
                        VStack(alignment: .leading, spacing: 8) {
                            Text(agent.clientName).font(.headline)
                            Text(agent.scopes.map(agentPermissionName).joined(separator: " · ")).font(.caption).foregroundStyle(.secondary)
                            Button("Disconnect", role: .destructive) { disconnecting = agent }.disabled(account.busy)
                        }
                    }
                    Text("External agents need your explicit permission. Disconnecting revokes their account access.").font(.footnote).foregroundStyle(.secondary)
                }
                Section("Advanced") {
                    Button("Use a personal server", systemImage: "server.rack") { if account.activatePersonal() { personalMode = true } }
                    Text("Connect your own Gatekeeper deployment and external agent using its device credential.").font(.footnote).foregroundStyle(.secondary)
                }
                Section {
                    Button("Delete account", role: .destructive) { deleting = true }.disabled(account.busy)
                    Text("Deletes your account, conversations, and server connections. Your selected apps remain protected locally.").font(.footnote).foregroundStyle(.secondary)
                }
                if account.error != nil || account.notice != nil { Section { AccountFeedback(account: account) } }
            }.navigationTitle("Settings")
                .refreshable { await account.reload() }
                .sheet(isPresented: $connectingAgent, onDismiss: {
                    if let id = enteredAgentRequest { enteredAgentRequest = nil; Task { await account.loadAgentRequest(id) } }
                }) { AgentRequestEntryView { enteredAgentRequest = $0 } }
                .confirmationDialog("Delete your Rook account?", isPresented: $deleting, titleVisibility: .visible) {
                    Button("Delete account permanently", role: .destructive) { Task { await account.deleteAccount() } }
                } message: { Text("This removes your account and its records. This cannot be undone. App Store subscriptions must be canceled separately in your Apple account.") }
                .confirmationDialog("Clear your conversation?", isPresented: $clearing, titleVisibility: .visible) {
                    Button("Clear conversation", role: .destructive) { Task { await account.clearHistory() } }
                } message: { Text("Messages are deleted. Timing records remain to preserve your cooldown.") }
                .confirmationDialog("Disconnect this agent?", isPresented: Binding(get: { disconnecting != nil }, set: { if !$0 { disconnecting = nil } }), titleVisibility: .visible) {
                    Button("Disconnect agent", role: .destructive) { if let agent = disconnecting { Task { await account.revokeAgent(agent) } }; disconnecting = nil }
                }
                .confirmationDialog("Revoke this device?", isPresented: Binding(get: { revoking != nil }, set: { if !$0 { revoking = nil } }), titleVisibility: .visible) {
                    Button("Revoke device", role: .destructive) { if let device = revoking { Task { await account.revoke(device) } }; revoking = nil }
                } message: { Text("The device will lose its server connection. This iPhone immediately relocks if you revoke it; other devices relock when they receive the update.") }
        }
    }
    private func subscriptionPeriod(_ product: Product) -> String {
        guard let period = product.subscription?.subscriptionPeriod else { return "" }
        switch period.unit {
        case .day: return " / \(period.value) day(s)"
        case .week: return " / \(period.value) week(s)"
        case .month: return " / \(period.value) month(s)"
        case .year: return " / \(period.value) year(s)"
        @unknown default: return ""
        }
    }
}
private struct AgentRequestEntryView: View {
    let completion: (UUID) -> Void
    @Environment(\.dismiss) private var dismiss
    @State private var requestID = ""
    @State private var error: String?
    var body: some View {
        NavigationStack {
            Form {
                Section("Request ID") {
                    TextField("Paste the request ID from your agent", text: $requestID).textInputAutocapitalization(.never).autocorrectionDisabled()
                    Text("Start connecting to Rook in your agent on your computer. Copy the request ID shown in its browser here to review the requested permissions.").font(.footnote).foregroundStyle(.secondary)
                    if let error { Text(error).font(.footnote).foregroundStyle(.red) }
                }
                Section {
                    Button("Review connection") {
                        guard let id = UUID(uuidString: requestID.trimmingCharacters(in: .whitespacesAndNewlines)) else { error = "Enter the complete request ID shown by your agent."; return }
                        completion(id)
                        dismiss()
                    }.disabled(requestID.isEmpty)
                }
            }.navigationTitle("Connect an agent").navigationBarTitleDisplayMode(.inline)
                .toolbar { ToolbarItem(placement: .cancellationAction) { Button("Cancel") { dismiss() } } }
        }.tint(gateGreen)
    }
}
private struct AgentConsentView: View {
    @ObservedObject var account: HostedAccount
    let request: AgentAuthorizationRequest
    let completion: (URL) -> Void
    var body: some View {
        NavigationStack {
            List {
                Section {
                    Label("Connect an external agent", systemImage: "person.badge.key").font(.title3.weight(.semibold))
                    Text("\(request.clientName) wants permission to act on your Rook account.")
                    Text("This name is supplied by the agent. Check the callback and permissions before connecting.").font(.footnote).foregroundStyle(.secondary)
                }
                Section("Permissions requested") {
                    ForEach(request.scopes, id: \.self) { scope in Text(agentPermissionName(scope)) }
                    Text("The agent can only use the permissions shown here. It cannot receive your account or device credentials.").font(.footnote).foregroundStyle(.secondary)
                }
                Section("Return to") {
                    Text(URLComponents(string: request.redirectURI)?.host ?? URLComponents(string: request.redirectURI)?.scheme ?? "Unknown callback").textSelection(.enabled)
                    Text("Only connect an agent you recognize. You can revoke access in Settings.").font(.footnote).foregroundStyle(.secondary)
                }
                Section {
                    if let notice = account.agentReturnNotice {
                        Label(notice, systemImage: "checkmark.circle").foregroundStyle(.secondary)
                        Button("Done") { account.agentRequest = nil }
                    } else {
                        Button("Allow connection") { decide(true) }.disabled(account.busy)
                        Button("Deny", role: .destructive) { decide(false) }.disabled(account.busy)
                    }
                }
                if account.error != nil { Section { AccountFeedback(account: account) } }
            }.navigationTitle("Agent permissions").navigationBarTitleDisplayMode(.inline)
                .interactiveDismissDisabled()
        }.tint(gateGreen)
    }
    private func decide(_ allow: Bool) {
        Task { if let url = await account.decideAgent(approve: allow) { completion(url) } }
    }
}
private struct PolicyLinks: View {
    var body: some View {
        ForEach([("Privacy policy", "GATEKEEPER_PRIVACY_URL"), ("Support", "GATEKEEPER_SUPPORT_URL"), ("Terms", "GATEKEEPER_TERMS_URL")], id: \.1) { label, key in
            if let raw = Bundle.main.object(forInfoDictionaryKey: key) as? String,
               let url = URL(string: raw), url.scheme == "https", url.host != nil { Link(label, destination: url) }
        }
    }
}

// Fixtures live in a separate DEBUG-only surface; they cannot authenticate or change shields.
#if DEBUG
private struct HostedPreviewView: View {
    @State private var tab = ProcessInfo.processInfo.environment["GATEKEEPER_PREVIEW_SCREEN"] == "muse" ? 1 : ProcessInfo.processInfo.environment["GATEKEEPER_PREVIEW_SCREEN"] == "settings" ? 2 : 0
    var body: some View {
        VStack(spacing: 0) {
            Text("DESIGN PREVIEW · NO LIVE ACCOUNT OR PROTECTION").font(.caption2.weight(.semibold)).padding(10).frame(maxWidth: .infinity).background(Color.yellow.opacity(0.25)).accessibilityAddTraits(.isHeader)
            TabView(selection: $tab) {
            NavigationStack {
                ScrollView {
                    VStack(alignment: .leading, spacing: 28) {
                        Label("Rook", systemImage: "door.left.hand.closed").font(.headline)
                        Text("Your attention\nis yours.").font(.system(.largeTitle, design: .rounded, weight: .semibold))
                        ProtectionDial(expiry: nil, now: Date(), ready: true).frame(maxWidth: .infinity)
                        Text("Room for what matters.").font(.title3.weight(.semibold)).frame(maxWidth: .infinity)
                        Text("Your selected apps are blocked. Ask Rook when you have a reason to step in.").font(.subheadline).foregroundStyle(.secondary).multilineTextAlignment(.center)
                        Button("Ask Rook") { tab = 1 }.buttonStyle(.borderedProminent).tint(gateFill).controlSize(.large).frame(maxWidth: .infinity)
                        Label("Protected apps · 3 apps", systemImage: "square.grid.2x2").padding(20).frame(maxWidth: .infinity, alignment: .leading).background(Color(uiColor: .secondarySystemGroupedBackground), in: RoundedRectangle(cornerRadius: 18))
                    }.padding(24)
                }.background(Color(uiColor: .systemGroupedBackground)).toolbar(.hidden, for: .navigationBar)
            }.tabItem { Label("Protection", systemImage: "lock.shield") }.tag(0)
            NavigationStack {
                ScrollView {
                    VStack(alignment: .leading, spacing: 24) {
                        Text("A reason to step in.").font(.system(.title, design: .rounded, weight: .semibold))
                        Text("Tell me what you need to do, and how you’ll know you’re done.").foregroundStyle(.secondary)
                        VStack(alignment: .leading, spacing: 8) { Text("YOU").font(.caption2).foregroundStyle(.secondary); Text("I need to reply to Alex about dinner. I’ll leave as soon as the message is sent.") }.padding(20).background(gateGreen.opacity(0.07), in: RoundedRectangle(cornerRadius: 18))
                        VStack(alignment: .leading, spacing: 8) { Text("ROOK").font(.caption2).foregroundStyle(.secondary); Text("That’s a clear plan. Five minutes to send your message, then back to your evening.") }.padding(20).background(Color(uiColor: .secondarySystemGroupedBackground), in: RoundedRectangle(cornerRadius: 18))
                        Label("Approval received · waiting for phone confirmation", systemImage: "clock").font(.subheadline.weight(.semibold))
                        Text("This is a design fixture. No access has been granted.").font(.footnote).foregroundStyle(.secondary)
                    }.padding(24)
                }.background(Color(uiColor: .systemGroupedBackground)).navigationTitle("Ask Rook")
            }.tabItem { Label("Ask Rook", systemImage: "bubble.left.and.bubble.right") }.tag(1)
            NavigationStack { List { Section("Access") { Label("Free beta access", systemImage: "sparkle"); Text("Subscriptions available at launch").foregroundStyle(.secondary) }; Section("This iPhone") { Label("Automatically paired", systemImage: "iphone"); Label("App selections stay on your phone", systemImage: "hand.raised") } }.navigationTitle("Settings") }.tabItem { Label("Settings", systemImage: "slider.horizontal.3") }.tag(2)
            }.tint(gateGreen)
        }
    }
}
#else
private struct HostedPreviewView: View { var body: some View { EmptyView() } }
#endif
