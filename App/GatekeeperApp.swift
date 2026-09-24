import SwiftUI
import FamilyControls
import UserNotifications

@main
struct GatekeeperApp: App {
    @UIApplicationDelegateAdaptor(GateAppDelegate.self) private var appDelegate
    var body: some Scene { WindowGroup { GateView() } }
}

struct GateView: View {
    @Environment(\.scenePhase) private var scenePhase
    @Environment(\.colorScheme) private var colorScheme
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @State private var selection = Protection.selection
    @State private var configuration = try? ConnectorKeychain.load()
    @State private var picker = false
    @State private var showConnection = false
    @State private var showSettings = false
    @State private var busy = false
    @State private var address = ""
    @State private var deviceToken = ""
    @State private var authorized = AuthorizationCenter.shared.authorizationStatus == .approved
    @State private var expiry = Protection.expiry
    @State private var error: String?
    @State private var connectionError: String?
    @State private var lastSynced: Date?
    @State private var now = Date()
    @State private var message = ""
    private var ink: Color { colorScheme == .dark ? Color(red: 0.69, green: 0.88, blue: 0.79) : Color(red: 0.14, green: 0.34, blue: 0.28) }
    private var secondaryInk: Color { colorScheme == .dark ? Color(red: 0.66, green: 0.70, blue: 0.68) : Color(red: 0.36, green: 0.40, blue: 0.38) }
    private var surface: Color { Color(uiColor: .secondarySystemGroupedBackground) }
    private var hasSelection: Bool {
        !selection.applicationTokens.isEmpty || !selection.categoryTokens.isEmpty || !selection.webDomainTokens.isEmpty
    }
    private var isOpen: Bool { expiry.map { $0 > now } ?? false }
    private var ready: Bool { authorized && hasSelection }
    private var title: String { !authorized ? "A little space.\nOn your terms." : !hasSelection ? "Choose your\nboundaries." : isOpen ? "Make this\ntime count." : "Your attention\nis yours." }
    private var selectionSummary: String {
        var parts: [String] = []
        if !selection.applicationTokens.isEmpty { parts.append("\(selection.applicationTokens.count) apps") }
        if !selection.categoryTokens.isEmpty { parts.append("\(selection.categoryTokens.count) categories") }
        if !selection.webDomainTokens.isEmpty { parts.append("\(selection.webDomainTokens.count) websites") }
        return parts.isEmpty ? "Choose apps to protect" : parts.joined(separator: " · ")
    }
    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(alignment: .leading, spacing: 28) {
                    header
                    Text(title).font(.system(.largeTitle, design: .rounded, weight: .semibold)).tracking(-0.8)
                        .fixedSize(horizontal: false, vertical: true)
                    ProtectionDial(expiry: isOpen ? expiry : nil, now: now, ready: ready)
                        .frame(maxWidth: .infinity)
                    VStack(spacing: 10) {
                        Text(isOpen ? "A small window. A clear intention." : ready ? "Room for what matters." : "Less autopilot. More intention.")
                            .font(.title3.weight(.semibold))
                        Text(isOpen ? "Your selected apps will block again when the timer ends." : ready ? "Your selected apps are blocked. Talk to Muse when you have a reason to step in." : "Choose what pulls you away. Muse helps you decide when to let it back in.")
                            .font(.subheadline).foregroundStyle(secondaryInk).multilineTextAlignment(.center)
                            .fixedSize(horizontal: false, vertical: true)
                    }.frame(maxWidth: .infinity)
                    primaryAction
                    if let error {
                        Label(error, systemImage: "exclamationmark.circle")
                            .font(.footnote).foregroundStyle(Color(uiColor: .systemRed))
                            .padding(16).background(surface, in: RoundedRectangle(cornerRadius: 16))
                    }
                    if !message.isEmpty && error == nil {
                        Text(message).font(.footnote).foregroundStyle(secondaryInk).fixedSize(horizontal: false, vertical: true)
                    }
                    controls
                    HStack(spacing: 6) {
                        Image(systemName: "lock.shield")
                        Text("A boundary you chose.")
                    }.font(.caption).foregroundStyle(secondaryInk).frame(maxWidth: .infinity).padding(.bottom, 8)
                }.padding(.horizontal, 24).padding(.top, 12).padding(.bottom, 24)
            }
            .background(Color(uiColor: .systemGroupedBackground).ignoresSafeArea())
            .toolbar(.hidden, for: .navigationBar)
            .tint(ink)
            .familyActivityPicker(isPresented: $picker, selection: $selection)
            .sheet(isPresented: $showConnection) { connectionSheet }
            .sheet(isPresented: $showSettings) { settingsSheet }
            .onChange(of: selection) { _, value in
                Protection.selection = value; Protection.close(); expiry = nil
                Task { await sync() }
            }
            .onChange(of: scenePhase) { _, phase in
                if phase == .active { refresh(); Task { await sync() } }
            }
            .onOpenURL { url in
                if url.scheme == "gatekeeper" && url.host == "sync" { Task { await sync() } }
            }
            .task { refresh(); await sync() }
            .task {
                var ticks = 0
                while !Task.isCancelled {
                    try? await Task.sleep(for: .seconds(1))
                    if Task.isCancelled { return }
                    now = Date(); refresh(); ticks += 1
                    if ticks % 10 == 0 && scenePhase == .active { await sync() }
                }
            }
            .animation(reduceMotion ? nil : .easeOut(duration: 0.2), value: isOpen)
        }
    }
    private var header: some View {
        HStack {
            HStack(spacing: 8) {
                Image(systemName: "door.left.hand.closed").foregroundStyle(ink)
                Text("Gatekeeper").font(.headline)
            }
            Spacer()
            Button { showSettings = true } label: {
                Image(systemName: "slider.horizontal.3").font(.body.weight(.medium))
                    .frame(width: 44, height: 44).background(surface, in: Circle())
            }.accessibilityLabel("Settings and access rules")
        }
    }
    @ViewBuilder private var primaryAction: some View {
        if !authorized {
            Button { Task {
                do { try await AuthorizationCenter.shared.requestAuthorization(for: .individual); refresh() }
                catch { self.error = error.localizedDescription }
            } } label: { actionLabel("Enable protection", symbol: "lock.shield") }
                .buttonStyle(GateButtonStyle())
        } else if !hasSelection {
            Button { picker = true } label: { actionLabel("Choose apps", symbol: "plus") }.buttonStyle(GateButtonStyle())
        } else if isOpen {
            Button {
                Protection.close(); refresh()
                message = "Access ended. Your original cooldown still applies."
                Task { await sync() }
            } label: { actionLabel("Finish & protect again", symbol: "lock.fill") }
                .buttonStyle(GateButtonStyle()).disabled(busy)
        } else if configuration == nil {
            Button { openConnection() } label: { actionLabel("Connect Muse", symbol: "arrow.up.right") }.buttonStyle(GateButtonStyle())
        } else {
            Button { Task { await sync() } } label: {
                HStack(spacing: 10) {
                    if busy { ProgressView().tint(.white) } else { Image(systemName: "arrow.triangle.2.circlepath") }
                    Text(busy ? "Checking with Muse…" : "Check for approval")
                }.frame(maxWidth: .infinity)
            }.buttonStyle(GateButtonStyle()).disabled(busy)
        }
    }
    private func actionLabel(_ text: String, symbol: String) -> some View {
        HStack { Text(text); Spacer(); Image(systemName: symbol) }.frame(maxWidth: .infinity)
    }
    private var controls: some View {
        VStack(spacing: 0) {
            Button { picker = true } label: {
                controlRow("Protected apps", detail: selectionSummary, symbol: "square.grid.2x2")
            }.disabled(!authorized)
            Divider().padding(.leading, 54)
            Button { openConnection() } label: {
                controlRow("Muse connection", detail: configuration == nil ? "Pair your agent" : error != nil ? "Paired · sync needs attention" : lastSynced == nil ? "Paired · awaiting sync" : "Connected · synced this session", symbol: "waveform")
            }.disabled(busy)
        }.buttonStyle(.plain).padding(.horizontal, 16).background(surface, in: RoundedRectangle(cornerRadius: 16))
    }
    private func controlRow(_ title: String, detail: String, symbol: String) -> some View {
        HStack(spacing: 14) {
            Image(systemName: symbol).font(.title3).foregroundStyle(ink).frame(width: 24)
            VStack(alignment: .leading, spacing: 4) {
                Text(title).font(.subheadline.weight(.semibold)).foregroundStyle(.primary)
                Text(detail).font(.caption).foregroundStyle(secondaryInk).fixedSize(horizontal: false, vertical: true)
            }
            Spacer(minLength: 4)
            Image(systemName: "chevron.right").font(.caption.weight(.semibold)).foregroundStyle(secondaryInk)
        }.padding(.vertical, 18).contentShape(Rectangle())
    }
    private var settingsSheet: some View {
        NavigationStack {
            List {
                Section {
                    Label("16 minutes of access", systemImage: "timer")
                    Label("30-minute cooldown afterward", systemImage: "hourglass")
                    Label("One approval for your selected set", systemImage: "square.grid.2x2")
                } header: { Text("Your access rhythm") }
                Section("Automatic access") {
                    Button("Enable approval notifications") {
                        Task {
                            _ = try? await UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .sound])
                            UIApplication.shared.registerForRemoteNotifications()
                            try? await BackgroundBridge.shared.registerToken()
                        }
                    }
                    Text("Muse can now send approvals in the background. If automatic access is delayed, hold the approval notification and choose Start access. iOS may require you to unlock your phone.").font(.footnote)
                }
                Section("How it works") {
                    Text("Tell Muse what you need to do and when you’ll stop. Approval starts access when your iPhone receives and verifies it. If needed, use the notification action or open Gatekeeper within 5 minutes.")
                    Text("Your iPhone handles the timer. Apps block again automatically, even when the service is offline.")
                    Text("If Muse ends access early, the change applies when your iPhone receives the update or Gatekeeper next syncs.")
                }.font(.subheadline)
                Section {
                    Label("Gatekeeper + Muse", systemImage: "door.left.hand.closed")
                } footer: { Text("Designed to help you follow your own intentions.") }
            }.navigationTitle("Your boundaries").navigationBarTitleDisplayMode(.inline)
                .toolbar { ToolbarItem(placement: .confirmationAction) { Button("Done") { showSettings = false } } }
        }.tint(ink)
    }
    private var connectionSheet: some View {
        NavigationStack {
            ScrollView {
                VStack(alignment: .leading, spacing: 24) {
                    Image(systemName: "waveform.path").font(.system(size: 36)).foregroundStyle(ink).padding(.top, 12)
                    Text("Meet your\ngatekeeper.").font(.system(.largeTitle, design: .rounded, weight: .semibold))
                    Text("Muse makes the call. This iPhone keeps the boundary.").font(.body).foregroundStyle(secondaryInk)
                    VStack(alignment: .leading, spacing: 20) {
                        VStack(alignment: .leading, spacing: 8) {
                            Text("Service address").font(.subheadline.weight(.semibold))
                            TextField("https://your-service.up.railway.app", text: $address)
                                .textContentType(.URL).textInputAutocapitalization(.never).autocorrectionDisabled().keyboardType(.URL)
                                .padding(14).background(surface, in: RoundedRectangle(cornerRadius: 12))
                        }
                        VStack(alignment: .leading, spacing: 8) {
                            Text("Device token").font(.subheadline.weight(.semibold))
                            SecureField("Paste your device token", text: $deviceToken)
                                .textInputAutocapitalization(.never).autocorrectionDisabled()
                                .padding(14).background(surface, in: RoundedRectangle(cornerRadius: 12))
                            Text("Use this iPhone’s token, rather than Muse’s connector token.").font(.footnote).foregroundStyle(secondaryInk)
                        }
                    }
                    if let connectionError { Label(connectionError, systemImage: "exclamationmark.circle").font(.footnote).foregroundStyle(Color(uiColor: .systemRed)) }
                    Button { Task { await connect() } } label: {
                        HStack { if busy { ProgressView().tint(.white) }; Text(busy ? "Verifying connection…" : "Verify & connect"); Spacer(); Image(systemName: "arrow.right") }
                    }.buttonStyle(GateButtonStyle()).disabled(busy || address.isEmpty || deviceToken.isEmpty)
                    Label("Stored securely in your iPhone’s Keychain.", systemImage: "lock")
                        .font(.footnote).foregroundStyle(secondaryInk)
                }.padding(24)
            }.background(Color(uiColor: .systemGroupedBackground))
                .navigationTitle(configuration == nil ? "Connect Muse" : "Connection").navigationBarTitleDisplayMode(.inline)
                .toolbar { ToolbarItem(placement: .confirmationAction) { Button("Done") { showConnection = false }.disabled(busy) } }
                .interactiveDismissDisabled(busy)
        }.tint(ink)
    }
    private func openConnection() {
        address = configuration?.baseURL.absoluteString ?? ""
        deviceToken = ""; connectionError = nil; showConnection = true
    }
    private func connect() async {
        guard !busy else { return }
        busy = true
        do {
            let candidate = try BridgeConfiguration(address: address, token: deviceToken.trimmingCharacters(in: .whitespacesAndNewlines))
            _ = try await ConnectorClient(configuration: candidate).state()
            try ConnectorKeychain.save(candidate)
            configuration = candidate; deviceToken = ""; showConnection = false; connectionError = nil
        } catch { connectionError = error.localizedDescription }
        busy = false
        if !showConnection { await sync() }
    }
    private func refresh() {
        now = Date()
        authorized = AuthorizationCenter.shared.authorizationStatus == .approved
        if authorized { Protection.reconcile() }
        expiry = Protection.expiry
    }
    private func sync() async {
        guard !busy, configuration != nil else { return }
        busy = true; error = nil
        defer { busy = false }
        do {
            try await BackgroundBridge.shared.sync()
            lastSynced = Date()
            refresh()
            try await BackgroundBridge.shared.registerToken()

        } catch {
            refresh()
            self.error = "Could not finish syncing: \(error.localizedDescription) Any existing local timer remains in effect."
        }
    }
}

private struct GateButtonStyle: ButtonStyle {
    @Environment(\.isEnabled) private var enabled
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    func makeBody(configuration: Configuration) -> some View {
        configuration.label.font(.body.weight(.semibold)).foregroundStyle(.white)
            .padding(.horizontal, 20).padding(.vertical, 17).frame(minHeight: 54)
            .background(Color(red: 0.14, green: 0.34, blue: 0.28), in: RoundedRectangle(cornerRadius: 16))
            .opacity(enabled ? (configuration.isPressed ? 0.82 : 1) : 0.55)
            .scaleEffect(configuration.isPressed && !reduceMotion ? 0.985 : 1)
            .animation(reduceMotion ? nil : .easeOut(duration: 0.18), value: configuration.isPressed)
    }
}

private struct ProtectionDial: View {
    let expiry: Date?
    let now: Date
    let ready: Bool
    private let mint = Color(red: 0.73, green: 0.91, blue: 0.81)
    private var progress: CGFloat {
        guard let expiry else { return ready ? 1 : 0 }
        return CGFloat(min(1, max(0, expiry.timeIntervalSince(now) / GatePolicy.window)))
    }
    var body: some View {
        ZStack {
            Circle().fill(Color(red: 0.08, green: 0.18, blue: 0.15))
            Circle().strokeBorder(mint.opacity(0.15), lineWidth: 1).padding(13)
            Canvas { context, size in
                let center = CGPoint(x: size.width / 2, y: size.height / 2)
                let radius = size.width / 2 - 27
                for tick in 0..<60 {
                    let angle = Double(tick) / 60 * .pi * 2 - .pi / 2
                    let length: Double = tick % 5 == 0 ? 12 : 5
                    var path = Path()
                    path.move(to: CGPoint(x: center.x + cos(angle) * radius, y: center.y + sin(angle) * radius))
                    path.addLine(to: CGPoint(x: center.x + cos(angle) * (radius - length), y: center.y + sin(angle) * (radius - length)))
                    context.stroke(path, with: .color(mint.opacity(Double(tick) / 60 < progress ? 0.85 : 0.18)), lineWidth: tick % 5 == 0 ? 2 : 1)
                }
            }.accessibilityHidden(true)
            VStack(spacing: 12) {
                Image(systemName: expiry != nil ? "lock.open" : ready ? "lock.shield" : "lock.shield")
                    .font(.system(size: 28, weight: .light)).foregroundStyle(mint)
                if let expiry {
                    Text(expiry, style: .timer).font(.system(size: 44, weight: .medium, design: .rounded)).monospacedDigit()
                        .contentTransition(.numericText()).foregroundStyle(.white)
                    Text("TIME REMAINING").font(.system(size: 10, weight: .semibold)).tracking(2).foregroundStyle(mint)
                } else {
                    Text(ready ? "Protected" : "Make space")
                        .font(.system(size: 28, weight: .medium, design: .rounded)).foregroundStyle(.white)
                    HStack(spacing: 6) {
                        Circle().fill(mint).frame(width: 5, height: 5)
                        Text(ready ? "YOUR BOUNDARY IS ON" : "START WITH A BOUNDARY")
                            .font(.system(size: 9, weight: .semibold)).tracking(1.5)
                    }.foregroundStyle(mint)
                }
            }.padding(44)
        }.frame(width: 272, height: 272)
            .accessibilityElement(children: .ignore)
            .accessibilityLabel(expiry != nil ? "Access window open" : ready ? "Protection applied" : "Protection setup needed")
            .accessibilityValue(expiry.map { "\(max(0, Int($0.timeIntervalSince(now)))) seconds remaining" } ?? "")
    }
}
