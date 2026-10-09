// Native macOS review and fresh Touch ID authentication. Candidate text is
// JSON data on stdin; this program never executes the reviewed command.
import AppKit
import Foundation
import LocalAuthentication
import LocalAuthenticationEmbeddedUI

struct ReviewDescription: Decodable {
    let agent: String
    let host: String?
    let project: String
    let repository: String?
    let cwd: String
    let title: String
    let effect: String
    let warning: String?
    let command: String
    let targets: [String]
    let text: String

    var valid: Bool {
        let required = [agent, project, cwd, title, effect, command, text]
        let fields = required + targets + [host ?? "", repository ?? "", warning ?? ""]
        return required.allSatisfy { !$0.isEmpty } && cwd.hasPrefix("/") &&
            agent.utf8.count <= 128 && project.utf8.count <= 512 &&
            (host?.utf8.count ?? 0) <= 128 && title.utf8.count <= 128 &&
            text.utf8.count <= 5_000 && targets.count <= 128 &&
            fields.reduce(0) { $0 + $1.utf8.count } <= 16_000
    }
}

struct ReviewRequest: Decodable {
    let description: ReviewDescription
    let nonce: String

    var valid: Bool {
        description.valid && nonce.utf8.count == 32 &&
            nonce.utf8.allSatisfy { (48...57).contains($0) || (97...102).contains($0) }
    }
}

@MainActor
final class ReviewWindow: NSWindow {
    var cancel: (() -> Void)?
    override var canBecomeKey: Bool { true }
    override var canBecomeMain: Bool { true }
    override func cancelOperation(_ sender: Any?) { cancel?() }
    override func performClose(_ sender: Any?) { cancel?() }
}

@MainActor
final class ReviewCard: NSView {
    override var wantsUpdateLayer: Bool { true }

    override func updateLayer() {
        let dark = effectiveAppearance.bestMatch(from: [.darkAqua, .aqua]) == .darkAqua
        layer?.backgroundColor = (dark ? NSColor.white.withAlphaComponent(0.055)
                                      : NSColor.black.withAlphaComponent(0.035)).cgColor
        layer?.cornerRadius = 12
    }

    override func viewDidChangeEffectiveAppearance() {
        super.viewDidChangeEffectiveAppearance()
        needsDisplay = true
    }
}

@MainActor
final class ReviewController: NSObject, NSWindowDelegate {
    private static let width: CGFloat = 460
    private static let inset: CGFloat = 16
    private let request: ReviewRequest
    private let context = LAContext()
    private var timer: Timer?
    private var finished = false
    private var authenticationStarted = false
    private var window: ReviewWindow?
    private var details: NSScrollView?
    private var detailsButton: NSButton?
    private var stack: NSStackView?

    init(_ request: ReviewRequest) {
        self.request = request
        super.init()
    }

    private func finish(_ approved: Bool) -> Never {
        finished = true
        timer?.invalidate()
        context.invalidate()
        print(approved ? "approved:\(request.nonce)" : "denied")
        exit(0)
    }

    private func label(_ value: String, size: CGFloat = 13,
                       weight: NSFont.Weight = .regular,
                       color: NSColor = .labelColor) -> NSTextField {
        let field = NSTextField(wrappingLabelWithString: value)
        field.font = .systemFont(ofSize: size, weight: weight)
        field.textColor = color
        field.isSelectable = true
        field.translatesAutoresizingMaskIntoConstraints = false
        return field
    }

    private func vertical(_ views: [NSView], spacing: CGFloat = 6) -> NSStackView {
        let result = NSStackView(views: views)
        result.orientation = .vertical
        result.alignment = .leading
        result.spacing = spacing
        result.translatesAutoresizingMaskIntoConstraints = false
        return result
    }

    private func horizontal(_ views: [NSView], spacing: CGFloat = 8) -> NSStackView {
        let result = NSStackView(views: views)
        result.orientation = .horizontal
        result.alignment = .centerY
        result.spacing = spacing
        result.translatesAutoresizingMaskIntoConstraints = false
        return result
    }

    private func icon(_ name: String, size: CGFloat, color: NSColor) -> NSImageView {
        let view = NSImageView(image: NSImage(systemSymbolName: name,
                                            accessibilityDescription: nil) ?? NSImage())
        view.symbolConfiguration = .init(pointSize: size, weight: .medium)
        view.contentTintColor = color
        view.translatesAutoresizingMaskIntoConstraints = false
        return view
    }

    private func spacer() -> NSView {
        let view = NSView()
        view.setContentHuggingPriority(.init(1), for: .horizontal)
        return view
    }

    private func card(_ content: NSView) -> NSView {
        let view = ReviewCard()
        view.wantsLayer = true
        view.translatesAutoresizingMaskIntoConstraints = false
        content.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(content)
        NSLayoutConstraint.activate([
            content.leadingAnchor.constraint(equalTo: view.leadingAnchor, constant: 12),
            content.trailingAnchor.constraint(equalTo: view.trailingAnchor, constant: -12),
            content.topAnchor.constraint(equalTo: view.topAnchor, constant: 12),
            content.bottomAnchor.constraint(equalTo: view.bottomAnchor, constant: -12),
        ])
        return view
    }

    private func scrollText(_ value: String, height: CGFloat, mono: Bool = false,
                            color: NSColor = .labelColor) -> NSScrollView {
        let scroll = NSScrollView()
        scroll.hasVerticalScroller = true
        scroll.autohidesScrollers = true
        scroll.drawsBackground = false
        scroll.translatesAutoresizingMaskIntoConstraints = false
        let width = Self.width - 2 * Self.inset
        let text = NSTextView(frame: NSRect(x: 0, y: 0, width: width, height: height))
        text.isEditable = false
        text.isSelectable = true
        text.isRichText = false
        text.drawsBackground = false
        text.textColor = color
        text.font = mono ? .monospacedSystemFont(ofSize: 11, weight: .regular)
                         : .systemFont(ofSize: 11)
        text.textContainerInset = NSSize(width: 0, height: 2)
        text.string = value
        text.isVerticallyResizable = true
        text.isHorizontallyResizable = false
        text.autoresizingMask = [.width]
        text.textContainer?.widthTracksTextView = true
        text.textContainer?.containerSize = NSSize(width: width, height: CGFloat.greatestFiniteMagnitude)
        scroll.documentView = text
        scroll.heightAnchor.constraint(equalToConstant: height).isActive = true
        return scroll
    }

    private func identityCard(_ info: ReviewDescription) -> NSView {
        let agentName = label(info.agent, size: 14, weight: .semibold)
        agentName.maximumNumberOfLines = 1
        agentName.lineBreakMode = .byTruncatingTail
        agentName.toolTip = info.agent
        let agent = horizontal([
            icon("terminal", size: 14, color: .controlAccentColor),
            agentName,
        ])
        if let host = info.host {
            agent.addArrangedSubview(label("· \(host)", size: 11, color: .secondaryLabelColor))
        }
        agent.addArrangedSubview(spacer())
        agent.addArrangedSubview(icon("shield.lefthalf.filled", size: 11, color: .secondaryLabelColor))
        agent.addArrangedSubview(label("DCG", size: 10, weight: .semibold, color: .secondaryLabelColor))
        let projectName = label(info.project, size: 13, weight: .medium)
        projectName.maximumNumberOfLines = 2
        projectName.lineBreakMode = .byTruncatingMiddle
        let project = horizontal([
            icon("folder", size: 12, color: .secondaryLabelColor),
            projectName,
        ])
        let identity = vertical([agent, project], spacing: 4)
        agent.widthAnchor.constraint(equalTo: identity.widthAnchor).isActive = true
        project.widthAnchor.constraint(equalTo: identity.widthAnchor).isActive = true
        return card(identity)
    }

    private func actionSummary(_ info: ReviewDescription) -> NSView {
        let action = label(info.title, size: 16, weight: .semibold)
        let explanation = label(info.effect, size: 12)
        let effect = vertical([action, explanation], spacing: 7)
        action.widthAnchor.constraint(equalTo: effect.widthAnchor).isActive = true
        explanation.widthAnchor.constraint(equalTo: effect.widthAnchor).isActive = true
        if let warning = info.warning {
            let notice = label(warning, size: 12, weight: .semibold, color: .systemOrange)
            effect.addArrangedSubview(notice)
            notice.widthAnchor.constraint(equalTo: effect.widthAnchor).isActive = true
        }
        return effect
    }

    private func detailsControl() -> NSView {
        let toggle = NSButton(title: "Details", target: self, action: #selector(toggleDetails))
        toggle.isBordered = false
        toggle.font = .systemFont(ofSize: 12, weight: .medium)
        toggle.contentTintColor = .controlAccentColor
        toggle.image = NSImage(systemSymbolName: "chevron.down", accessibilityDescription: nil)
        toggle.imagePosition = .imageTrailing
        toggle.setAccessibilityLabel("Genauen Aufruf, alle Ziele und vollständige geprüfte Skripte anzeigen")
        toggle.translatesAutoresizingMaskIntoConstraints = false
        toggle.heightAnchor.constraint(equalToConstant: 32).isActive = true
        toggle.widthAnchor.constraint(equalToConstant: 76).isActive = true
        detailsButton = toggle
        return horizontal([toggle, spacer()], spacing: 12)
    }

    private func authenticationRow() -> NSView {
        let auth = LAAuthenticationView(context: context, controlSize: .large)
        auth.translatesAutoresizingMaskIntoConstraints = false
        auth.widthAnchor.constraint(equalToConstant: 48).isActive = true
        auth.heightAnchor.constraint(equalToConstant: 48).isActive = true
        let instruction = vertical([
            label("Finger auflegen", size: 13, weight: .semibold),
            label("Diesen Vorgang einmal erlauben", size: 11, color: .secondaryLabelColor),
        ], spacing: 3)
        let cancel = NSButton(title: "Ablehnen", target: self, action: #selector(decline))
        cancel.bezelStyle = .rounded
        cancel.keyEquivalent = "\u{1b}"
        cancel.translatesAutoresizingMaskIntoConstraints = false
        cancel.heightAnchor.constraint(equalToConstant: 36).isActive = true
        cancel.widthAnchor.constraint(equalToConstant: 80).isActive = true
        let authentication = horizontal([auth, instruction, spacer(), cancel], spacing: 12)
        instruction.widthAnchor.constraint(lessThanOrEqualTo: authentication.widthAnchor, constant: -164).isActive = true
        window?.initialFirstResponder = cancel
        return authentication
    }

    private func buildWindow() -> ReviewWindow {
        let info = request.description
        let window = ReviewWindow(contentRect: NSRect(x: 0, y: 0, width: Self.width, height: 440),
                                  styleMask: [.borderless], backing: .buffered, defer: false)
        self.window = window
        window.title = "DCG · \(info.agent) · \(info.project)"
        window.isReleasedWhenClosed = false
        window.isOpaque = false
        window.backgroundColor = .clear
        window.hasShadow = true
        window.level = .floating
        window.isMovableByWindowBackground = true
        window.collectionBehavior = [.moveToActiveSpace, .fullScreenAuxiliary]
        window.delegate = self
        window.cancel = { [weak self] in self?.finish(false) }

        let content = NSView()
        if #available(macOS 26.0, *) {
            let glass = NSGlassEffectView()
            glass.style = .regular
            glass.cornerRadius = 28
            glass.contentView = content
            window.contentView = glass
        } else {
            let material = NSVisualEffectView()
            material.material = .hudWindow
            material.blendingMode = .behindWindow
            material.state = .active
            material.wantsLayer = true
            material.layer?.cornerRadius = 28
            material.layer?.masksToBounds = true
            material.addSubview(content)
            content.translatesAutoresizingMaskIntoConstraints = false
            NSLayoutConstraint.activate([
                content.leadingAnchor.constraint(equalTo: material.leadingAnchor),
                content.trailingAnchor.constraint(equalTo: material.trailingAnchor),
                content.topAnchor.constraint(equalTo: material.topAnchor),
                content.bottomAnchor.constraint(equalTo: material.bottomAnchor),
            ])
            window.contentView = material
        }

        let identity = identityCard(info)
        let effect = actionSummary(info)
        let disclosure = detailsControl()
        let details = scrollText(info.text, height: 150, mono: true)
        details.isHidden = true
        self.details = details
        let divider = NSBox()
        divider.boxType = .separator
        let authentication = authenticationRow()
        let stack = vertical([identity, effect, disclosure, details, divider, authentication], spacing: 12)
        stack.setCustomSpacing(16, after: identity)
        stack.setCustomSpacing(0, after: disclosure)
        stack.setCustomSpacing(12, after: details)
        content.addSubview(stack)
        NSLayoutConstraint.activate([
            stack.leadingAnchor.constraint(equalTo: content.leadingAnchor, constant: Self.inset),
            stack.trailingAnchor.constraint(equalTo: content.trailingAnchor, constant: -Self.inset),
            stack.topAnchor.constraint(equalTo: content.topAnchor, constant: Self.inset),
            stack.bottomAnchor.constraint(equalTo: content.bottomAnchor, constant: -Self.inset),
        ])
        for row in [identity, effect, disclosure, details, divider, authentication] as [NSView] {
            row.widthAnchor.constraint(equalTo: stack.widthAnchor).isActive = true
        }
        self.stack = stack
        return window
    }

    private func resizeToFit() {
        guard let window, let stack else { return }
        window.contentView?.layoutSubtreeIfNeeded()
        let old = window.frame
        let height = stack.fittingSize.height + 2 * Self.inset
        window.setFrame(NSRect(x: old.minX, y: old.maxY - height, width: Self.width, height: height), display: true)
    }

    @objc private func toggleDetails() {
        guard let details else { return }
        details.isHidden.toggle()
        detailsButton?.image = NSImage(systemSymbolName: details.isHidden ? "chevron.down" : "chevron.up",
                                       accessibilityDescription: nil)
        resizeToFit()
    }

    @objc private func decline() { finish(false) }

    func windowWillClose(_ notification: Notification) { finish(false) }

    func windowDidResignKey(_ notification: Notification) {
        if authenticationStarted && !finished { finish(false) }
    }

    func windowDidBecomeKey(_ notification: Notification) {
        // Wait until the populated window is on screen and the application is
        // active. No click, recent unlock or second system alert is required.
        DispatchQueue.main.async { [weak self] in self?.beginAuthentication() }
    }

    private func beginAuthentication() {
        guard !finished, !authenticationStarted,
              let window, window.isVisible, window.isKeyWindow, NSApp.isActive else { return }
        authenticationStarted = true
        context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics,
            localizedReason: "\(request.description.agent): \(request.description.title)") { [weak self] success, _ in
            DispatchQueue.main.async {
                guard let self, !self.finished else { return }
                // Switching to another application must never leave a hidden
                // approval waiting for a fingerprint intended for that app.
                self.finish(success && NSApp.isActive && self.window?.isKeyWindow == true)
            }
        }
    }

    func run() -> Never {
        let app = NSApplication.shared
        app.setActivationPolicy(.accessory)

        // A new context for every request, with no reuse of a recent unlock
        // and no code/password fallback. Only an actual Touch ID result allows.
        context.touchIDAuthenticationAllowableReuseDuration = 0
        context.localizedFallbackTitle = ""
        context.localizedCancelTitle = "Ablehnen"
        var error: NSError?
        guard context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error),
              context.biometryType == .touchID else {
            FileHandle.standardError.write(Data("Touch ID ist nicht verfügbar. Der Vorgang bleibt gestoppt.\n".utf8))
            finish(false)
        }

        let timer = Timer(timeInterval: 120, repeats: false) { [weak self] _ in
            DispatchQueue.main.async {
                guard let self, !self.finished else { return }
                self.finish(false)
            }
        }
        self.timer = timer
        RunLoop.main.add(timer, forMode: .common)
        let window = buildWindow()
        self.window = window
        resizeToFit()
        window.center()
        window.makeKeyAndOrderFront(nil)
        app.activate(ignoringOtherApps: true)
        DispatchQueue.main.async { [weak self] in self?.beginAuthentication() }
        app.run()
        finish(false)
    }
}

// A separately compiled UI test entry can choose an appearance. The same
// controller and real authentication remain active in those previews.
#if !DCG_UI_PREVIEW
@main
#endif
struct ReviewEntry {
    @MainActor
    static func main() {
        let input = FileHandle.standardInput.readDataToEndOfFile()
        guard input.count <= 32_768,
              let request = try? JSONDecoder().decode(ReviewRequest.self, from: input),
              request.valid else {
            print("denied")
            exit(2)
        }
        let controller = ReviewController(request)
        withExtendedLifetime(controller) {
            controller.run()
        }
    }
}
