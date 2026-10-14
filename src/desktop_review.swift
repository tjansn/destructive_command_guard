// Native macOS review and fresh Touch ID authentication. Candidate text is
// JSON data on stdin; this program never executes the reviewed command.
import AppKit
import Foundation
import LocalAuthentication
import LocalAuthenticationEmbeddedUI
import QuartzCore

// The window server must not infer an active-state rectangular shadow from
// NSGlassEffectView's backing surface. Clip the material and draw one explicit
// rounded shadow inside a transparent, padded window in both focus states.
@MainActor
final class ReviewPanelSurface: NSView {
    static let padding: CGFloat = 20
    static let radius: CGFloat = 28
    let clip = NSView()
    // Not `shadow`: that name would override NSView's NSShadow property.
    private let shadowLayer = CALayer()
    private let shadowCutout = CAShapeLayer()

    init(material: NSView) {
        super.init(frame: .zero)
        wantsLayer = true
        layer?.backgroundColor = NSColor.clear.cgColor
        shadowLayer.shadowColor = NSColor.black.cgColor
        shadowLayer.shadowOpacity = 0.22
        shadowLayer.shadowRadius = 10
        shadowLayer.shadowOffset = CGSize(width: 0, height: -3)
        shadowCutout.fillRule = .evenOdd
        shadowLayer.mask = shadowCutout
        layer?.addSublayer(shadowLayer)
        clip.wantsLayer = true
        clip.layer?.cornerRadius = Self.radius
        clip.layer?.masksToBounds = true
        clip.layer?.borderWidth = 0
        addSubview(clip)
        clip.addSubview(material)
        material.translatesAutoresizingMaskIntoConstraints = false
        NSLayoutConstraint.activate([
            material.leadingAnchor.constraint(equalTo: clip.leadingAnchor),
            material.trailingAnchor.constraint(equalTo: clip.trailingAnchor),
            material.topAnchor.constraint(equalTo: clip.topAnchor),
            material.bottomAnchor.constraint(equalTo: clip.bottomAnchor),
        ])
    }

    required init?(coder: NSCoder) { fatalError("init(coder:) is not supported") }

    override func layout() {
        super.layout()
        let panel = bounds.insetBy(dx: Self.padding, dy: Self.padding)
        clip.frame = panel
        CATransaction.begin()
        CATransaction.setDisableActions(true)
        shadowLayer.frame = bounds
        let outline = CGPath(roundedRect: panel, cornerWidth: Self.radius,
                             cornerHeight: Self.radius, transform: nil)
        shadowLayer.shadowPath = outline
        let cutout = CGMutablePath()
        cutout.addRect(bounds)
        cutout.addPath(outline)
        shadowCutout.frame = bounds
        shadowCutout.path = cutout
        CATransaction.commit()
    }
}

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
    let executables: [String]
    let targets: [String]
    let text: String
    let scope: String
    let scope_text: String

    static func inlineCommand(_ source: String) -> String {
        source.replacingOccurrences(of: "\r\n", with: "\n")
            .components(separatedBy: .newlines).joined(separator: " ⏎ ")
            .replacingOccurrences(of: "\t", with: " ⇥ ")
    }

    var commandHeading: String {
        command.contains(where: { $0.isNewline }) ? "Aufruf · mehrere Zeilen (Details)" : "Aufruf"
    }

    var valid: Bool {
        let required = [agent, project, cwd, title, effect, command, text, scope_text]
        let fields = required + targets + executables + [host ?? "", repository ?? "", warning ?? ""]
        return ["one_time", "exact_version", "learned_filesystem", "approved_scripts", "confined"].contains(scope) &&
            required.allSatisfy { !$0.isEmpty } && cwd.hasPrefix("/") &&
            agent.utf8.count <= 128 && project.utf8.count <= 512 &&
            (host?.utf8.count ?? 0) <= 128 && title.utf8.count <= 128 &&
            text.utf8.count <= 5_000 && targets.count <= 128 && executables.count <= 128 &&
            executables.allSatisfy { $0.hasPrefix("/") } &&
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

// UI-less state machine: an invalidated attempt can never approve a later one.
@MainActor
protocol BiometricAttempt: AnyObject {
    func evaluate(_ reply: @escaping @MainActor (Bool) -> Void)
    func cancel()
}

@MainActor
final class ReviewAuthentication {
    private let clock: () -> TimeInterval
    private let focused: () -> Bool
    private let makeAttempt: () -> BiometricAttempt?
    private let waiting: () -> Void
    private let reactivate: () -> Void
    private let complete: (Bool) -> Void
    private var appearedAt: TimeInterval?
    private var attempt: BiometricAttempt?
    private var generation: UInt64 = 0
    private var reactivated = false
    private(set) var finished = false

    init(clock: @escaping () -> TimeInterval, focused: @escaping () -> Bool,
         makeAttempt: @escaping () -> BiometricAttempt?, waiting: @escaping () -> Void,
         reactivate: @escaping () -> Void, complete: @escaping (Bool) -> Void) {
        self.clock = clock
        self.focused = focused
        self.makeAttempt = makeAttempt
        self.waiting = waiting
        self.reactivate = reactivate
        self.complete = complete
    }

    func appeared() { if appearedAt == nil { appearedAt = clock() } }

    func becameKey() {
        guard !finished, attempt == nil, focused() else { return }
        guard let fresh = makeAttempt() else { deny(); return }
        generation += 1
        let ticket = generation
        attempt = fresh
        fresh.evaluate { [weak self] success in
            guard let self, !self.finished, self.generation == ticket else { return }
            // The reply itself must observe both active app and key window.
            guard self.focused() else { self.resignedKey(); return }
            self.finish(success)
        }
    }

    func resignedKey() {
        guard !finished else { return }
        cancelAttempt()
        waiting()
        if let appearedAt, clock() - appearedAt < 1.5, !reactivated {
            reactivated = true
            reactivate()
        }
    }

    private func cancelAttempt() {
        generation += 1
        let old = attempt
        attempt = nil
        old?.cancel()
    }

    func deny() { finish(false) }

    private func finish(_ approved: Bool) {
        guard !finished else { return }
        finished = true
        cancelAttempt()
        complete(approved)
    }
}

@MainActor
final class NativeBiometricAttempt: BiometricAttempt {
    let context = LAContext()
    private let reason: String

    init?(reason: String) {
        self.reason = reason
        context.touchIDAuthenticationAllowableReuseDuration = 0
        context.localizedFallbackTitle = ""
        context.localizedCancelTitle = "Ablehnen"
        var error: NSError?
        guard context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error),
              context.biometryType == .touchID else { return nil }
    }

    func evaluate(_ reply: @escaping @MainActor (Bool) -> Void) {
        context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics,
                               localizedReason: reason) { success, _ in
            DispatchQueue.main.async { reply(success) }
        }
    }

    func cancel() { context.invalidate() }
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

// The material alone lets the backdrop through: nearly see-through over dark
// windows and without text contrast over light ones. Lay a mostly opaque
// window-background fill over it; a paused panel is fully opaque.
@MainActor
final class ReviewPanelContent: NSView {
    static let activeOpacity: CGFloat = 0.86
    var paused = false { didSet { needsDisplay = true } }

    override var wantsUpdateLayer: Bool { true }

    override func updateLayer() {
        layer?.backgroundColor = NSColor.windowBackgroundColor
            .withAlphaComponent(paused ? 1 : Self.activeOpacity).cgColor
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
    private var timer: Timer?
    // Set only by the 120-second deadline, so dcg can tell an unanswered
    // dialog from an explicit decline.
    private var expired = false
    private var authContainer: NSView?
    private var authInstruction: NSTextField?
    private var authDetail: NSTextField?
    private var panelContent: ReviewPanelContent?
    private var window: ReviewWindow?
    private var details: NSScrollView?
    private var detailsButton: NSButton?
    private var stack: NSStackView?
    private lazy var authentication: ReviewAuthentication = ReviewAuthentication(
        clock: { ProcessInfo.processInfo.systemUptime },
        focused: { [weak self] in
            NSApp.isActive && self?.window?.isVisible == true && self?.window?.isKeyWindow == true
        },
        makeAttempt: { [weak self] in self?.makeAttempt() },
        waiting: { [weak self] in
            self?.showPaused()
        },
        reactivate: { [weak self] in
            DispatchQueue.main.async {
                guard let self, !self.authentication.finished else { return }
                NSApp.activate(ignoringOtherApps: true)
                self.window?.makeKeyAndOrderFront(nil)
            }
        },
        complete: { [weak self] approved in self?.finish(approved) }
    )

    init(_ request: ReviewRequest) {
        self.request = request
        super.init()
    }

    private func finish(_ approved: Bool) -> Never {
        timer?.invalidate()
        print(approved ? "approved:\(request.nonce)" : expired ? "expired" : "denied")
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

    private func commandSummary(_ info: ReviewDescription) -> NSView {
        let command = label(ReviewDescription.inlineCommand(info.command), size: 12)
        let cwd = label(info.cwd, size: 11)
        for field in [command, cwd] {
            field.font = .monospacedSystemFont(ofSize: field === command ? 12 : 11, weight: .regular)
            field.maximumNumberOfLines = 1
            field.lineBreakMode = .byTruncatingMiddle
            field.toolTip = field.stringValue
        }
        command.toolTip = info.command
        command.setAccessibilityLabel("Genauer Aufruf: \(info.command)")
        cwd.setAccessibilityLabel("Arbeitsordner: \(info.cwd)")
        let result = vertical([label(info.commandHeading, size: 11, weight: .semibold), command,
                               label("Arbeitsordner", size: 11, weight: .semibold), cwd,
                               label(info.scope_text, size: 12)], spacing: 5)
        if !info.executables.isEmpty {
            result.insertArrangedSubview(label("Aufgelöste ausführbare Dateien", size: 11, weight: .semibold), at: 2)
            for (index, path) in info.executables.prefix(3).enumerated() {
                let executable = label(path, size: 11)
                executable.font = .monospacedSystemFont(ofSize: 11, weight: .regular)
                executable.maximumNumberOfLines = 1
                executable.lineBreakMode = .byTruncatingMiddle
                executable.toolTip = path
                result.insertArrangedSubview(executable, at: 3 + index)
            }
            if info.executables.count > 3 {
                result.insertArrangedSubview(label("Weitere ausführbare Dateien in Details", size: 11), at: 6)
            }
        }
        for row in result.arrangedSubviews {
            row.widthAnchor.constraint(equalTo: result.widthAnchor).isActive = true
        }
        return card(result)
    }

    private func evidenceDetails(_ info: ReviewDescription) -> NSScrollView {
        let value = info.text + "\n\n" + info.scope_text
        let scroll = scrollText(value, height: 150, mono: false)
        if let text = scroll.documentView as? NSTextView, let storage = text.textStorage {
            let mono = NSFont.monospacedSystemFont(ofSize: 11, weight: .regular)
            let source = value as NSString
            for literal in [info.command, info.cwd] + info.targets + info.executables {
                var start = 0
                while start < source.length {
                    let range = source.range(of: literal, options: [], range: NSRange(location: start, length: source.length - start))
                    if range.location == NSNotFound || range.length == 0 { break }
                    storage.addAttribute(.font, value: mono, range: range)
                    start = NSMaxRange(range)
                }
            }
            var offset = 0
            for line in value.components(separatedBy: "\n") {
                let length = (line as NSString).length
                if line.hasPrefix("  | ") || line.hasPrefix("/") || line.hasPrefix("~") {
                    storage.addAttribute(.font, value: mono, range: NSRange(location: offset, length: length))
                }
                offset += length + 1
            }
        }
        return scroll
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
        let auth = NSView()
        authContainer = auth
        auth.translatesAutoresizingMaskIntoConstraints = false
        auth.wantsLayer = true
        auth.layer?.masksToBounds = true
        auth.widthAnchor.constraint(equalToConstant: 48).isActive = true
        auth.heightAnchor.constraint(equalToConstant: 48).isActive = true
        let prompt = label("Finger auflegen", size: 13, weight: .semibold)
        authInstruction = prompt
        let detail = label("Diesen Vorgang freigeben", size: 11, color: .secondaryLabelColor)
        authDetail = detail
        let instruction = vertical([prompt, detail], spacing: 3)
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
        let window = ReviewWindow(contentRect: NSRect(x: 0, y: 0, width: Self.width + 2 * ReviewPanelSurface.padding, height: 480),
                                  styleMask: [.borderless], backing: .buffered, defer: false)
        self.window = window
        window.title = "DCG · \(info.agent) · \(info.project)"
        window.isReleasedWhenClosed = false
        window.isOpaque = false
        window.backgroundColor = .clear
        window.hasShadow = false
        window.level = .floating
        window.isMovableByWindowBackground = true
        window.collectionBehavior = [.canJoinAllSpaces, .fullScreenAuxiliary]
        window.delegate = self
        window.cancel = { [weak self] in self?.authentication.deny() }

        let content = ReviewPanelContent()
        panelContent = content
        content.wantsLayer = true
        content.layer?.cornerRadius = 28
        content.layer?.masksToBounds = true
        if #available(macOS 26.0, *) {
            let glass = NSGlassEffectView()
            glass.style = .regular
            glass.cornerRadius = 28
            glass.contentView = content
            window.contentView = ReviewPanelSurface(material: glass)
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
            window.contentView = ReviewPanelSurface(material: material)
        }

        let identity = identityCard(info)
        let effect = actionSummary(info)
        let command = commandSummary(info)
        let disclosure = detailsControl()
        let details = evidenceDetails(info)
        details.isHidden = true
        self.details = details
        let divider = NSBox()
        divider.boxType = .separator
        let authentication = authenticationRow()
        let stack = vertical([identity, effect, command, disclosure, details, divider, authentication], spacing: 12)
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
        for row in [identity, effect, command, disclosure, details, divider, authentication] as [NSView] {
            row.widthAnchor.constraint(equalTo: stack.widthAnchor).isActive = true
        }
        self.stack = stack
        return window
    }

    private func resizeToFit() {
        guard let window, let stack else { return }
        window.contentView?.layoutSubtreeIfNeeded()
        let old = window.frame
        let height = stack.fittingSize.height + 2 * (Self.inset + ReviewPanelSurface.padding)
        let width = Self.width + 2 * ReviewPanelSurface.padding
        window.setFrame(NSRect(x: old.minX, y: old.maxY - height, width: width, height: height), display: true)
        window.contentView?.layoutSubtreeIfNeeded()
        window.invalidateShadow()
        DispatchQueue.main.async { [weak window] in window?.invalidateShadow() }
    }

    @objc private func toggleDetails() {
        guard let details else { return }
        details.isHidden.toggle()
        detailsButton?.image = NSImage(systemSymbolName: details.isHidden ? "chevron.down" : "chevron.up",
                                       accessibilityDescription: nil)
        resizeToFit()
    }

    @objc private func decline() { authentication.deny() }

    func windowWillClose(_ notification: Notification) { authentication.deny() }

    func windowDidResize(_ notification: Notification) { window?.invalidateShadow() }

    private func showPaused() {
        authInstruction?.stringValue = "Prüfung pausiert"
        authDetail?.stringValue = "Klicke auf den Dialog, um mit Touch ID fortzufahren"
        if let container = authContainer {
            for child in container.subviews { child.removeFromSuperview() }
            let paused = icon("hand.tap", size: 24, color: .labelColor)
            container.addSubview(paused)
            NSLayoutConstraint.activate([
                paused.centerXAnchor.constraint(equalTo: container.centerXAnchor),
                paused.centerYAnchor.constraint(equalTo: container.centerYAnchor),
                paused.widthAnchor.constraint(equalToConstant: 24),
                paused.heightAnchor.constraint(equalToConstant: 24),
            ])
        }
        // Preserve readable contrast when inactive glass changes its tint.
        panelContent?.paused = true
        resizeToFit()
    }

    func windowDidResignKey(_ notification: Notification) {
        authentication.resignedKey()
    }

    func windowDidBecomeKey(_ notification: Notification) {
        // Wait until the populated window is on screen and the application is
        // active. No click, recent unlock or second system alert is required.
        DispatchQueue.main.async { [weak self] in self?.authentication.becameKey() }
    }

    private func makeAttempt() -> BiometricAttempt? {
        guard let fresh = NativeBiometricAttempt(
            reason: "\(request.description.agent): \(request.description.title)") else {
            FileHandle.standardError.write(Data("Touch ID ist nicht verfügbar. Der Vorgang bleibt gestoppt.\n".utf8))
            return nil
        }
        if let container = authContainer {
            for child in container.subviews { child.removeFromSuperview() }
            let view = LAAuthenticationView(context: fresh.context, controlSize: .large)
            view.translatesAutoresizingMaskIntoConstraints = false
            container.addSubview(view)
            NSLayoutConstraint.activate([
                view.leadingAnchor.constraint(equalTo: container.leadingAnchor),
                view.trailingAnchor.constraint(equalTo: container.trailingAnchor),
                view.topAnchor.constraint(equalTo: container.topAnchor),
                view.bottomAnchor.constraint(equalTo: container.bottomAnchor),
            ])
        }
        panelContent?.paused = false
        authInstruction?.stringValue = "Finger auflegen"
        authDetail?.stringValue = "Diesen Vorgang freigeben"
        resizeToFit()
        return fresh
    }

    func run() -> Never {
        let app = NSApplication.shared
        app.setActivationPolicy(.accessory)

        let timer = Timer(timeInterval: 120, repeats: false) { [weak self] _ in
            DispatchQueue.main.async {
                self?.expired = true
                self?.authentication.deny()
            }
        }
        self.timer = timer
        RunLoop.main.add(timer, forMode: .common)
        let window = buildWindow()
        self.window = window
        resizeToFit()
        window.center()
        authentication.appeared()
        window.makeKeyAndOrderFront(nil)
        app.activate(ignoringOtherApps: true)
        DispatchQueue.main.async { [weak self] in self?.authentication.becameKey() }
        app.run()
        authentication.deny()
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
