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
final class ReviewController: NSObject, NSWindowDelegate {
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

    private func scrollText(_ value: String, height: CGFloat, mono: Bool = false) -> NSScrollView {
        let scroll = NSScrollView()
        scroll.hasVerticalScroller = true
        scroll.autohidesScrollers = true
        scroll.drawsBackground = false
        scroll.translatesAutoresizingMaskIntoConstraints = false
        let text = NSTextView(frame: NSRect(x: 0, y: 0, width: 432, height: height))
        text.isEditable = false
        text.isSelectable = true
        text.isRichText = false
        text.drawsBackground = false
        text.textColor = .secondaryLabelColor
        text.font = mono ? .monospacedSystemFont(ofSize: 11, weight: .regular)
                         : .systemFont(ofSize: 11)
        text.textContainerInset = NSSize(width: 0, height: 2)
        text.string = value
        text.isVerticallyResizable = true
        text.isHorizontallyResizable = false
        text.autoresizingMask = [.width]
        text.textContainer?.widthTracksTextView = true
        text.textContainer?.containerSize = NSSize(width: 432, height: CGFloat.greatestFiniteMagnitude)
        scroll.documentView = text
        scroll.heightAnchor.constraint(equalToConstant: height).isActive = true
        return scroll
    }

    private func buildWindow() -> ReviewWindow {
        let info = request.description
        let window = ReviewWindow(contentRect: NSRect(x: 0, y: 0, width: 480, height: 440),
                                  styleMask: [.borderless], backing: .buffered, defer: false)
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
        let surface: NSView
        if #available(macOS 26.0, *) {
            let glass = NSGlassEffectView()
            glass.style = .regular
            glass.cornerRadius = 26
            glass.contentView = content
            surface = glass
        } else {
            let material = NSVisualEffectView()
            material.material = .hudWindow
            material.blendingMode = .behindWindow
            material.state = .active
            material.wantsLayer = true
            material.layer?.cornerRadius = 26
            material.layer?.masksToBounds = true
            material.addSubview(content)
            content.translatesAutoresizingMaskIntoConstraints = false
            NSLayoutConstraint.activate([
                content.leadingAnchor.constraint(equalTo: material.leadingAnchor),
                content.trailingAnchor.constraint(equalTo: material.trailingAnchor),
                content.topAnchor.constraint(equalTo: material.topAnchor),
                content.bottomAnchor.constraint(equalTo: material.bottomAnchor),
            ])
            surface = material
        }
        window.contentView = surface

        let header = horizontal([
            icon("shield.lefthalf.filled", size: 13, color: .secondaryLabelColor),
            label("DCG · Einmalige Freigabe", size: 11, weight: .medium, color: .secondaryLabelColor),
        ])
        let agentName = label(info.agent, size: 18, weight: .semibold)
        agentName.maximumNumberOfLines = 1
        agentName.lineBreakMode = .byTruncatingTail
        agentName.toolTip = info.agent
        let agent = horizontal([
            icon("terminal", size: 17, color: .labelColor),
            agentName,
        ])
        if let host = info.host {
            agent.addArrangedSubview(label("· \(host)", size: 13, color: .secondaryLabelColor))
        }
        let projectName = label(info.project, size: 14, weight: .medium)
        projectName.maximumNumberOfLines = 2
        projectName.lineBreakMode = .byTruncatingMiddle
        projectName.toolTip = info.repository ?? info.cwd
        let project = horizontal([
            icon(info.repository == nil ? "folder" : "chevron.left.forwardslash.chevron.right", size: 13, color: .secondaryLabelColor),
            projectName,
        ])
        let path = scrollText(info.cwd, height: 34)
        path.setAccessibilityLabel("Arbeitsordner: \(info.cwd)")
        let identity = vertical([agent, project, path], spacing: 5)
        agent.widthAnchor.constraint(equalTo: identity.widthAnchor).isActive = true
        project.widthAnchor.constraint(equalTo: identity.widthAnchor).isActive = true
        path.widthAnchor.constraint(equalTo: identity.widthAnchor).isActive = true

        let action = label(info.title, size: 23, weight: .semibold)
        let explanation = label(info.effect, size: 13)
        let effect = vertical([action, explanation], spacing: 8)
        explanation.widthAnchor.constraint(equalTo: effect.widthAnchor).isActive = true
        if let warning = info.warning {
            let notice = label(warning, size: 12, weight: .semibold, color: .systemOrange)
            effect.addArrangedSubview(notice)
            notice.widthAnchor.constraint(equalTo: effect.widthAnchor).isActive = true
        }
        if !info.targets.isEmpty {
            var summary = info.targets.prefix(2).map { "• \($0)" }.joined(separator: "\n")
            if info.targets.count > 2 {
                summary += "\n+ \(info.targets.count - 2) weitere Ziele in den Details"
            }
            let targets = scrollText(summary, height: info.targets.count == 1 ? 32 : 52)
            targets.setAccessibilityLabel("Betroffene Ziele")
            effect.addArrangedSubview(targets)
            targets.widthAnchor.constraint(equalTo: effect.widthAnchor).isActive = true
        }

        let command = label(info.command, size: 11, color: .secondaryLabelColor)
        command.font = .monospacedSystemFont(ofSize: 11, weight: .regular)
        command.maximumNumberOfLines = 2
        command.lineBreakMode = .byTruncatingMiddle
        command.toolTip = info.command
        command.setAccessibilityLabel("Genauer Aufruf: \(info.command)")

        let toggle = NSButton(title: "Details und Skripte", target: self, action: #selector(toggleDetails))
        toggle.isBordered = false
        toggle.font = .systemFont(ofSize: 12, weight: .medium)
        toggle.contentTintColor = .secondaryLabelColor
        toggle.image = NSImage(systemSymbolName: "chevron.right", accessibilityDescription: nil)
        toggle.imagePosition = .imageLeading
        toggle.setAccessibilityLabel("Genauen Aufruf, alle Ziele und vollständige geprüfte Skripte anzeigen")
        toggle.heightAnchor.constraint(equalToConstant: 28).isActive = true
        detailsButton = toggle
        let details = scrollText(info.text, height: 150, mono: true)
        details.isHidden = true
        self.details = details

        let auth = LAAuthenticationView(context: context, controlSize: .large)
        auth.translatesAutoresizingMaskIntoConstraints = false
        auth.widthAnchor.constraint(equalToConstant: 48).isActive = true
        auth.heightAnchor.constraint(equalToConstant: 48).isActive = true
        let instruction = vertical([
            label("Mit Fingerabdruck erlauben", size: 13, weight: .semibold),
            label("Finger auf Touch ID legen. Gilt nur für diesen Aufruf.", size: 11, color: .secondaryLabelColor),
        ], spacing: 3)
        let authentication = horizontal([auth, instruction], spacing: 12)
        instruction.widthAnchor.constraint(equalTo: authentication.widthAnchor, constant: -60).isActive = true
        let cancel = NSButton(title: "Ablehnen", target: self, action: #selector(decline))
        cancel.bezelStyle = .rounded
        cancel.keyEquivalent = "\u{1b}"
        cancel.heightAnchor.constraint(equalToConstant: 32).isActive = true
        let spacer = NSView()
        spacer.setContentHuggingPriority(.init(1), for: .horizontal)
        let footer = horizontal([
            label("Ohne Freigabe bleibt alles gestoppt.", size: 10, color: .secondaryLabelColor),
            spacer, cancel,
        ])

        let stack = vertical([header, identity, effect, command, toggle, details, authentication, footer], spacing: 14)
        stack.setCustomSpacing(0, after: toggle)
        stack.setCustomSpacing(12, after: details)
        content.addSubview(stack)
        NSLayoutConstraint.activate([
            stack.leadingAnchor.constraint(equalTo: content.leadingAnchor, constant: 24),
            stack.trailingAnchor.constraint(equalTo: content.trailingAnchor, constant: -24),
            stack.topAnchor.constraint(equalTo: content.topAnchor, constant: 24),
            stack.bottomAnchor.constraint(equalTo: content.bottomAnchor, constant: -24),
        ])
        for row in [identity, effect, command, details, authentication, footer] as [NSView] {
            row.widthAnchor.constraint(equalTo: stack.widthAnchor).isActive = true
        }
        self.stack = stack
        return window
    }

    private func resizeToFit() {
        guard let window, let stack else { return }
        window.contentView?.layoutSubtreeIfNeeded()
        let old = window.frame
        let height = stack.fittingSize.height + 48
        window.setFrame(NSRect(x: old.minX, y: old.maxY - height, width: 480, height: height), display: true)
    }

    @objc private func toggleDetails() {
        guard let details else { return }
        details.isHidden.toggle()
        detailsButton?.image = NSImage(systemSymbolName: details.isHidden ? "chevron.right" : "chevron.down",
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

@main
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
