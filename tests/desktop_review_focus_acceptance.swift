// Manual native acceptance: the production window and LAContext, with Orca
// stealing focus twice. No candidate is executed and no approval is stored.
import AppKit
import Foundation
import LocalAuthenticationEmbeddedUI

@main
struct FocusAcceptance {
    @MainActor
    static func main() {
        guard CommandLine.arguments.count == 3,
              ["light", "dark"].contains(CommandLine.arguments[1]) else {
            fatalError("Usage: focus-preview light|dark /absolute/temporary/screenshot-directory")
        }
        let appearance = CommandLine.arguments[1]
        let output = URL(fileURLWithPath: CommandLine.arguments[2]).standardizedFileURL.resolvingSymlinksInPath()
        precondition(output.path.hasPrefix("/private/tmp/") || output.path.hasPrefix(URL(fileURLWithPath: NSTemporaryDirectory()).resolvingSymlinksInPath().path))
        var directory: ObjCBool = false
        precondition(FileManager.default.fileExists(atPath: output.path, isDirectory: &directory) && directory.boolValue)
        NSApplication.shared.appearance = NSAppearance(named: appearance == "dark" ? .darkAqua : .aqua)
        guard let orca = NSWorkspace.shared.runningApplications.first(where: {
            $0.localizedName == "Orca"
        }) else { fatalError("Orca must be running for native acceptance") }
        let info = ReviewDescription(
            agent: "Claude Code", host: "Orca", project: "Harmloser Dialogtest",
            repository: nil, cwd: NSTemporaryDirectory(), title: "Unvollständigen Sandbox-Test prüfen",
            effect: "Kein Befehl wird ausgeführt. Der Test schließt diesen Dialog selbst.",
            warning: nil, command: "cd '/temporary/literal preview directory/node-harness' && npm test", executables: ["/opt/homebrew/bin/npm"], targets: [],
            text: "Test: Orca übernimmt zweimal den Fokus. Keine Dateien oder Freigaben werden geändert.\n\nGenauer Aufruf (nur Anzeigedaten):\ncd '/temporary/literal preview directory/node-harness' && npm test\n\nArbeitsordner:\n\(NSTemporaryDirectory())",
            scope: "one_time", scope_text: "Die Freigabe gilt nur für diesen harmlosen Dialogtest.")
        let controller = ReviewController(ReviewRequest(description: info, nonce: String(repeating: "0", count: 32)))

        @MainActor func window() -> ReviewWindow {
            guard let window = NSApp.windows.first(where: { $0 is ReviewWindow }) as? ReviewWindow else {
                fatalError("dialog disappeared during focus acceptance")
            }
            return window
        }
        @MainActor func descendants(_ view: NSView) -> [NSView] {
            [view] + view.subviews.flatMap { descendants($0) }
        }
        @MainActor func capture(_ stage: String, key: Bool) {
            let panel = window()
            precondition(panel.isVisible && panel.isKeyWindow == key)
            precondition(NSApp.isActive == key)
            panel.contentView?.layoutSubtreeIfNeeded()
            let views = descendants(panel.contentView!)
            let glyphs = views.compactMap { $0 as? LAAuthenticationView }
            if key {
                precondition(glyphs.count == 1, "one fresh biometric view per attempt")
                let glyph = glyphs[0]
                precondition(abs(glyph.frame.width - 48) < 1 && abs(glyph.frame.height - 48) < 1, "Touch ID view must stay 48 x 48")
                precondition(glyph.superview?.layer?.masksToBounds == true, "glyph container must clip")
            } else {
                precondition(glyphs.isEmpty, "paused dialog must remove the cancelled glyph")
                precondition(views.compactMap { ($0 as? NSTextField)?.stringValue }.contains("Prüfung pausiert"))
            }
            let destination = output.appendingPathComponent("\(appearance)-\(stage).png")
            precondition(!FileManager.default.fileExists(atPath: destination.path), "do not overwrite previous evidence")
            let screenshot = Process()
            screenshot.executableURL = URL(fileURLWithPath: "/usr/sbin/screencapture")
            screenshot.arguments = ["-x", "-l", String(panel.windowNumber), destination.path]
            try! screenshot.run()
            screenshot.waitUntilExit()
            precondition(screenshot.terminationStatus == 0 && FileManager.default.fileExists(atPath: destination.path))
            print("CAPTURE: \(destination.path)")
        }

        // The first steal is after the one automatic early recovery window;
        // the UI-less controller suite separately tests that early recovery.
        DispatchQueue.main.asyncAfter(deadline: .now() + 1.0) { capture("first-key", key: true) }
        DispatchQueue.main.asyncAfter(deadline: .now() + 2.0) {
            orca.activate(options: [.activateIgnoringOtherApps])
        }
        DispatchQueue.main.asyncAfter(deadline: .now() + 3.0) { capture("first-paused", key: false) }
        DispatchQueue.main.asyncAfter(deadline: .now() + 4.0) {
            window().makeKeyAndOrderFront(nil)
            NSApp.activate(ignoringOtherApps: true)
        }
        DispatchQueue.main.asyncAfter(deadline: .now() + 5.0) { capture("recreated-key", key: true) }
        DispatchQueue.main.asyncAfter(deadline: .now() + 6.0) {
            orca.activate(options: [.activateIgnoringOtherApps])
        }
        DispatchQueue.main.asyncAfter(deadline: .now() + 7.0) {
            capture("recreated-paused", key: false)
            print("PASS: four native focus/layout states; closing without approval")
            window().cancel?()
        }
        controller.run()
    }
}
