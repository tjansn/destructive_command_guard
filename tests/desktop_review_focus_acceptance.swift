// Manual native acceptance: the production window and LAContext, with Orca
// stealing focus twice. No candidate is executed and no approval is stored.
import AppKit
import Foundation

@main
struct FocusAcceptance {
    @MainActor
    static func main() {
        guard let orca = NSWorkspace.shared.runningApplications.first(where: {
            $0.localizedName == "Orca"
        }) else { fatalError("Orca must be running for native acceptance") }
        let info = ReviewDescription(
            agent: "DCG-Test", host: "Orca", project: "Harmloser Dialogtest",
            repository: nil, cwd: NSTemporaryDirectory(), title: "Fokuswechsel testen",
            effect: "Kein Befehl wird ausgeführt. Der Test schließt diesen Dialog selbst.",
            warning: nil, command: "printf 'dialog test only'", targets: [],
            text: "Test: Orca übernimmt zweimal den Fokus. Keine Dateien oder Freigaben werden geändert.")
        let controller = ReviewController(ReviewRequest(description: info, nonce: String(repeating: "0", count: 32)))
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.3) {
            orca.activate(options: [.activateIgnoringOtherApps])
        }
        DispatchQueue.main.asyncAfter(deadline: .now() + 1.0) {
            precondition(NSApp.isActive && NSApp.keyWindow != nil, "first early steal must reactivate DCG")
            FileHandle.standardError.write(Data("First steal recovered; dialog still open.\n".utf8))
            orca.activate(options: [.activateIgnoringOtherApps])
        }
        DispatchQueue.main.asyncAfter(deadline: .now() + 2.0) {
            precondition(!NSApp.isActive, "second steal must leave Orca active")
            guard let window = NSApp.windows.first(where: { $0 is ReviewWindow }) as? ReviewWindow else {
                fatalError("dialog disappeared after second steal")
            }
            precondition(window.isVisible && !window.isKeyWindow, "unfocused dialog must stay visible")
            FileHandle.standardError.write(Data("Native focus acceptance passed: Orca active, dialog visible; closing without approval.\n".utf8))
            window.cancel?()
        }
        controller.run()
    }
}
