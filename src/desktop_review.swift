// Native macOS review and fresh Touch ID authentication. Candidate text is
// JSON data on stdin; this program never executes the reviewed command.
import AppKit
import Foundation
import LocalAuthentication

struct ReviewRequest: Decodable {
    let text: String
    let nonce: String

    var valid: Bool {
        !text.isEmpty && text.utf8.count <= 6_000 && nonce.utf8.count == 32 &&
            nonce.utf8.allSatisfy { (48...57).contains($0) || (97...102).contains($0) }
    }
}

@MainActor
final class ReviewController {
    private let request: ReviewRequest
    private let context = LAContext()
    private var timer: Timer?
    private var finished = false

    init(_ request: ReviewRequest) {
        self.request = request
    }

    private func finish(_ approved: Bool) -> Never {
        finished = true
        timer?.invalidate()
        context.invalidate()
        print(approved ? "approved:\(request.nonce)" : "denied")
        exit(0)
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
        RunLoop.main.add(timer, forMode: .modalPanel)

        let alert = NSAlert()
        alert.messageText = "Diesen Vorgang erlauben?"
        alert.informativeText = "Lies zuerst die Erklärung. Mit „Einmal freigeben“ bestätigst du danach per Touch ID."
        alert.alertStyle = .warning
        alert.icon = NSImage(systemSymbolName: "touchid", accessibilityDescription: "Touch ID")
        alert.addButton(withTitle: "Ablehnen")
        alert.addButton(withTitle: "Einmal freigeben")

        let scroll = NSScrollView(frame: NSRect(x: 0, y: 0, width: 620, height: 385))
        scroll.hasVerticalScroller = true
        scroll.borderType = .bezelBorder
        let text = NSTextView(frame: NSRect(x: 0, y: 0, width: 600, height: 385))
        text.isEditable = false
        text.isSelectable = true
        text.isRichText = false
        text.font = .systemFont(ofSize: 13)
        text.string = request.text
        text.isVerticallyResizable = true
        text.isHorizontallyResizable = false
        text.textContainer?.containerSize = NSSize(width: 600, height: CGFloat.greatestFiniteMagnitude)
        text.textContainer?.widthTracksTextView = true
        scroll.documentView = text
        alert.accessoryView = scroll

        app.activate(ignoringOtherApps: true)
        guard alert.runModal() == .alertSecondButtonReturn else { finish(false) }

        context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics,
            localizedReason: "diesen einen Vorgang freigeben") { [weak self] success, _ in
            // LocalAuthentication invokes the reply on a private queue.
            DispatchQueue.main.async {
                guard let self, !self.finished else { return }
                self.finish(success)
            }
        }
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
