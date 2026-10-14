// Executed by the Rust test with the production controller, without NSApplication
// or real biometrics. Delayed replies deliberately survive fake cancellation.
import Foundation

@MainActor
final class FakeBiometricAttempt: BiometricAttempt {
    var reply: (@MainActor (Bool) -> Void)?
    var cancelled = false
    func evaluate(_ reply: @escaping @MainActor (Bool) -> Void) { self.reply = reply }
    func cancel() { cancelled = true }
}

@MainActor
final class Harness {
    var now: TimeInterval = 10
    var active = true
    var key = true
    var available = true
    var attempts: [FakeBiometricAttempt] = []
    var results: [Bool] = []
    var waits = 0
    var reactivations = 0
    lazy var controller = ReviewAuthentication(
        clock: { self.now }, focused: { self.active && self.key },
        makeAttempt: {
            guard self.available else { return nil }
            let attempt = FakeBiometricAttempt()
            self.attempts.append(attempt)
            return attempt
        },
        waiting: { self.waits += 1 },
        reactivate: { self.reactivations += 1 },
        complete: { self.results.append($0) }
    )
    func start() { controller.appeared(); controller.becameKey() }
    func steal() { active = false; key = false; controller.resignedKey() }
    func click() { active = true; key = true; controller.becameKey() }
}

@main
struct ControllerTests {
    @MainActor
    static func main() {
        let tests: [(String, () -> Void)] = [
            ("multi-line command summary exposes every line break and keeps details", {
                let command = "echo first\n\nrm -rf fixture\r\necho\tlast"
                let text = "Full command:\n" + command
                let info = ReviewDescription(
                    agent: "Codex", host: nil, project: "fixture", repository: nil,
                    cwd: "/tmp/fixture", title: "Fixture", effect: "No execution",
                    warning: nil, command: command, executables: [], targets: [], text: text,
                    scope: "one_time", scope_text: "Only this fixture")
                precondition(ReviewDescription.inlineCommand(info.command) == "echo first ⏎  ⏎ rm -rf fixture ⏎ echo ⇥ last")
                precondition(info.commandHeading.contains("mehrere Zeilen"))
                precondition(info.command == command && info.text == text)
                precondition(ReviewDescription.inlineCommand("cargo test") == "cargo test")
            }),
            ("early steal cancels without finishing and restarts fresh", {
                let h = Harness(); h.start(); h.now += 0.03; h.steal()
                precondition(h.results.isEmpty && h.attempts[0].cancelled)
                precondition(h.waits == 1 && h.reactivations == 1)
                h.click()
                precondition(h.attempts.count == 2 && h.attempts[0] !== h.attempts[1])
                h.attempts[1].reply?(true)
                precondition(h.results == [true])
            }),
            ("cancelled success and failure replies cannot finish a new attempt", {
                let h = Harness(); h.start(); h.steal(); h.click()
                h.attempts[0].reply?(true); h.attempts[0].reply?(false)
                precondition(h.results.isEmpty && !h.attempts[1].cancelled)
                h.attempts[1].reply?(true)
                precondition(h.results == [true])
            }),
            ("success while inactive cannot approve even before resign event", {
                let h = Harness(); h.start(); h.active = false
                h.attempts[0].reply?(true)
                precondition(h.results.isEmpty && h.attempts[0].cancelled)
            }),
            ("success without key window cannot approve", {
                let h = Harness(); h.start(); h.key = false
                h.attempts[0].reply?(true)
                precondition(h.results.isEmpty && h.attempts[0].cancelled)
            }),
            ("second early steal waits for click", {
                let h = Harness(); h.start(); h.steal(); h.click(); h.steal()
                precondition(h.reactivations == 1 && h.attempts.count == 2 && h.results.isEmpty)
                h.controller.becameKey()
                precondition(h.attempts.count == 2)
                h.click(); precondition(h.attempts.count == 3)
            }),
            ("late focus loss never reactivates automatically", {
                let h = Harness(); h.start(); h.now += 1.5; h.steal()
                precondition(h.reactivations == 0 && h.results.isEmpty)
                h.click(); precondition(h.attempts.count == 2)
            }),
            ("overall timeout while waiting denies and ignores late replies", {
                let h = Harness(); h.start(); h.steal(); h.now += 120
                h.controller.deny(); h.click(); h.attempts[0].reply?(true)
                precondition(h.results == [false] && h.controller.finished && h.attempts.count == 1)
            }),
            ("explicit decline cancels active authentication", {
                let h = Harness(); h.start(); h.controller.deny(); h.attempts[0].reply?(true)
                precondition(h.results == [false] && h.attempts[0].cancelled)
            }),
            ("unavailable Touch ID denies", {
                let h = Harness(); h.available = false; h.start()
                precondition(h.results == [false] && h.attempts.isEmpty)
            }),
            ("biometric failure with focus denies", {
                let h = Harness(); h.start(); h.attempts[0].reply?(false)
                precondition(h.results == [false])
            }),
            ("duplicate become key events do not start overlapping attempts", {
                let h = Harness(); h.start(); h.controller.becameKey()
                precondition(h.attempts.count == 1)
                h.attempts[0].reply?(true); h.controller.becameKey(); h.steal()
                precondition(h.results == [true] && h.attempts.count == 1 && h.reactivations == 0)
            }),
            ("inactive window cannot start authentication", {
                let h = Harness(); h.active = false; h.start()
                precondition(h.attempts.isEmpty && h.results.isEmpty)
                h.click(); precondition(h.attempts.count == 1)
            }),
        ]
        for (name, test) in tests { test(); print("PASS: \(name)") }
        print("\(tests.count) controller cases passed")
    }
}
