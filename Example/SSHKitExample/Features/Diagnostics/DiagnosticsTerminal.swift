import Foundation
import GhosttyTerminal

@MainActor
@Observable
final class DiagnosticsTerminal {
    let viewState: TerminalViewState
    private let inMemory: InMemoryTerminalSession

    init() {
        inMemory = InMemoryTerminalSession(
            write: { _ in },
            resize: { _ in },
        )
        viewState = TerminalViewState(terminalConfiguration: TerminalConfiguration())
        viewState.configuration = TerminalSurfaceOptions(backend: .inMemory(inMemory))
    }

    func write(_ data: Data) {
        inMemory.receive(data)
    }

    func write(_ string: String) {
        inMemory.receive(Data(Self.normalizeNewlines(string).utf8))
    }

    func writeLine(_ string: String = "") {
        write(string + "\r\n")
    }

    func clear() {
        inMemory.receive(Data("\u{1B}[2J\u{1B}[H".utf8))
    }

    private static func normalizeNewlines(_ s: String) -> String {
        guard s.contains("\n") else { return s }
        var out = ""
        out.reserveCapacity(s.count)
        var prev: Character?
        for ch in s {
            if ch == "\n", prev != "\r" {
                out.append("\r\n")
            } else {
                out.append(ch)
            }
            prev = ch
        }
        return out
    }
}
