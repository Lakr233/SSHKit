import Foundation
@testable import SSHKitExample
import Testing

@Suite("TerminalOutputLineDiscipline")
struct TerminalOutputLineDisciplineTests {
    @Test
    func `bare line feeds receive carriage returns`() {
        var discipline = TerminalOutputLineDiscipline()

        let result = discipline.translate(Data("a\nb\n".utf8))

        #expect(result.data == Data("a\r\nb\r\n".utf8))
        #expect(result.insertedCarriageReturns == 2)
    }

    @Test
    func `existing carriage return line feeds pass through`() {
        var discipline = TerminalOutputLineDiscipline()

        let result = discipline.translate(Data("a\r\nb\r\n".utf8))

        #expect(result.data == Data("a\r\nb\r\n".utf8))
        #expect(result.insertedCarriageReturns == 0)
    }

    @Test
    func `carriage return at chunk boundary protects following line feed`() {
        var discipline = TerminalOutputLineDiscipline()

        let first = discipline.translate(Data([0x61, 0x0D]))
        let second = discipline.translate(Data([0x0A, 0x62]))

        #expect(first.data == Data([0x61, 0x0D]))
        #expect(first.insertedCarriageReturns == 0)
        #expect(second.data == Data([0x0A, 0x62]))
        #expect(second.insertedCarriageReturns == 0)
    }
}
