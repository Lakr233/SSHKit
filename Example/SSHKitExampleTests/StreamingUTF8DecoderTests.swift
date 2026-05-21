import Foundation
@testable import SSHKitExample
import Testing

@Suite("StreamingUTF8Decoder")
struct StreamingUTF8DecoderTests {
    @Test
    func `ASCII chunks decode immediately and leave no residual`() {
        var d = StreamingUTF8Decoder()
        #expect(d.push(Data("hello".utf8)) == "hello")
        #expect(d.push(Data(" world".utf8)) == " world")
        let tail = d.flush()
        #expect(tail.text == "")
        #expect(tail.residual.isEmpty)
    }

    @Test
    func `Multi-byte scalar split across chunks is buffered then emitted`() {
        var d = StreamingUTF8Decoder()
        // 中 = E4 B8 AD (3 bytes)
        let bytes: [UInt8] = [0xE4, 0xB8, 0xAD]
        #expect(d.push(Data([bytes[0], bytes[1]])) == "")
        let next = d.push(Data([bytes[2]]))
        #expect(next == "中")
        let tail = d.flush()
        #expect(tail.text == "")
        #expect(tail.residual.isEmpty)
    }

    @Test
    func `Truncated trailing bytes surface as residual on flush`() {
        var d = StreamingUTF8Decoder()
        #expect(d.push(Data("ok".utf8)) == "ok")
        // Start of a 3-byte sequence with no follow-up.
        let truncated: [UInt8] = [0xE4]
        #expect(d.push(Data(truncated)) == "")
        let tail = d.flush()
        #expect(tail.text == "")
        #expect(tail.residual == Data(truncated))
    }

    @Test
    func `Empty chunk is a no-op`() {
        var d = StreamingUTF8Decoder()
        #expect(d.push(Data()) == "")
        let tail = d.flush()
        #expect(tail.text == "")
        #expect(tail.residual.isEmpty)
    }
}
