import Foundation

/// Decodes a stream of `Data` chunks into UTF-8 strings without falsely flagging
/// valid UTF-8 as invalid when a multi-byte scalar straddles a chunk boundary.
///
/// Strategy: append each new chunk to a holdover buffer. Scan backwards from
/// the tail to find the start of any incomplete UTF-8 sequence; the bytes up
/// to that point form a complete prefix which can be safely decoded.
struct StreamingUTF8Decoder {
    private var buffer: Data = .init()

    /// Append a chunk and return whatever can now be decoded as valid UTF-8.
    /// Trailing incomplete bytes stay buffered for the next call.
    mutating func push(_ chunk: Data) -> String {
        guard !chunk.isEmpty else { return "" }
        buffer.append(chunk)
        let safeEnd = StreamingUTF8Decoder.endOfDecodableUTF8Prefix(in: buffer)
        guard safeEnd > 0 else { return "" }
        let decodable = buffer.prefix(safeEnd)
        buffer.removeFirst(safeEnd)
        return String(decoding: decodable, as: UTF8.self)
    }

    /// Drain any remaining bytes. If the residual buffer is valid UTF-8,
    /// returns the decoded string and no residual. If the residual is
    /// invalid (truncated mid-scalar), the residual bytes are returned for
    /// caller-side reporting.
    mutating func flush() -> (text: String, residual: Data) {
        let snapshot = buffer
        buffer.removeAll(keepingCapacity: false)
        if snapshot.isEmpty { return ("", Data()) }
        if let s = String(data: snapshot, encoding: .utf8) {
            return (s, Data())
        }
        return ("", snapshot)
    }

    /// Returns the largest prefix length whose bytes are valid, complete UTF-8.
    static func endOfDecodableUTF8Prefix(in data: Data) -> Int {
        // Walk back at most 3 bytes — UTF-8 scalars are 1-4 bytes, so any
        // incomplete trailing sequence must start within the last 3 bytes.
        let count = data.count
        let scanFrom = max(0, count - 3)
        for cut in stride(from: count, through: scanFrom, by: -1) {
            if cut == 0 { return 0 }
            let prefix = data.prefix(cut)
            if String(data: prefix, encoding: .utf8) != nil {
                return cut
            }
        }
        return 0
    }
}
