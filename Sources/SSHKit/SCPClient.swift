import Foundation

public extension SSHConnection {
    func uploadFileWithSCP(
        localURL: URL,
        toRemotePath remotePath: String,
        permissions: UInt16 = 0o644,
        maximumSize: UInt64 = 64 * 1024 * 1024,
    ) async throws {
        try SCPPathValidator.validateRemotePath(remotePath)
        try SCPPathValidator.validatePermissions(permissions)
        let filename = try SCPPathValidator.validatedFilename(localURL.lastPathComponent)
        try SCPPathValidator.validateUploadSize(localURL: localURL, maximumSize: maximumSize)
        let data = try Data(contentsOf: localURL)
        try SCPPathValidator.validateUploadByteCount(UInt64(data.count), maximumSize: maximumSize)
        let command = try await openCommand("scp -t -- \(SCPPathValidator.shellQuoted(remotePath))")
        var reader = SCPEventReader(command: command)

        do {
            try await reader.expectAck(context: "SCP upload start")
            let mode = String(format: "%04o", permissions)
            try await command.write("C\(mode) \(data.count) \(filename)\n")
            try await reader.expectAck(context: "SCP upload header")
            try await command.write(data)
            try await command.write(Data([0]))
            try await reader.expectAck(context: "SCP upload data")
            try await command.sendEOF()
            try await reader.expectClosed(context: "SCP upload")
        } catch {
            try? await command.close()
            throw error
        }
    }

    func downloadFileWithSCP(
        remotePath: String,
        toLocalURL localURL: URL,
        maximumSize: UInt64 = 64 * 1024 * 1024,
    ) async throws {
        try SCPPathValidator.validateRemotePath(remotePath)
        let command = try await openCommand("scp -f -- \(SCPPathValidator.shellQuoted(remotePath))")
        var reader = SCPEventReader(command: command)

        do {
            try await command.write(Data([0]))
            let header = try await reader.readFileHeader(maximumSize: maximumSize)
            try SCPPathValidator.validateFilename(header.filename)
            try await command.write(Data([0]))
            let byteCount = try SCPPathValidator.validatedByteCount(header.size)
            let data = try await reader.readBytes(count: byteCount, context: "SCP download data")
            try await reader.expectAck(context: "SCP download data terminator")
            try data.write(to: localURL, options: .atomic)
            try await command.write(Data([0]))
            try await command.sendEOF()
            try await reader.expectClosed(context: "SCP download")
        } catch {
            try? await command.close()
            throw error
        }
    }
}

struct SCPFileHeader: Equatable {
    var permissions: String
    var size: UInt64
    var filename: String
}

enum SCPPathValidator {
    static func validateRemotePath(_ path: String) throws {
        guard path.isEmpty == false else {
            throw SSHKitError(code: SSHKitErrorCode.invalidState.rawValue, message: "SCP remote path must not be empty.")
        }
        guard path.utf8.contains(0) == false, path.contains("\n") == false, path.contains("\r") == false else {
            throw SSHKitError(code: SSHKitErrorCode.invalidState.rawValue, message: "SCP remote path must not contain control separators.")
        }
        guard path.hasPrefix("-") == false else {
            throw SSHKitError(code: SSHKitErrorCode.invalidState.rawValue, message: "SCP remote path must not start with '-'.")
        }
    }

    static func validatedFilename(_ filename: String) throws -> String {
        try validateFilename(filename)
        return filename
    }

    static func validateFilename(_ filename: String) throws {
        guard filename.isEmpty == false, filename != ".", filename != ".." else {
            throw SSHKitError(code: SSHKitErrorCode.invalidState.rawValue, message: "SCP filename must be a regular filename.")
        }
        guard filename.contains("/") == false, filename.utf8.contains(0) == false, filename.contains("\n") == false, filename.contains("\r") == false else {
            throw SSHKitError(code: SSHKitErrorCode.invalidState.rawValue, message: "SCP filename must not contain path or control separators.")
        }
    }

    static func validatePermissions(_ permissions: UInt16) throws {
        guard permissions <= 0o7777 else {
            throw SSHKitError(code: SSHKitErrorCode.invalidState.rawValue, message: "SCP permissions must fit in four octal digits.")
        }
    }

    static func validatedByteCount(_ size: UInt64) throws -> Int {
        guard size <= UInt64(Int.max) else {
            throw SSHKitError(code: SSHKitErrorCode.commandFailed.rawValue, message: "SCP download size exceeds this platform's addressable memory.")
        }
        return Int(size)
    }

    static func validateUploadSize(localURL: URL, maximumSize: UInt64) throws {
        let attributes = try FileManager.default.attributesOfItem(atPath: localURL.path)
        guard let size = attributes[.size] as? NSNumber else {
            throw SSHKitError(code: SSHKitErrorCode.invalidState.rawValue, message: "SCP upload source size is unavailable.")
        }
        let byteCount = size.uint64Value
        try validateUploadByteCount(byteCount, maximumSize: maximumSize)
    }

    static func validateUploadByteCount(_ byteCount: UInt64, maximumSize: UInt64) throws {
        guard byteCount <= maximumSize else {
            throw SSHKitError(code: SSHKitErrorCode.commandFailed.rawValue, message: "SCP upload size \(byteCount) exceeds maximum \(maximumSize).")
        }
    }

    static func shellQuoted(_ value: String) -> String {
        "'\(value.replacingOccurrences(of: "'", with: "'\\''"))'"
    }
}

private struct SCPEventReader {
    private var iterator: AsyncStream<SSHCommandEvent>.Iterator
    private var buffer = Data()
    private var standardError = Data()

    init(command: SSHCommand) {
        iterator = command.events.makeAsyncIterator()
    }

    mutating func expectAck(context: String) async throws {
        let byte = try await readByte(context: context)
        switch byte {
        case 0:
            return
        case 1, 2:
            let message = try await readLine(context: context)
            throw SSHKitError(code: SSHKitErrorCode.commandFailed.rawValue, message: "\(context) failed: \(message)")
        default:
            throw SSHKitError(code: SSHKitErrorCode.commandFailed.rawValue, message: "\(context) returned unexpected SCP response byte \(byte).")
        }
    }

    mutating func readFileHeader(maximumSize: UInt64) async throws -> SCPFileHeader {
        let byte = try await readByte(context: "SCP download header")
        if byte == 1 || byte == 2 {
            let message = try await readLine(context: "SCP download header")
            throw SSHKitError(code: SSHKitErrorCode.commandFailed.rawValue, message: "SCP download failed: \(message)")
        }
        guard byte == UInt8(ascii: "C") else {
            throw SSHKitError(code: SSHKitErrorCode.commandFailed.rawValue, message: "SCP download returned an unsupported response byte \(byte).")
        }

        let line = try await readLine(context: "SCP download header")
        let parts = line.split(separator: " ", maxSplits: 2, omittingEmptySubsequences: false)
        guard parts.count == 3, let size = UInt64(parts[1]) else {
            throw SSHKitError(code: SSHKitErrorCode.commandFailed.rawValue, message: "SCP download returned a malformed file header.")
        }
        guard size <= maximumSize else {
            throw SSHKitError(code: SSHKitErrorCode.commandFailed.rawValue, message: "SCP download size \(size) exceeds maximum \(maximumSize).")
        }

        return SCPFileHeader(permissions: String(parts[0]), size: size, filename: String(parts[2]))
    }

    mutating func readBytes(count: Int, context: String) async throws -> Data {
        var output = Data()
        output.reserveCapacity(count)
        while output.count < count {
            if buffer.isEmpty == false {
                let takeCount = min(count - output.count, buffer.count)
                output.append(buffer.prefix(takeCount))
                buffer.removeFirst(takeCount)
                continue
            }
            try await fillBuffer(context: context)
        }
        return output
    }

    mutating func expectClosed(context: String) async throws {
        while let event = await iterator.next() {
            switch event {
            case let .standardOutput(data):
                buffer.append(data)
            case let .standardError(data):
                standardError.append(data)
            case .closed(let status, exitSignal: _):
                guard status == 0 else {
                    let message = String(data: standardError, encoding: .utf8) ?? ""
                    throw SSHKitError(code: SSHKitErrorCode.commandFailed.rawValue, message: "\(context) exited with status \(status). \(message)")
                }
                guard buffer.isEmpty else {
                    throw SSHKitError(code: SSHKitErrorCode.commandFailed.rawValue, message: "\(context) returned unexpected trailing SCP protocol data.")
                }
                return
            }
        }
        throw SSHKitError(code: SSHKitErrorCode.commandFailed.rawValue, message: "\(context) ended without a close status.")
    }

    private mutating func readByte(context: String) async throws -> UInt8 {
        while buffer.isEmpty {
            try await fillBuffer(context: context)
        }
        return buffer.removeFirst()
    }

    private mutating func readLine(context: String) async throws -> String {
        var line = Data()
        while true {
            let byte = try await readByte(context: context)
            if byte == UInt8(ascii: "\n") {
                if line.last == UInt8(ascii: "\r") {
                    line.removeLast()
                }
                return String(data: line, encoding: .utf8) ?? ""
            }
            line.append(byte)
            if line.count > 16 * 1024 {
                throw SSHKitError(code: SSHKitErrorCode.commandFailed.rawValue, message: "\(context) line exceeded 16 KiB.")
            }
        }
    }

    private mutating func fillBuffer(context: String) async throws {
        while let event = await iterator.next() {
            switch event {
            case let .standardOutput(data):
                if data.isEmpty == false {
                    buffer.append(data)
                    return
                }
            case let .standardError(data):
                standardError.append(data)
            case .closed(let status, exitSignal: _):
                let message = String(data: standardError, encoding: .utf8) ?? ""
                throw SSHKitError(code: SSHKitErrorCode.commandFailed.rawValue, message: "\(context) ended with status \(status). \(message)")
            }
        }
        throw SSHKitError(code: SSHKitErrorCode.commandFailed.rawValue, message: "\(context) ended before SCP data arrived.")
    }
}
