import Foundation
import SSHKit

struct ConnectionPool {
    let configuration: SSHClientConfiguration

    func run<R>(_ body: @Sendable (SSHConnection) async throws -> R) async throws -> R {
        try await SSHClient.withConnection(configuration) { connection in
            try await body(connection)
        }
    }
}
