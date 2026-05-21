import Foundation

enum SimulatorDetection {
    static var isRunningInSimulator: Bool {
        #if targetEnvironment(simulator)
            true
        #else
            false
        #endif
    }
}
