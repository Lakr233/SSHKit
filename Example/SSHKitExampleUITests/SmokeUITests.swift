import XCTest

final class SmokeUITests: XCTestCase {
    override func setUp() {
        continueAfterFailure = false
    }

    @MainActor
    func testLaunches() {
        let app = XCUIApplication()
        app.launch()
        XCTAssertTrue(app.wait(for: .runningForeground, timeout: 10), "App did not finish launching")
    }

    @MainActor
    func testSetupSheetPresentsOnFirstLaunch() {
        let app = XCUIApplication()
        app.launchArguments += ["-AppleLanguages", "(en)", "-AppleLocale", "en_US"]
        app.launch()
        // The Setup sheet shows the Connect button as soon as fields are filled.
        let connectButton = app.buttons["SSHKitExample.Setup.Connect"]
        XCTAssertTrue(connectButton.waitForExistence(timeout: 10),
                      "Setup sheet did not present on first launch")
    }
}
