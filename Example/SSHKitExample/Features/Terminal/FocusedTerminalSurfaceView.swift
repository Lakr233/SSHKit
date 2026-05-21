import GhosttyTerminal
import SwiftUI

// Drop-in replacement for `TerminalSurfaceView` that also drives focus.
//
// `TerminalSurfaceView` (libghostty-spm) configures the underlying
// `TerminalView` but never makes it first responder. The library's own
// `UITerminalView+Interaction.touchesBegan` calls `becomeFirstResponder()`
// when a touch lands on the view, but SwiftUI gesture recognizers higher
// in the responder chain frequently swallow that touch before it reaches
// the embedded UIView — and AppKit has no equivalent rescue path at all.
// The net effect when embedded in SwiftUI: hardware keystrokes are
// silently dropped.
//
// This wrapper takes initial focus when a hardware keyboard is the
// expected input device (Mac Catalyst, native macOS, iPad/iPhone with a
// paired hardware keyboard). On touch-only devices we leave focus alone
// because forcing focus would pop the software keyboard with no user
// gesture — let the library's `touchesBegan` rescue handle that.
//
// On UIKit we also observe `GCKeyboard` connect/disconnect notifications
// while the view is attached: pairing a keyboard mid-session promotes the
// terminal to first responder; unpairing one resigns focus so iOS doesn't
// present the software keyboard.

#if canImport(UIKit)
    import GameController
    import UIKit

    @MainActor
    struct FocusedTerminalSurfaceView: UIViewRepresentable {
        let context: TerminalViewState

        func makeCoordinator() -> Coordinator {
            Coordinator()
        }

        func makeUIView(context viewContext: Context) -> TerminalView {
            let view = TerminalView(frame: .zero)
            view.delegate = context
            view.controller = context.controller
            view.configuration = context.configuration
            viewContext.coordinator.attach(to: view)
            // Initial focus belt-and-braces: SwiftUI calls updateUIView
            // shortly after attachment, but we don't want first-key-press to
            // depend on that contract — schedule a deferred focus attempt
            // that re-checks the window before acting.
            Self.takeFocusIfAppropriate(view)
            return view
        }

        func updateUIView(_ view: TerminalView, context viewContext: Context) {
            if view.controller !== context.controller {
                view.controller = context.controller
            }
            view.configuration = context.configuration
            viewContext.coordinator.attach(to: view)
            Self.takeFocusIfAppropriate(view)
        }

        static func dismantleUIView(_: TerminalView, coordinator: Coordinator) {
            coordinator.detach()
        }

        fileprivate static func takeFocusIfAppropriate(_ view: TerminalView) {
            // All gates are re-evaluated inside the closure so that a state
            // change between scheduling and the runloop tick (window detach,
            // hardware keyboard unpair, another view becoming first responder)
            // is honored. In particular, `shouldAutoTakeFocus` is re-checked
            // because a HW-keyboard disconnect during the dispatch window
            // would otherwise pop the software keyboard.
            DispatchQueue.main.async { [weak view] in
                guard let view,
                      view.window != nil,
                      !view.isFirstResponder,
                      shouldAutoTakeFocus
                else { return }
                view.becomeFirstResponder()
            }
        }

        /// Auto-focus is appropriate when there's a hardware keyboard
        /// expectation. On a touch-only device (iPhone, iPad without a paired
        /// hardware keyboard) forcing focus would present the software
        /// keyboard with zero user gesture — a UX regression versus the
        /// library's own example apps. Let `touchesBegan` handle those.
        fileprivate static var shouldAutoTakeFocus: Bool {
            #if targetEnvironment(macCatalyst)
                return true
            #else
                return GCKeyboard.coalesced != nil
            #endif
        }

        /// Observes hardware-keyboard pair/unpair while the view is attached.
        ///
        /// - Pair during session → promote terminal to first responder so the
        ///   first keystroke lands without requiring a tap.
        /// - Unpair during session → resign first responder so iOS does not
        ///   immediately present the software keyboard.
        @MainActor
        final class Coordinator {
            private weak var view: TerminalView?
            private var connectToken: NSObjectProtocol?
            private var disconnectToken: NSObjectProtocol?

            func attach(to view: TerminalView) {
                self.view = view
                #if !targetEnvironment(macCatalyst)
                    guard connectToken == nil, disconnectToken == nil else { return }
                    let center = NotificationCenter.default
                    connectToken = center.addObserver(
                        forName: .GCKeyboardDidConnect,
                        object: nil,
                        queue: .main,
                    ) { [weak self] _ in
                        MainActor.assumeIsolated { self?.handleKeyboardChange() }
                    }
                    disconnectToken = center.addObserver(
                        forName: .GCKeyboardDidDisconnect,
                        object: nil,
                        queue: .main,
                    ) { [weak self] _ in
                        MainActor.assumeIsolated { self?.handleKeyboardChange() }
                    }
                #endif
            }

            func detach() {
                let center = NotificationCenter.default
                if let connectToken { center.removeObserver(connectToken) }
                if let disconnectToken { center.removeObserver(disconnectToken) }
                connectToken = nil
                disconnectToken = nil
                view = nil
            }

            private func handleKeyboardChange() {
                guard let view, view.window != nil else { return }
                if GCKeyboard.coalesced != nil {
                    if !view.isFirstResponder { view.becomeFirstResponder() }
                } else {
                    if view.isFirstResponder { _ = view.resignFirstResponder() }
                }
            }
        }
    }

#elseif canImport(AppKit)
    import AppKit

    @MainActor
    struct FocusedTerminalSurfaceView: NSViewRepresentable {
        let context: TerminalViewState

        func makeNSView(context _: Context) -> TerminalView {
            let view = TerminalView(frame: .zero)
            view.delegate = context
            view.controller = context.controller
            view.configuration = context.configuration
            // See the UIKit branch for the rationale on the deferred focus
            // attempt: the async closure re-checks the window so it's safe
            // to call here before AppKit has attached the view.
            takeFocusIfAppropriate(view)
            return view
        }

        func updateNSView(_ view: TerminalView, context _: Context) {
            if view.controller !== context.controller {
                view.controller = context.controller
            }
            view.configuration = context.configuration
            takeFocusIfAppropriate(view)
        }

        private func takeFocusIfAppropriate(_ view: TerminalView) {
            DispatchQueue.main.async { [weak view] in
                guard let view, let window = view.window, window.firstResponder !== view else { return }
                window.makeFirstResponder(view)
            }
        }
    }
#endif
