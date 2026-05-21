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
// This wrapper takes initial focus on the platforms where it is safe to do
// so unprompted (Mac Catalyst, native macOS, iPad with a hardware keyboard).
// On iPhone we deliberately leave focus alone, because forcing focus would
// pop the software keyboard the instant the screen appears — there the
// library's `touchesBegan` rescue is the correct entry point.
//
// We re-check focus on every `update*` rather than gating with a one-shot
// flag, so detach-then-reattach (e.g. moving between tabs of a sheet that
// hosts this view) refocuses cleanly. SwiftUI only calls `update*` when an
// observed input changes, so this does not fight a deliberate focus move
// within the same view tree.

#if canImport(UIKit)
    import UIKit

    @MainActor
    struct FocusedTerminalSurfaceView: UIViewRepresentable {
        let context: TerminalViewState

        func makeUIView(context _: Context) -> TerminalView {
            let view = TerminalView(frame: .zero)
            view.delegate = context
            view.controller = context.controller
            view.configuration = context.configuration
            // Initial focus belt-and-braces: SwiftUI calls updateUIView
            // shortly after attachment, but we don't want first-key-press to
            // depend on that contract — schedule a deferred focus attempt
            // that re-checks the window before acting.
            takeFocusIfAppropriate(view)
            return view
        }

        func updateUIView(_ view: TerminalView, context _: Context) {
            if view.controller !== context.controller {
                view.controller = context.controller
            }
            view.configuration = context.configuration
            takeFocusIfAppropriate(view)
        }

        private func takeFocusIfAppropriate(_ view: TerminalView) {
            guard Self.shouldAutoTakeFocus else { return }
            // No synchronous window/responder gate here: this is also called
            // from makeUIView where the view has no window yet. The async
            // closure re-checks both conditions before acting, so a too-early
            // call is safely deferred and a redundant call is a cheap no-op.
            DispatchQueue.main.async { [weak view] in
                guard let view, view.window != nil, !view.isFirstResponder else { return }
                view.becomeFirstResponder()
            }
        }

        /// Auto-focus is appropriate when there's a hardware keyboard
        /// expectation. On iPhone the software keyboard would appear with no
        /// user gesture, which is a UX regression versus the library's own
        /// example apps; let `touchesBegan` handle it there.
        private static var shouldAutoTakeFocus: Bool {
            #if targetEnvironment(macCatalyst)
                return true
            #else
                return UIDevice.current.userInterfaceIdiom != .phone
            #endif
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
