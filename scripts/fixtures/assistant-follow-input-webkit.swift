// Process-targeted CGEvent keys and native drags for owned browser test windows.
import ApplicationServices
import Cocoa
import WebKit

final class Probe: NSObject, WKNavigationDelegate, WKScriptMessageHandler {
  var web: WKWebView!
  var window: NSWindow!
  var screenOrigin: CGPoint?
  var pressedKeys = Set<String>()
  // Keep split keyboard state private to this helper, never the shared HID table.
  let keySource = CGEventSource(stateID: .privateState)
  var targetPID = getpid()
  var targetIdentity: [String: Any]?
  var inputErrors = [String]()

  static func identity(_ pid: pid_t) -> [String: Any]? {
    guard let app = NSRunningApplication(processIdentifier: pid), !app.isTerminated,
          let launched = app.launchDate, let executable = app.executableURL else { return nil }
    return ["pid": Int(pid), "launched": launched.timeIntervalSince1970, "executable": executable.path]
  }

  func ownsTarget() -> Bool {
    if targetPID == getpid() { return true }
    guard let expected = targetIdentity, let actual = Probe.identity(targetPID) else { return false }
    return NSDictionary(dictionary: expected).isEqual(to: actual)
  }

  func diagnostics() -> [String: Any] {
    let frontmost = NSWorkspace.shared.frontmostApplication?.processIdentifier ?? -1
    return ["accessibilityTrusted": AXIsProcessTrusted(), "frontmostPID": Int(frontmost),
      "helperPID": Int(getpid()), "targetPID": Int(targetPID), "targetIsFrontmost": frontmost == targetPID,
      "targetIdentityValid": ownsTarget(), "keyboardInput": "process-targeted CGEvent",
      "os": ProcessInfo.processInfo.operatingSystemVersionString]
  }

  func fail(_ message: String) {
    inputErrors.append(message)
    fputs("\(message)\n", stderr)
  }

  func terminate(_ code: Int32, message: String) -> Never {
    fail(message)
    let released = releaseHeldKeys()
    fputs("owned key cleanup: released=\(released) remaining=\(pressedKeys.count)\n", stderr)
    window?.close()
    exit(code)
  }

  func start(url: String) {
    let config = WKWebViewConfiguration()
    config.websiteDataStore = .nonPersistent()
    config.userContentController.add(self, name: "probe")
    web = WKWebView(frame: NSRect(x: 0, y: 0, width: 800, height: 600), configuration: config)
    web.navigationDelegate = self
    window = NSWindow(
      contentRect: NSRect(x: 240, y: 160, width: 800, height: 600),
      styleMask: [.titled, .closable],
      backing: .buffered,
      defer: false)
    window.contentView = web
    window.title = "Assistant follow input regression"
    window.level = .floating
    NSApp.setActivationPolicy(.regular)
    window.makeKeyAndOrderFront(nil)
    NSApp.activate(ignoringOtherApps: true)
    let url = URL(string: url)!
    web.load(URLRequest(url: url))
    DispatchQueue.main.asyncAfter(deadline: .now() + 180) {
      self.terminate(2, message: "timeout")
    }
  }

  func webView(_ webView: WKWebView, didFail navigation: WKNavigation!, withError error: Error) {
    terminate(1, message: "navigation failed: \(error.localizedDescription)")
  }

  func webView(_ webView: WKWebView, didFailProvisionalNavigation navigation: WKNavigation!, withError error: Error) {
    terminate(1, message: "provisional failed: \(error.localizedDescription)")
  }

  func userContentController(_ userContentController: WKUserContentController, didReceive message: WKScriptMessage) {
    let text = message.body as? String ?? ""
    guard let data = text.data(using: .utf8),
          let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
          let phase = obj["phase"] as? String else {
      terminate(1, message: "malformed fixture report")
    }
    if phase == "done" {
      let released = releaseHeldKeys()
      var report = obj
      report["nativeHeldKeysReleased"] = released
      report["nativeHeldKeysRemaining"] = pressedKeys.count
      report["nativeDiagnostics"] = diagnostics()
      report["nativeInputErrors"] = inputErrors
      let data = try! JSONSerialization.data(withJSONObject: report)
      print(String(data: data, encoding: .utf8)!)
      fflush(stdout)
      window?.close()
      exit(released && inputErrors.isEmpty ? 0 : 3)
    }
    let releasing = phase == "key-up" && pressedKeys.contains(obj["key"] as? String ?? "")
    if !releasing {
      NSApp.activate(ignoringOtherApps: true)
      window.makeKeyAndOrderFront(nil)
      pump(0.1)
    }
    let trusted = AXIsProcessTrusted() && ownsTarget()
      && (releasing || NSWorkspace.shared.frontmostApplication?.processIdentifier == targetPID)
    let delivered = trusted && input(obj)
    let flag = delivered ? "true" : "false"
    web.evaluateJavaScript("window.__continue(\(flag)); 0") { _, error in
      if let error {
        self.terminate(1, message: "continue \(phase): \(error.localizedDescription)")
      }
    }
  }

  func cgPoint(viewX: CGFloat, viewY: CGFloat) -> CGPoint {
    if let origin = screenOrigin { return CGPoint(x: origin.x + viewX, y: origin.y + viewY) }
    let viewPoint = NSPoint(x: viewX, y: web.isFlipped ? viewY : web.bounds.height - viewY)
    let windowPoint = web.convert(viewPoint, to: nil)
    let screenPoint = window.convertToScreen(NSRect(x: windowPoint.x, y: windowPoint.y, width: 0, height: 0)).origin
    let primaryHeight = NSScreen.screens.first?.frame.height ?? 0
    return CGPoint(x: screenPoint.x, y: primaryHeight - screenPoint.y)
  }

  func post(_ point: CGPoint, _ type: CGEventType) {
    let event = CGEvent(mouseEventSource: nil, mouseType: type, mouseCursorPosition: point, mouseButton: .left)
    event?.flags = []
    event?.post(tap: .cghidEventTap)
  }

  func pump(_ seconds: Double) {
    RunLoop.current.run(until: Date().addingTimeInterval(seconds))
  }

  func input(_ obj: [String: Any]) -> Bool {
    let rect = obj["rect"] as? [String: Double] ?? [:]
    switch obj["phase"] as? String {
    case "drag-away": drag(rect, fromTop: false)
    case "drag-back": drag(rect, fromTop: true)
    case "select": select(rect)
    case "hold", "release":
      let content = obj["content"] as? Bool ?? false
      let x = CGFloat(rect["x"] ?? 0) + CGFloat(rect["width"] ?? 0) - (content ? 40 : 3)
      let y = CGFloat(rect["y"] ?? 0) + CGFloat(rect["height"] ?? 0) - 14
      let point = cgPoint(viewX: x, viewY: y)
      post(point, .mouseMoved)
      pump(0.05)
      post(point, obj["phase"] as? String == "hold" ? .leftMouseDown : .leftMouseUp)
    case "wheel":
      let point = cgPoint(viewX: CGFloat(rect["x"] ?? 0) + 120, viewY: CGFloat(rect["y"] ?? 0) + 180)
      post(point, .mouseMoved)
      pump(0.08)
      let deltas = obj["deltas"] as? [Int] ?? []
      let momentum = obj["momentum"] as? Bool == true
      func wheel(_ delta: Int, phase: Int64 = 0, momentumPhase: Int64 = 0) {
        let source = CGEventSource(stateID: .hidSystemState)
        let event = CGEvent(scrollWheelEvent2Source: source, units: .pixel, wheelCount: 1,
          wheel1: Int32(-delta), wheel2: 0, wheel3: 0)
        event?.flags = []
        event?.location = point
        event?.setIntegerValueField(.scrollWheelEventIsContinuous, value: 1)
        event?.setIntegerValueField(.scrollWheelEventScrollPhase, value: phase)
        event?.setIntegerValueField(.scrollWheelEventMomentumPhase, value: momentumPhase)
        event?.post(tap: .cghidEventTap)
      }
      for (index, delta) in deltas.enumerated() {
        if momentum && index > 0 { wheel(delta, momentumPhase: 2) }
        else { wheel(delta, phase: index == 0 ? 1 : 2) }
        if momentum && index == 0 { pump(0.03); wheel(0, phase: 4) }
        pump(Double(obj["gapMs"] as? Int ?? 20) / 1000)
      }
      if momentum { wheel(0, momentumPhase: 4) }
      else { wheel(0, phase: 4) }
    case "key", "key-down", "key-up":
      guard press(obj["key"] as? String ?? "PageUp", phase: obj["phase"] as? String ?? "key", repeatKey: obj["repeat"] as? Bool ?? false) else { return false }
    default: break
    }
    // Pump native animation steps as in the system WebKit review. The page
    // waits separately for event delivery and quiet-period settlement.
    if screenOrigin == nil { pump(0.5) }
    return true
  }

  func drag(_ rect: [String: Double], fromTop: Bool) {
    let x = CGFloat(rect["x"] ?? 0) + CGFloat(rect["width"] ?? 0) - 3
    let top = CGFloat(rect["y"] ?? 0)
    let height = CGFloat(rect["height"] ?? 0)
    let startY = fromTop ? top + 14 : top + height - 14
    let endY = fromTop ? top + height - 14 : top + 36
    let start = cgPoint(viewX: x, viewY: startY)
    let end = cgPoint(viewX: x, viewY: endY)
    post(start, .mouseMoved)
    pump(0.08)
    post(start, .leftMouseDown)
    pump(0.05)
    for step in 1...16 {
      let y = start.y + (end.y - start.y) * CGFloat(step) / 16
      post(CGPoint(x: start.x, y: y), .leftMouseDragged)
      pump(0.02)
    }
    post(end, .leftMouseUp)
  }

  func select(_ rect: [String: Double]) {
    let y = CGFloat(rect["y"] ?? 0) + CGFloat(rect["height"] ?? 0) / 2
    let x0 = CGFloat(rect["x"] ?? 0) + 8
    let x1 = CGFloat(rect["x"] ?? 0) + max(24, CGFloat(rect["width"] ?? 0) - 8)
    let start = cgPoint(viewX: x0, viewY: y)
    let end = cgPoint(viewX: x1, viewY: y)
    post(start, .mouseMoved)
    pump(0.06)
    post(start, .leftMouseDown)
    pump(0.04)
    for step in 1...10 {
      let x = start.x + (end.x - start.x) * CGFloat(step) / 10
      post(CGPoint(x: x, y: start.y), .leftMouseDragged)
      pump(0.02)
    }
    post(end, .leftMouseUp)
  }

  func releaseHeldKeys() -> Bool {
    if pressedKeys.isEmpty { return true }
    guard AXIsProcessTrusted(), ownsTarget() else {
      fail("owned key cleanup refused: Accessibility or target identity unavailable")
      return false
    }
    // A release goes only to our original target, even if focus moved elsewhere.
    // Posting has no delivery acknowledgement; fixture event receipts verify it.
    for name in Array(pressedKeys) {
      if !press(name, phase: "key-up") { return false }
    }
    return pressedKeys.isEmpty
  }

  func press(_ name: String, phase: String = "key", repeatKey: Bool = false) -> Bool {
    let code: CGKeyCode
    switch name {
    case "Home": code = 115
    case "ArrowUp": code = 126
    case "End": code = 119
    case "PageDown": code = 121
    case "Shift+Space": code = 49
    case "PageUp": code = 116
    default: fail("unsupported key: \(name)"); return false
    }
    guard ownsTarget(), let source = keySource,
          let down = CGEvent(keyboardEventSource: source, virtualKey: code, keyDown: true),
          let up = CGEvent(keyboardEventSource: source, virtualKey: code, keyDown: false) else {
      fail("key event creation or target identity failed")
      return false
    }
    if phase == "key-up" && !pressedKeys.contains(name) {
      fail("refusing release of an unowned key: \(name)")
      return false
    }
    down.flags = name == "Shift+Space" ? .maskShift : []
    up.flags = []
    if phase != "key-up" {
      down.setIntegerValueField(.keyboardEventAutorepeat, value: repeatKey ? 1 : 0)
      down.postToPid(targetPID)
      pressedKeys.insert(name)
    }
    if phase == "key" { pump(0.05) }
    if phase != "key-down" {
      up.postToPid(targetPID)
      pressedKeys.remove(name)
    }
    return true
  }
}

let app = NSApplication.shared
let probe = Probe()
guard CommandLine.arguments.count > 1 else { exit(2) }
if CommandLine.arguments[1] == "--identity" {
  guard CommandLine.arguments.count == 3, let pid = pid_t(CommandLine.arguments[2]),
        let identity = Probe.identity(pid),
        let data = try? JSONSerialization.data(withJSONObject: identity),
        let text = String(data: data, encoding: .utf8) else { exit(3) }
  print(text)
} else if CommandLine.arguments[1] == "--input" {
  // The runner captures the launch identity of its CDP-owned browser once.
  // Validate it again before every input, including background key cleanup.
  guard CommandLine.arguments.count == 5, let pid = pid_t(CommandLine.arguments[2]),
        let obj = try? JSONSerialization.jsonObject(with: Data(CommandLine.arguments[3].utf8)) as? [String: Any],
        let identity = try? JSONSerialization.jsonObject(with: Data(CommandLine.arguments[4].utf8)) as? [String: Any],
        let owned = NSRunningApplication(processIdentifier: pid) else { exit(3) }
  probe.targetPID = pid
  probe.targetIdentity = identity
  guard AXIsProcessTrusted(), probe.ownsTarget() else { exit(3) }
  let releasing = obj["phase"] as? String == "key-up" && obj["ownedKey"] as? Bool == true
  if releasing {
    guard let key = obj["key"] as? String else { exit(3) }
    probe.pressedKeys.insert(key)
    exit(probe.press(key, phase: "key-up") ? 0 : 3)
  }
  owned.activate(options: [.activateIgnoringOtherApps])
  probe.pump(0.15)
  guard NSWorkspace.shared.frontmostApplication?.processIdentifier == pid else { exit(4) }
  func webOrigin(_ element: AXUIElement, depth: Int = 0) -> CGPoint? {
    guard depth < 15 else { return nil }
    var role: CFTypeRef?
    AXUIElementCopyAttributeValue(element, kAXRoleAttribute as CFString, &role)
    if role as? String == "AXWebArea" {
      var position: CFTypeRef?
      if AXUIElementCopyAttributeValue(element, kAXPositionAttribute as CFString, &position) == .success,
         let position {
        var point = CGPoint.zero
        if AXValueGetValue(position as! AXValue, .cgPoint, &point) { return point }
      }
    }
    var children: CFTypeRef?
    AXUIElementCopyAttributeValue(element, kAXChildrenAttribute as CFString, &children)
    for child in children as? [AXUIElement] ?? [] {
      if let point = webOrigin(child, depth: depth + 1) { return point }
    }
    return nil
  }
  var origin: CGPoint?
  for _ in 0..<20 {
    origin = webOrigin(AXUIElementCreateApplication(pid))
    if origin != nil { break }
    probe.pump(0.1)
  }
  guard let origin else { exit(5) }
  probe.screenOrigin = origin
  if !probe.input(obj) { probe.terminate(3, message: "input failed") }
} else {
  probe.start(url: CommandLine.arguments[1])
  app.run()
}
