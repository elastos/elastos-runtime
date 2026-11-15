// esbuild injects this WebSocket into the SDK. Every SDK socket terminates at
// Home; relay credentials and launch authority travel in the first frame.
let runtime;
export function configureRuntime(options) {
  runtime = options;
}

export class WebSocket extends EventTarget {
  static CONNECTING = 0;
  static OPEN = 1;
  static CLOSING = 2;
  static CLOSED = 3;
  CONNECTING = 0;
  OPEN = 1;
  CLOSING = 2;
  CLOSED = 3;
  readyState = 0;
  bufferedAmount = 0;
  protocol = "";
  extensions = "";
  constructor(relay) {
    super();
    if (!runtime) throw new Error("WalletConnect Runtime transport is unavailable.");
    const current = runtime;
    this.url = "Runtime WalletConnect relay";
    const NativeSocket = current.WebSocket || globalThis.WebSocket;
    const socket = this.socket = new NativeSocket(current.url);
    socket.onopen = async () => {
      try {
        const token = current.authorize ? (await current.authorize()).token : current.token;
        if (this.readyState === 0) socket.send(JSON.stringify({ token, relay }));
      } catch { this.fail(); this.close(); }
    };
    socket.onmessage = event => {
      if (this.readyState === 0) {
        if (event.data !== '{"ready":true}') { this.close(); return; }
        this.readyState = 1;
        this.emit("open", new Event("open"));
      } else {
        this.emit("message", new MessageEvent("message", { data: event.data }));
      }
    };
    socket.onerror = () => this.fail();
    socket.onclose = () => {
      if (this.readyState === 0) this.fail();
      this.readyState = 3;
      this.emit("close", new Event("close"));
    };
  }
  fail() {
    if (this.failed) return;
    this.failed = true;
    this.emit("error", new Event("error"));
  }
  emit(name, event) { this[`on${name}`]?.(event); this.dispatchEvent(event); }
  send(data) {
    if (this.readyState !== 1) throw new Error("WalletConnect connection is closed.");
    this.socket.send(data);
  }
  close() { if (this.readyState === 0) this.fail(); this.readyState = 2; this.socket.close(); }
}
