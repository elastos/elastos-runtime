// esbuild injects this WebSocket into the SDK. Every SDK socket terminates at
// Home; relay credentials and launch authority travel in the first frame.
let runtime;
let retired = false;
const sockets = new Set();
const listeners = new Set();
const timers = new Map();
export function configureRuntime(options) {
  runtime = options;
  retired = false;
}

// These bindings are injected into this pinned SDK only. An adapter owns the
// SDK's host resources, including anonymous network listeners and deadlines.
function addRuntimeListener(type, listener, options) {
  if (retired) return;
  globalThis.window.addEventListener(type, listener, options);
  listeners.add({type, listener, options});
}
export { addRuntimeListener as "window.addEventListener" };
export function setTimeout(handler, delay, ...args) {
  if (retired) return 0;
  const id = globalThis.setTimeout(() => {
    timers.delete(id);
    Reflect.apply(handler, globalThis, args);
  }, delay);
  timers.set(id, 'timeout');
  return id;
}
export function setInterval(handler, delay, ...args) {
  if (retired) return 0;
  const id = globalThis.setInterval(handler, delay, ...args);
  timers.set(id, 'interval');
  return id;
}
export function clearTimeout(id) { timers.delete(id); globalThis.clearTimeout(id); }
export function clearInterval(id) { timers.delete(id); globalThis.clearInterval(id); }
export function retireRuntime() {
  retired = true;
  runtime = undefined;
  for (const {type, listener, options} of listeners) globalThis.window.removeEventListener(type, listener, options);
  listeners.clear();
  for (const [id, kind] of timers) {
    if (kind === 'interval') globalThis.clearInterval(id);
    else globalThis.clearTimeout(id);
  }
  timers.clear();
  for (const socket of sockets) socket.close();
  sockets.clear();
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
    if (retired || !runtime) throw new Error("WalletConnect Runtime transport is unavailable.");
    const current = runtime;
    this.url = "Runtime WalletConnect relay";
    const NativeSocket = current.WebSocket || globalThis.WebSocket;
    const socket = this.socket = new NativeSocket(current.url);
    sockets.add(this);
    socket.onopen = async () => {
      if (retired || this.readyState !== 0) return;
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
      sockets.delete(this);
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
