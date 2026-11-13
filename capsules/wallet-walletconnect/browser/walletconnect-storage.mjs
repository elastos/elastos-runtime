// Capsule-local compatibility for SDK imports. Runtime owns protocol storage.
export function installWalletConnectStorage(window, trace = () => {}) {
  const stores = new WeakMap();
  const data = receiver => {
    const value = stores.get(receiver);
    if (!value) throw new TypeError("Illegal invocation");
    return value;
  };
  const text = value => {
    if (typeof value === "symbol") throw new TypeError("Cannot convert a Symbol to a string");
    return String(value);
  };
  const requireArguments = (count, actual) => {
    if (actual < count) throw new TypeError(`${count} arguments required`);
  };
  const prototype = Object.create(window.Storage.prototype);
  Object.defineProperties(prototype, {
    length: { configurable: true, enumerable: true, get() { return data(this).values.size; } },
    key: { configurable: true, enumerable: true, writable: true, value: function key(index) {
      const state = data(this); requireArguments(1, arguments.length);
      return [...state.values.keys()][+index >>> 0] ?? null;
    } },
    getItem: { configurable: true, enumerable: true, writable: true, value: function getItem(key) {
      const state = data(this); requireArguments(1, arguments.length); key = text(key);
      return state.values.has(key) ? state.values.get(key) : null;
    } },
    setItem: { configurable: true, enumerable: true, writable: true, value: function setItem(key, value) {
      const state = data(this); requireArguments(2, arguments.length);
      key = text(key); value = text(value);
      const refused = /wc@2:|keychain/i.test(key);
      trace({ store: state.name, operation: "setItem", key, refused });
      if (refused) throw new window.DOMException("WalletConnect protocol state requires Runtime storage.", "SecurityError");
      state.values.set(key, value);
    } },
    removeItem: { configurable: true, enumerable: true, writable: true, value: function removeItem(key) {
      const state = data(this); requireArguments(1, arguments.length); key = text(key);
      trace({ store: state.name, operation: "removeItem", key }); state.values.delete(key);
    } },
    clear: { configurable: true, enumerable: true, writable: true, value: function clear() {
      const state = data(this); trace({ store: state.name, operation: "clear" }); state.values.clear();
    } },
  });
  const memory = name => {
    const values = new Map();
    const target = Object.create(prototype);
    const visible = key => typeof key === "string" && values.has(key) && !Reflect.has(target, key);
    const storage = new Proxy(target, {
      get(target, key, receiver) { return visible(key) ? values.get(key) : Reflect.get(target, key, receiver); },
      has(target, key) { return values.has(key) || Reflect.has(target, key); },
      set(target, key, value) {
        if (typeof key === "symbol") return Reflect.set(target, key, value);
        prototype.setItem.call(storage, key, value); return true;
      },
      deleteProperty(target, key) {
        if (typeof key === "symbol") return Reflect.deleteProperty(target, key);
        prototype.removeItem.call(storage, key); return true;
      },
      ownKeys(target) { return [...Reflect.ownKeys(target), ...[...values.keys()].filter(visible)]; },
      getOwnPropertyDescriptor(target, key) {
        return visible(key) ? { value: values.get(key), configurable: true, enumerable: true, writable: true }
          : Reflect.getOwnPropertyDescriptor(target, key);
      },
      defineProperty(target, key, descriptor) {
        if (typeof key === "symbol") return Reflect.defineProperty(target, key, descriptor);
        if ("get" in descriptor || "set" in descriptor || descriptor.configurable === false
            || descriptor.enumerable === false || descriptor.writable === false) return false;
        prototype.setItem.call(storage, key, descriptor.value); return true;
      },
    });
    stores.set(storage, { name, values });
    return storage;
  };
  const local = memory("localStorage"), session = memory("sessionStorage");
  for (const [name, storage] of [["localStorage", local], ["sessionStorage", session]]) {
    Object.defineProperty(window, name, { get: () => storage, configurable: false, enumerable: true });
  }
  return () => { prototype.clear.call(local); prototype.clear.call(session); };
}
