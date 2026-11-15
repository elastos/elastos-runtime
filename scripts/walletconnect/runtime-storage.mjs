export function runtimeStorage(api) {
  let queue = Promise.resolve();
  const update = body => {
    const next = queue.then(() => api("storage", { method: "POST", body: JSON.stringify(body) }));
    queue = next.catch(() => {});
    return next;
  };
  const all = async () => { await queue; return api("storage"); };
  return {
    async getKeys() { return Object.keys(await all()); },
    async getEntries() { return Object.entries(await all()); },
    async getItem(key) { return (await all())[key]; },
    async setItem(key, value) { await update({ key, value }); },
    async removeItem(key) { await update({ key, value: null }); },
  };
}
