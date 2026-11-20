export function runtimeStorage(api) {
  let queue = Promise.resolve();
  let retired = false;
  const update = body => {
    const next = queue.then(() => retired ? undefined : api("storage", { method: "POST", body: JSON.stringify(body) }));
    queue = next.catch(() => {});
    return next;
  };
  const all = async () => { await queue; return retired ? {} : api("storage"); };
  return {
    // Disconnect deletes this Core's session. Already acknowledged payloads
    // can finish their bookkeeping after its listeners and transport stop;
    // their obsolete state has no authority to reach Home or a later Core.
    retire() { retired = true; },
    async getKeys() { return Object.keys(await all()); },
    async getEntries() { return Object.entries(await all()); },
    async getItem(key) { return (await all())[key]; },
    async setItem(key, value) { await update({ key, value }); },
    async removeItem(key) { await update({ key, value: null }); },
  };
}
