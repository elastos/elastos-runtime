import QRCode from './qrcode.mjs';

// Same provider.connect, deadline and cleanup as scripts/walletconnect/adapter.mjs.
// Only QR presentation moves to the window's shared view.
export async function connectWithView(adapter, options, presentation) {
  const provider = await adapter.restoreWalletConnectEvm(options);
  if (provider.connected && provider.session?.expiry > Date.now() / 1000) return provider;
  const lifetime = new AbortController();
  let rejectCancel, timer, active = true;
  const cancelled = new Promise((_, reject) => { rejectCancel = reject; });
  const stop = (error = new Error('Wallet connection cancelled.')) => {
    active = false;
    lifetime.abort();
    presentation.hide();
    rejectCancel(error);
    provider.signer.abortPairingAttempt();
    provider.signer.client.core.relayer.transportClose().catch(() => {});
  };
  const abort = () => stop(options.signal.reason);
  options.signal?.addEventListener('abort', abort, {once:true});
  const display = async uri => {
    try {
      const data = await QRCode.toDataURL(uri, {width:280, margin:4});
      if (!active) return;
      presentation.show(data, {
        cancel:() => stop(),
        copy:() => options.copyLink(uri, {signal:lifetime.signal}),
      }, uri);
      options.onPhase?.('pairing');
    } catch (error) { if (active) stop(error); }
  };
  provider.on('display_uri', display);
  const signerConnect = provider.signer.connect;
  let proposalError;
  provider.signer.connect = async function (...args) {
    try { return await signerConnect.apply(this, args); }
    catch (error) { proposalError = error; throw error; }
  };
  try {
    timer = setTimeout(() => stop(new Error('The QR code expired. Select Connect wallet for a new one.')), 180000);
    await Promise.race([provider.connect(), cancelled]);
    return provider;
  } catch (error) {
    throw proposalError && error?.message === proposalError.message ? proposalError : error;
  } finally {
    active = false;
    lifetime.abort();
    provider.signer.connect = signerConnect;
    clearTimeout(timer);
    options.signal?.removeEventListener('abort', abort);
    provider.removeListener('display_uri', display);
    presentation.hide({connected:provider.connected && Boolean(provider.session)});
  }
}
