import { createHomeClipboardClient } from "/apps/home/home-clipboard-client.js?v=home-20261111a";
import { startExtensionWindow } from './extension-window.mjs';

const CONNECTOR_ID = 'wallet-unisat';
const homeOrigin = new URLSearchParams(window.location.search).get('home_origin')?.trim() || '';
const frameHomeToken = new URLSearchParams(window.location.hash.slice(1)).get('home_token')?.trim() || '';
const homeClipboard = createHomeClipboardClient({
  targetId: CONNECTOR_ID,
  homeOrigin,
  homeToken: frameHomeToken,
});
homeClipboard.start();
startExtensionWindow('unisat', homeClipboard);
