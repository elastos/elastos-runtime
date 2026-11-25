import {pulseCopied} from './wallet-render.js';
import {chainLabel, shortAddress, isPasskeyManagedAccount, walletDisplay, accountName} from './wallet-format.js';

const text = (tag, value, className = '') => {
  const node = document.createElement(tag); node.textContent = value; node.className = className; return node;
};
const button = (label, action, primary = false) => {
  const node = text('button', label, `el-button${primary ? ' el-button-primary' : ''}`);
  node.type = 'button'; node.onclick = action; return node;
};
export function inventoryWalletName(entry) {
  const account = entry.accounts[0];
  if (account && isPasskeyManagedAccount(account)) return accountName(account);
  const reported=account?.wallet_display_name || entry.wallet_display_name;
  if(reported)return walletDisplay({wallet_display_name:reported}).name;
  return ({metamask:'MetaMask', unisat:'UniSat', walletconnect:'Your wallet'}[account?.connector_id?.replace('wallet-', '') || entry.sign_in?.connector]) || 'Your wallet';
}
const kind = entry => entry.accounts[0]?.connector_id?.replace('wallet-', '') || entry.sign_in?.connector || 'passkey';
const bitcoin = entry => entry.chain_namespace.startsWith('bip122:');
const appsStatement = entry => bitcoin(entry) ? 'Proves you own this Bitcoin address to apps' : 'Apps and websites can ask; you approve each request.';

export function createWalletInventory({root, openSystem, connectApps, removeApps, copyAddress, send, receive, manageBuiltIn, getBalance = () => '', openActivity, openSettings, togglePrivacy, isPrivate=()=>false, onError=()=>{}}) {
  let inventory = {entries:[]}, selected = new URLSearchParams(location.search).get('wallet_entry') || '';
  let result = '', dialog, operation = 0, busy = false, renderKey = '';
  let connectionController;
  function link(label, action) {
    const node = text('a', label, 'wallet-inventory-link'); node.href = '#';
    node.onclick = event => {event.preventDefault(); action();}; return node;
  }
  function identity(entry) {
    const node = text('div', '', 'one-identity');
    const image = document.createElement('img'); image.className = 'one-logo'; image.alt = '';
    image.src = `/apps/home/connection-${kind(entry) === 'passkey' ? 'wallet' : kind(entry)}.png`;
    const copy = text('div', ''); const name = text('strong', inventoryWalletName(entry));
    name.dir = 'auto';
    const meta = text('div', '', 'one-meta'), address = text('code', shortAddress(entry.address)); address.title = entry.address;
    meta.append(address, text('span', (entry.chain_namespace === 'eip155:20' ? 'ESC' : chainLabel(entry.chain_namespace)) + (kind(entry) === 'walletconnect' ? ' · WalletConnect' : '')));
    copy.append(name, meta); node.append(image, copy); return node;
  }
  function card(entry, detail) {
    const article = text('article', '', 'one-wallet'); article.dataset.wallet = entry.inventory_id;
    const top = text('div', '', 'one-wallet-top');
    top.append(identity(entry), detail ? button('Copy', async event => {const control=event.currentTarget;control.disabled=true;try{await copyAddress(entry.address);pulseCopied(control);}catch(error){onError(error);}finally{control.disabled=false;}}) : button('Open', () => open(entry.inventory_id)));
    if (!detail) top.lastChild.setAttribute('aria-label', `Open ${inventoryWalletName(entry)}`);
    article.append(top);
    const managed = entry.accounts.some(isPasskeyManagedAccount);
    if (managed) {
      const built = text('div', '', 'one-builtin'), controls = text('div', '');
      controls.append(text('strong', getBalance(entry)), button('Send', () => send(entry)), button('Receive', () => receive(entry)));
      built.append(text('span', 'Approved with your passkey'), controls); article.append(built);
    }
    if (!detail) {
      const summary = text('div', '', 'one-summary');
      if (entry.sign_in) summary.append(text('p', `Signs in to ${inventory.account_name || 'your'}${inventory.account_name ? "'s" : ''} account`));
      if (entry.accounts.length) summary.append(text('p', appsStatement(entry)));
      article.append(summary);
    } else {
      const uses = text('section', '', 'one-used-by'); uses.append(text('h2', 'Used by'));
      if (entry.sign_in) {
        const owner = text('div', '', 'one-owner');
        owner.append(text('div', `System: signs in to ${inventory.account_name || 'your'}${inventory.account_name ? "'s" : ''} account`), link('Manage in System', openSystem)); uses.append(owner);
      }
      const apps = text('div', '', 'one-owner one-apps'), copy = text('div', '', 'one-use-label');
      const label = text('span', 'Apps and websites'); label.id = 'inventory-apps-label';
      copy.append(label, text('small', bitcoin(entry) ? 'Prove you own this Bitcoin address to apps.' : appsStatement(entry)), text('small', managed ? 'Approved with your passkey' : entry.accounts.length ? 'Connected for apps' : 'Off · Connect with one wallet signature.'));
      apps.append(copy);
      if (!managed) {
        const toggle = button('', () => entry.accounts.length ? confirmOff(entry) : confirmOn(entry));
        toggle.className = 'one-switch'; toggle.setAttribute('role', 'switch'); toggle.setAttribute('aria-labelledby', label.id);
        toggle.setAttribute('aria-checked', String(entry.accounts.length > 0)); toggle.disabled = busy;
        toggle.append(document.createElement('span')); apps.append(toggle);
      }
      uses.append(apps); article.append(uses);
      if (bitcoin(entry) && !managed) article.append(text('p', 'Sending Bitcoin from this Home is not available yet.', 'one-note'));
      if (managed) {
        const controls = text('div', '', 'one-built-actions');
        controls.append(button('Manage address', () => manageBuiltIn(entry)), button('Activity', openActivity), button('Settings', openSettings), button(isPrivate()?'Show balances':'Hide balances',togglePrivacy)); article.append(controls);
      }
    }
    return article;
  }
  function render() {
    const key = JSON.stringify([inventory, selected, result, busy, inventory.entries.filter(entry => entry.accounts.some(isPasskeyManagedAccount)).map(getBalance)]);
    if (key === renderKey) return; renderKey = key;
    const section = text('section', '', 'one-section'), heading = text('header', '', 'one-heading'), title = text('div', '');
    const entry = inventory.entries.find(entry => entry.inventory_id === selected);
    if (selected && !entry) selected = '';
    if (entry) title.append(button('Back to wallets', () => open('')));
    title.append(text('h1', entry ? 'Wallet' : 'Wallets')); heading.append(title);
    if (!entry) {const add=button('Add wallet for apps', choose, true);add.id='wallet-add-apps';heading.append(add);}
    section.append(heading);
    if (result) {const status=text('p',result,'one-result');status.setAttribute('role','status');section.append(status);}
    if (!entry) {
      const note = text('p', '', 'one-muted one-list-note');
      note.append('To sign in with a wallet, use ', link('System > Accounts', openSystem), '.'); section.append(note);
    }
    const list = text('div', '', 'one-list');
    for (const row of entry ? [entry] : inventory.entries) list.append(card(row, Boolean(entry)));
    if (!inventory.entries.length) list.append(text('p', 'Add a wallet for apps, or create a Home address in Settings.', 'one-muted'));
    section.append(list);
    if (!entry && !inventory.entries.some(entry=>entry.accounts.some(isPasskeyManagedAccount))) {
      const controls = text('div', '', 'one-built-actions'); controls.append(button('Activity', openActivity), button('Settings', openSettings)); section.append(controls);
    }
    root.replaceChildren(section);
  }
  function open(id) {if (busy) return false; selected = id; result = ''; render(); return true;}
  function close() {const restore=Boolean(dialog);operation++;connectionController?.abort();connectionController=null;dialog?.close();dialog?.remove();dialog=null;busy=false;render();if(restore)(root.querySelector('[role=switch]')||root.querySelector('#wallet-add-apps'))?.focus({preventScroll:true});}
  function modal(title, nodes, approve, label) {
    close(); const modal = document.createElement('dialog'); dialog = modal; modal.className = 'one-dialog';
    modal.setAttribute('aria-label', title);
    const body = text('div', '', 'one-dialog-body'); body.append(text('h2', title), ...nodes);
    const footer = text('footer', '', 'one-dialog-footer'); footer.append(button('Cancel', close));if(label)footer.append(button(label, approve, true));
    modal.append(body, footer); modal.addEventListener('cancel', event => {event.preventDefault(); close();});
    root.after(modal); modal.showModal();
  }
  function confirmOn(entry) {
    const wallet = text('div', '', 'one-proof-wallet'); wallet.append(identity(entry));
    const message = text('div', bitcoin(entry) ? `Prove ownership of this Bitcoin address for app requests on ${inventory.account_name || 'your'}’s Home.` : 'Allow this wallet to approve requests from apps on this Home.', 'one-message');
    const fields = text('dl', '', 'one-proof-fields');
    for (const [label, value] of [['Home', `${inventory.account_name || 'Your'}’s Home`], ['Account', inventory.account_name || 'Your account'], ['Requested by', 'Wallet']]) {
      const row = text('div', ''); row.append(text('dt', label), text('dd', value)); fields.append(row);
    }
    modal('Connect for apps', [text('p', 'Wallet signature', 'one-step'), wallet, message, fields], async () => {
      if (busy) return; busy = true; const epoch = operation; connectionController = new AbortController(); render();
      try {await connectApps(entry, () => epoch === operation, undefined, connectionController.signal); if (epoch !== operation) return; close(); result = 'Connected for apps.'; render();}
      catch (error) {if (epoch === operation) {busy = false; bodyError(error); render();}}
    }, 'Sign message');
  }
  function confirmOff(entry) {
    const wallet = text('div', '', 'one-proof-wallet'); wallet.append(identity(entry));
    const note = text('p', '', 'one-muted');
    note.textContent = entry.sign_in ? `System still uses this wallet to sign in to ${inventory.account_name || 'your'}${inventory.account_name ? "'s" : ''} account.` : 'System manages sign-in use.';
    const scope = text('p', bitcoin(entry) ? 'This ends Bitcoin proof requests through this Home.' : '');
    if (!bitcoin(entry)) {const name=text('bdi',inventoryWalletName(entry));name.dir='auto';scope.append('This ends app and website requests for this wallet only (',name,') on this Home.');}
    modal('Turn off app use?', [wallet, scope, note, text('p', 'Passkey approval', 'one-step')], async () => {
      if (busy) return; busy = true; const epoch = operation; render();
      try {await removeApps(entry, () => epoch === operation); if (epoch !== operation) return; close(); result = 'App use turned off.'; render();}
      catch (error) {if (epoch === operation) {busy = false; bodyError(error); render();}}
    }, 'Approve with passkey');
  }
  function bodyError(error) {
    const body = dialog?.querySelector('.one-dialog-body'); if (!body) return;
    body.querySelector('[role=alert]')?.remove(); const message = text('p', error.message || 'Wallet could not confirm this change. Check again.', 'one-note'); message.setAttribute('role', 'alert'); body.append(message);
  }
  function choose() {
    const list = text('div', '', 'one-choices');
    for (const [method, name] of [['metamask', 'MetaMask'], ['unisat', 'UniSat'], ['walletconnect', 'WalletConnect']]) {
      const row = button(name, event => {event.stopPropagation(); close(); connectApps(null, () => true, method).catch(error => {result = error.message; render();});});
      row.dataset.walletOpenMethod = `wallet-${method}`;
      if (method === 'walletconnect') row.append(text('small', 'Rainbow, Trust and other phone wallets'));
      list.append(row);
    }
    modal('Add wallet for apps', [list]);
  }
  return {
    update(next) {
      if (inventory.account_id && inventory.account_id !== next.account_id) {close(); selected = ''; result = '';}
      inventory = next; render();
    }, open, close, openAdd:choose,
  };
}
