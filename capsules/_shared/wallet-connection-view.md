# Wallet connection view

The view draws supplied data. Each window owns its real state, mounting, focus and effects. Importing this module performs no work. The current window controllers opt into it separately.

Call reduceConnection(presentation, sources) to derive contract-owned fields, then renderConnection(document, view) to get a detached main element. All controls are declarative data-action intents. The window validates authority and handles each effect outside this module.

The presentation input has window, stage, an already-cleaned account display projection, waitSeconds for window-local waits, an optional local PNG qrData, validated homeOrigin, WalletConnect localSafety, compact, targetNetwork (a canonical requested-network label), and previousFocus. Contract sources are the original provider message, optional current safety message, Runtime summary and other summaries, alternative navigation facts, audience, and an explicit nowSeconds. The reducer preserves exact site origins, request identity and the earliest supplied deadline. It never reads a clock.

Names have bounded isolated text elements. Runtime owns name cleaning; this view validates bounds and uses the returned text. Pre-link extension names are fixed local copy selected by the provider enum. WalletConnect peer marks are generic. Site identity uses only the validated requesting_origin projection; unknown sites are omitted. Request reason remains labelled app content.

Mount the returned element, then focus the data-focus outcome/accounts element or the data-action control named by view.focus. For a same-stage update, pass previousFocus={stage,action,key}; match the returned focusKey to data-focus-key before falling back to its action. Keep scroll and focus management in the window. Answered states always focus the non-action outcome. QR callers retain the invoking control and restore it on close, apply connectionKey for Tab cycling and the Escape cancel intent; the view itself grants no cancellation authority.

Choose compact for constrained frames. The compact tree keeps current status, wait and exits outside the scrolling request content. The smallest tested frame is 320 by 182 CSS pixels (320 by 220 outer desktop window and 38-pixel chrome); the phone frame is 360 by 596 inside a 360 by 640 outer window with 44-pixel chrome. The test measures these dimensions with Home’s actual CSS.

The module and closed screen definitions, CSS and four local PNG marks are copied into each connector by scripts/vendor-ui-tokens.sh. Product-data validation checks each copy and its containment. The packaging test calls the real release stage/archive functions and compares every archived asset to its shared source.

## State production contract

Every stage below is a presentation state, not proof that a real producer exists. Window-local fixtures are labelled “window-local: produced by the window lane” in scripts/fixtures/wallet-connection-view-states.json. The window lanes must produce the same models from consent, pairing, link/session, selection and panel state. Provider, request, site and payment fields pass through the pure reducers. Provisional fixture examples are explicitly listed in that test file; they grant no authority or real-wallet compatibility claim.

### walletconnect

`nothing-saved`, `internet-pending`, `internet-refused`, `internet-off`, `internet-expired`, `internet-clearing`, `internet-ready`, `preparing-qr`, `qr-shown`, `qr-cancelled`, `qr-expired`, `connection-declined`, `link-wait`, `link-declined`, `link-timeout`, `link-cancelled`, `saved-unlinked`, `connection-expired`, `request-connection-expired`, `wallet-removed`, `linked`, `linked-multiple`, `request-waiting`, `request-multiple`, `request-unsendable`, `request-expired`, `request-phone`, `request-declined`, `request-timeout`, `request-done`, `request-cancelled`, `transaction-waiting`, `transaction-deadline`, `transaction-phone`, `transaction-declined`, `transaction-timeout`, `transaction-cancelled`, `transaction-wallet-error`, `transaction-done`, `transaction-reopened`, `request-wallet-error`, `request-new-connection`, `request-network-unsupported`, `request-wallet-removed`, `request-sent-wallet-removed`, `transaction-wallet-removed`, `request-internet-off`, `request-internet-pending`, `disconnecting`, `disconnected`, `window-expired`, `guest-access`, `link-error`, `request-list`, `request-selected-second`, `request-next`, `transaction-late-result`, `guest-ready`, `link-busy`, `request-busy`, `link-late-ignored`, `focus`.

### metamask

`ready`, `ready-multiple`, `extension-missing`, `extensions-unavailable`, `extension-wait`, `extension-timeout`, `extension-cancelled`, `link-wait`, `connection-declined`, `link-declined`, `link-timeout`, `link-cancelled`, `link-late-ignored`, `account-unavailable`, `site-access-ended`, `connect-already-open`, `request-access-error`, `transaction-access-error`, `request-network-declined`, `request-network-unknown`, `linked`, `request-waiting`, `request-multiple`, `request-unsendable`, `request-typed-data`, `request-expired`, `request-extension`, `request-declined`, `request-timeout`, `request-done`, `request-cancelled`, `transaction-waiting`, `transaction-extension`, `transaction-declined`, `transaction-timeout`, `transaction-cancelled`, `transaction-wallet-error`, `transaction-done`, `request-wallet-error`, `request-late-ignored`, `window-expired`, `link-error`, `request-list`, `request-selected-second`, `request-next`, `transaction-late-result`, `other-ethereum-wallet`, `access-wrong-account`, `link-busy`, `request-busy`, `extension-busy`, `extension-late-ignored`, `focus`.

### unisat

`ready`, `extension-missing`, `extensions-unavailable`, `extension-wait`, `extension-timeout`, `extension-cancelled`, `link-wait`, `connection-declined`, `link-declined`, `link-timeout`, `link-cancelled`, `link-late-ignored`, `account-unavailable`, `network-changed`, `network-fractal`, `network-unknown`, `linked`, `request-waiting`, `request-multiple`, `request-unsendable`, `request-expired`, `request-extension`, `request-declined`, `request-timeout`, `request-done`, `request-cancelled`, `request-wallet-error`, `request-late-ignored`, `window-expired`, `link-error`, `request-list`, `request-selected-second`, `request-next`, `request-network-testnet`, `request-network-fractal`, `request-network-unknown`, `link-busy`, `request-busy`, `extension-busy`, `extension-late-ignored`, `focus`.

### panel

`empty`, `empty-alt`, `linked`, `linked-unisat`, `unconfigured`, `linked-metamask`, `linked-unnamed`, `empty-return`, `linked-return`, `linked-metamask-return`, `linked-unisat-return`.

