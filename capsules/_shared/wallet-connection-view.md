# Wallet connection view

The view draws supplied data. Each window owns its real state, presentation lifetime and effects. Importing this module performs no work. The current window controllers opt into it separately.

Call reduceConnection(presentation, sources) to derive contract-owned fields. renderConnection(document, view) returns a detached main element; mountConnection(container, view, previousMount) applies presentation focus and scroll inside the caller’s container. All controls are declarative data-action intents. The window validates authority and handles each effect outside this module.

The presentation input has window, stage, an already-cleaned account display projection, waitSeconds for window-local waits, an optional local PNG qrData, validated homeOrigin, WalletConnect localSafety, compact, targetNetwork (a canonical requested-network label), previousFocus, and an optional closed transactionDisplay projection (amount, asset, destination, network) computed by Home/Runtime. App-authored reason remains separate. Contract sources are the original provider message, optional current safety message, Runtime summary and other summaries, alternative navigation facts, audience, and an explicit nowSeconds. The reducer preserves exact site origins, request identity and the earliest supplied deadline. It never reads a clock.

Names have bounded isolated text elements. Runtime owns name cleaning; this view validates bounds and uses the returned text. Pre-link extension names are fixed local copy selected by the provider enum. WalletConnect peer marks are generic. Site identity uses only the validated requesting_origin projection; unknown sites are omitted. Request reason remains labelled app content.

A card opens with Close window focused and scroll at zero when it first appears for a request, or when its window, request ID or stage changes. A redraw of the same request in the same stage preserves the person’s focused control and all scroll positions. A timer-only update changes the wait text in place, retaining the focused DOM node for assistive technology. Focusing an approving control scrolls the site’s final line into view directly above it. Keyboard activation reveals that same unit again if the person has scrolled away; the site/action unit remains in normal flow.

The window passes the same Runtime summary request_id on every redraw, and a different ID for a new request. For pre-request Connect/restore/finish cards associated with a Browser request, pass sources.contextSummary from the existing Runtime summary. The pure reducer returns a closed requestContext (id, app, actor, site); this context supplies identity without inventing a message request or changing the stage. Omit it when the window has no requesting-app summary. For a fresh window-local attempt with no request identity, dispose the old mount and pass no previous mount record. Direct factory callers may supply the same reduced requestContext shape. The window owns the current mount record and its lifetime:

```js
let mounted;
function draw(presentation, sources) {
  const previousFocus = mounted && captureConnectionPresentation(mounted.root);
  const view = reduceConnection({...presentation, previousFocus}, sources);
  mounted = mountConnection(container, view, mounted);
}
// When the window stops owning the container:
mounted?.dispose();
```

The module keeps no current request, timer or mount record. captureConnectionPresentation(root) reads only the supplied tree; the caller owns its snapshot. A caller with its own mounting code supplies previousFocus={window,stage,requestId,action,key}, captures/restores its own scroll positions for matching identity, and preserves the focused node on timer updates. For a new card it applies view.focus with preventScroll and resets scroll to zero. For matching identity, focusKey identifies the control before falling back to its action. Closing dismisses the view and does not decline or cancel the request. Answered cards initially focus their non-action outcome. QR callers retain the invoking control and restore it on close, apply connectionKey for Tab cycling and the Escape cancel intent; the view itself grants no cancellation authority.

Choose compact for constrained frames. For post-action waits and outcomes, the compact tree keeps status, wait and exits outside scrolling content. A card that still offers approval with a site instead scrolls as a whole, with its site/action unit at the end. The smallest tested frame is 320 by 182 CSS pixels (320 by 220 outer desktop window and 38-pixel chrome); the phone frame is 360 by 596 inside a 360 by 640 outer window with 44-pixel chrome. The test measures these dimensions with Home’s actual CSS.

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

The factory returns a deeply frozen view. `renderConnection` accepts only a view
created by this module instance through `connectionView` or `reduceConnection`.
A window that transfers state between realms transfers the closed input and
runs the factory in the rendering realm. It owns mounting and effects.

`browser_typed_data_sign` summaries use “Sign typed data”. Known Browser and Notes
IDs have local display labels; an unnamed app uses “Requesting app”. Request
content has the visible label “From app:”. The exact ASCII origin wraps in full
under “Site reported by Browser”. The approval unit stays in normal card flow; long cards scroll from their start. Wait/outcome recovery retains its own visible exit. The contract-only `request-unavailable`
stage in each connector retains request identity and provides return to the app.
The window lanes must produce this stage from a stale request selection as well
as every window-local stage listed above; the enabling lane supplies render data.

## Approval access and position (Main’s proposed sharpening of W:1173)

The site and each approving control share one normal-flow unit at the end of
the card. The site is the last content before those controls; only fixed Home
text of at most one short line may intervene. Approving controls are never
pinned independently of the site. When the unit fits, it may remain together;
otherwise the card scrolls from its start and the unit remains at its end. A
visible line near the top says “More below.” only while content remains below the viewport. The presentation mount observes scrolling, resizing and font completion to update this cue; these measurements govern the cue alone, never approval. Closing the view is
available at the top, without passing the site. App and wallet names,
app-authored reasons and account context precede this unit.

The origin wraps in full, at dots, with inside-label wrapping only when a
label cannot fit. The last three host labels and port stay together whenever
they fit the available line. Outcome cards keep the site in their design
position with the same wrapping. No approval uses a cached fit measurement.
This guarantees access and position. It does not establish that a person read
the site, authenticate it, or grant authority from it. The scrolling area may
contain the full card; it is not restricted to the identity area.

Computed transaction display values are supplied as their own bounded fields; they are never relabelled as words from the app. The provisional amount examples need a canonical projection from the foundation lane before real window production.


## Presentation recovery copy

For unknown-safety busy recovery, H:754 and H:763-780 govern Close and Wallet activity. A selected transaction on request-busy says that this transaction may still be waiting in the named wallet, once (H:772-775); it does not attribute that work to another window. Other busy cards describe the unanswered operation and uncertainty about other-window payment work. link-error with unknown safety conservatively withholds Connect pending the contract owner’s retry decision. This presentation choice supplies no producer, payment settlement or new authority.


## Existing-plumbing inputs

These optional closed presentation inputs describe what the current window can show. They add no effect, route, permission or Home message.

- `supportedActions`: a unique subset of `connectionActionIds`. Omit it for the design's full controls. A supplied list only removes controls, including account Copy/Disconnect, picker and panel controls and QR keyboard intents. It cannot add a connector or grant an effect. The factory replaces instructions for removed Check controls with fixed recovery copy. Missing navigation uses manual Home/app steps. When this window cannot close itself, Home's frame controls provide dismissal; an approving card puts that instruction at the top and initially focuses it.
- `copyFeedback`: `link-copied`, `address-copied`, or `copy-failed`. The window supplies its real Clipboard result. Fixed local text appears in an announced status element, including the QR card.
- `connectionNotice`: `account-changed`, `network-changed`, `transport-unavailable`, `connection-removed`, `connection-expired`, or `provider-unavailable`. This is a secondary fixed notice; it preserves the current wait, transaction hash/result, request and receipt. It never converts a provider disconnect into a wallet refusal or access-removal claim.
- `currentSelection`: exactly `{address,network}`, with bounds 128 and 80 characters. It is shown separately as isolated text. A differing selection labels the request's account Required account. The window supplies the request-bound address and network together in the account projection, and the live wallet selection here; a missing network must not be guessed from the wallet's new selection.
- `localReturn`: a boolean. On answered cards it adds the local-only `back-to-connection` intent. The window chooses its own next local screen; this intent sends no Home message and settles no payment.

The window lanes produce `wallet-loading`, `wallet-unavailable`, `home-wallet-required`, `provider-unavailable`, `account-changed`, `account-unavailable-unknown`, `network-unsupported`, `preparing-request` and `preparing-connection` from existing reads and events. Their named local fixtures are in `scripts/fixtures/wallet-connection-live-view-states.json`. Generic extension-wait remains the truthful state when the base gives one terminal link answer. Account recovery retries require proven false payment safety; an unknown snapshot keeps Close/check-Wallet recovery.

The request picker keeps every supplied summary (up to 100 other requests plus the selected one); other designed cards keep their short preview and View requests intent. Account cards accept up to 100 supplied rows and scroll; greater input is refused, not truncated. This is a bounded presentation batch, not a claim about Runtime's maximum account count. A producer needing a larger list needs paging and an agreed source bound. The pure summary reducer preserves Runtime's expired status and known request-kind titles; an unknown intent is Approval request. Existing dismissed input remains compatible with legacy callers and is not a claim that Runtime stores that status.

The default site label element is exactly Site reported by Browser. Its following colon and space are separate fixed punctuation. From app:, Requesting app and the request-unavailable sentence remain unchanged for the designer.


`transport-reconnecting` is an additional connectionNotice value: WalletConnect is reconnecting. The window adds/removes it from its existing SDK transport events in idle, wait or result states. A latent request summary never substitutes an account address or request identity on a non-request screen; an expired latent summary does not turn a link screen into an expired request.

`transactionHash` is a display-only 0x-prefixed 64-hex hash for supplied EVM transaction summaries. It remains full, selectable isolated text under Transaction hash:. It supplies no settlement or receipt, preserves the supplied outcome, and conservatively withholds Send/new-connection controls. The window supplies its already-validated base hash when its existing completion route fails. `showNextRequests` is an explicit opt-in to the existing local View requests control on terminal or blocked cards, from supplied other summaries. It preserves the outcome and grants no permission to send a consumed request again.

The requesting_app_name catalog field supplies the app label. Its absence uses the unchanged Requesting app fallback, including Browser/Notes actor IDs; the actor still controls whether the reported-site projection is eligible. No display name is invented from the actor ID.

The required CI origin subset uses the 135-character review host and 512-byte origin at 320×182 and 480×522, effective 100/200% zoom, in both engines. The all-state layout matrix keeps both phone frames, and the stage/style/mutation tests cover all approving stages and intermediate dot-wrap widths. Standalone origin tests keep all 480 scenarios.


`checking-response` is a WalletConnect window-local presentation while the existing verify/complete POST is pending. Its selected summary is optional because a link proof can have no app request. It says Your wallet has answered. Home is checking the response. and Stopping here ends this wait. Home may still record the response. Stop waiting keeps its existing local semantics. This stage records or settles nothing.

`network-unknown` and `network-unsupported` are additional fixed connectionNotice values. They can accompany a proof wait without any account projection. `localReturn` and `showNextRequests` are opt-in local display navigation on terminal or blocked cards, including unknown-result cards when the caller permits it. They preserve the exact outcome. Active Cancel/Stop waits and QR cards keep their explicit way out instead. A caller that keeps only Close on an unknown result leaves these flags off. The caller retains all consumed-request/effect guards when it handles local navigation. Queue text uses request for one and requests for several; an opt-in next queue is labelled other requests.

WalletConnect also supplies `home-read-unavailable` for a failed existing Home-summary read and `disconnect-error` for failed existing cleanup. Their Check again/Disconnect intents reuse the window's current read/cleanup handlers. Its `account-unavailable-unknown` state offers Get new QR code when supplied safety permits retry; an empty account list supplies no lock/removal cause and no account to confirm. Unknown safety retains Close/check-Wallet recovery.

`queueCount` remains the total number of displayed queue records. The added `queuePendingCount`, `queueRecoveryCount` and `queueOtherCount` distinguish pending requests, approved transaction records and other non-pending records from the reduced Runtime summaries. Only pending records are called requests waiting; approved transactions are transactions to review. All supplied records remain in the picker, including recovery records. These labels imply no new result or permission to send again.
