// Fixed local copy and closed stage definitions. Design source: 58aaafe6db48f8a3600f1e3bb8312499405502fc.
// This data grants no effect or navigation authority.
export const screens = {
  "walletconnect": {
    "nothing-saved": {
      "notice": "Connect a wallet app with a QR code, then sign a message.",
      "primary": {
        "id": "connect",
        "label": "Connect wallet",
        "quiet": false
      }
    },
    "internet-pending": {
      "status": "Allow WalletConnect to use the internet?",
      "notice": "Answer in Inbox to get your QR code.",
      "primary": {
        "id": "inbox",
        "label": "Show Request",
        "quiet": false
      },
      "secondary": [
        {
          "id": "cancel",
          "label": "Cancel",
          "quiet": false
        }
      ]
    },
    "internet-refused": {
      "status": "Internet access is off for WalletConnect.",
      "notice": "Allow access in Inbox, then return here to connect.",
      "primary": {
        "id": "inbox",
        "label": "Open Inbox",
        "quiet": false
      }
    },
    "internet-off": {
      "status": "Internet access is off for WalletConnect.",
      "notice": "Allow access in Inbox when you want to connect again.",
      "primary": {
        "id": "inbox",
        "label": "Open Inbox",
        "quiet": false
      }
    },
    "internet-expired": {
      "status": "The access request expired.",
      "notice": "After Allow, return here to connect.",
      "primary": {
        "id": "inbox",
        "label": "Open Inbox",
        "quiet": false
      },
      "focus": "inbox"
    },
    "internet-clearing": {
      "status": "Internet access is off.",
      "notice": "Finish removing the saved connection in Inbox.",
      "primary": {
        "id": "inbox",
        "label": "Open Inbox",
        "quiet": false
      }
    },
    "internet-ready": {
      "notice": "Connect a wallet app with a QR code, then sign a message.",
      "primary": {
        "id": "connect",
        "label": "Connect wallet",
        "quiet": false
      },
      "secondary": [
        {
          "id": "inbox",
          "label": "Manage in Inbox",
          "quiet": true
        }
      ]
    },
    "preparing-qr": {
      "status": "Getting your QR code…",
      "secondary": [
        {
          "id": "cancel",
          "label": "Cancel",
          "quiet": false
        }
      ]
    },
    "qr-shown": {
      "qr": true
    },
    "qr-cancelled": {
      "status": "Connection cancelled.",
      "primary": {
        "id": "connect",
        "label": "Connect wallet",
        "quiet": false
      },
      "focus": "connect"
    },
    "qr-expired": {
      "status": "QR code expired.",
      "primary": {
        "id": "connect",
        "label": "Try again",
        "quiet": false
      },
      "focus": "connect"
    },
    "connection-declined": {
      "status": "Connection declined.",
      "primary": {
        "id": "connect",
        "label": "Try again",
        "quiet": false
      },
      "focus": "connect"
    },
    "link-wait": {
      "status": "Open {{wallet}} on your phone and sign the message to confirm this account is yours.",
      "notice": "Stopping here leaves the request open in {{wallet}}.",
      "selectedAccount": true,
      "wait": true,
      "dispatched": true,
      "secondary": [
        {
          "id": "stop-waiting",
          "label": "Stop waiting",
          "quiet": false
        }
      ]
    },
    "link-declined": {
      "status": "Account confirmation declined.",
      "notice": "Send another message to connect this account.",
      "selectedAccount": true,
      "primary": {
        "id": "finish",
        "label": "Send new message",
        "quiet": false
      },
      "secondary": [
        {
          "id": "start-over",
          "label": "Get new QR code",
          "quiet": true
        }
      ],
      "focus": "finish"
    },
    "link-timeout": {
      "status": "Time to connect ran out.",
      "notice": "The request may still be waiting in {{wallet}}. Reject or close it there, then check again.",
      "selectedAccount": true,
      "primary": {
        "id": "check-access",
        "label": "Check again",
        "quiet": false
      },
      "secondary": [
        {
          "id": "start-over",
          "label": "Get new QR code",
          "quiet": true
        },
        {
          "id": "close-window",
          "label": "Close window",
          "quiet": true
        }
      ],
      "focus": "check-access"
    },
    "link-cancelled": {
      "status": "You stopped waiting.",
      "notice": "The request may still be waiting in {{wallet}}. Reject or close it there, then check again.",
      "selectedAccount": true,
      "primary": {
        "id": "check-access",
        "label": "Check again",
        "quiet": false
      },
      "secondary": [
        {
          "id": "start-over",
          "label": "Get new QR code",
          "quiet": true
        },
        {
          "id": "close-window",
          "label": "Close window",
          "quiet": true
        }
      ],
      "focus": "check-access"
    },
    "saved-unlinked": {
      "status": "Confirm this account is yours.",
      "notice": "Send a message to {{wallet}}, then sign it there.",
      "selectedAccount": true,
      "primary": {
        "id": "finish",
        "label": "Send message",
        "quiet": false
      },
      "secondary": [
        {
          "id": "start-over",
          "label": "Get new QR code",
          "quiet": true
        }
      ]
    },
    "connection-expired": {
      "status": "This wallet connection expired.",
      "primary": {
        "id": "start-over",
        "label": "Get new QR code",
        "quiet": false
      },
      "focus": "start-over"
    },
    "request-connection-expired": {
      "status": "This wallet connection expired.",
      "notice": "Reconnect with the account shown on this request, then send it.",
      "account": true,
      "request": true,
      "wait": true,
      "primary": {
        "id": "start-over",
        "label": "Get new QR code",
        "quiet": false
      },
      "focus": "start-over"
    },
    "wallet-removed": {
      "status": "Your wallet removed this connection.",
      "notice": "Scan a new QR code to reconnect.",
      "primary": {
        "id": "connect",
        "label": "Connect wallet",
        "quiet": false
      },
      "focus": "connect"
    },
    "linked": {
      "status": "Connected.",
      "account": true,
      "primary": {
        "id": "open-wallet",
        "label": "Open Wallet",
        "quiet": false
      },
      "focus": "open-wallet"
    },
    "linked-multiple": {
      "status": "Connected.",
      "account": true,
      "primary": {
        "id": "open-wallet",
        "label": "Open Wallet",
        "quiet": false
      },
      "focus": "open-wallet"
    },
    "request-waiting": {
      "account": true,
      "request": true,
      "wait": true,
      "requestAction": {
        "id": "send-request",
        "label": "Send to {{wallet}}",
        "quiet": false
      },
      "reviewAction": {
        "id": "open-wallet",
        "label": "Review in Wallet",
        "quiet": true
      }
    },
    "request-multiple": {
      "account": true,
      "request": true,
      "wait": true,
      "requestAction": {
        "id": "send-request",
        "label": "Send to {{wallet}}",
        "quiet": false
      },
      "reviewAction": {
        "id": "open-wallet",
        "label": "Review in Wallet",
        "quiet": true
      },
      "queueCount": 3,
      "choices": 0
    },
    "request-unsendable": {
      "status": "This request cannot be sent from WalletConnect. Reject it in Wallet.",
      "account": true,
      "request": true,
      "outcome": true,
      "primary": {
        "id": "open-wallet",
        "label": "Open Wallet",
        "quiet": false
      },
      "focus": "open-wallet"
    },
    "request-expired": {
      "status": "This request expired.",
      "notice": "To try again, return to {{site}} in {{app}}.",
      "account": true,
      "request": true,
      "outcome": true,
      "primary": {
        "id": "open-request-app",
        "label": "Open {{app}}",
        "quiet": false
      },
      "focus": "open-request-app"
    },
    "request-phone": {
      "status": "Waiting for {{wallet}}.",
      "notice": "Open {{wallet}} on your phone to check the message. Stopping here leaves it open in {{wallet}}.",
      "account": true,
      "request": true,
      "wait": true,
      "dispatched": true,
      "secondary": [
        {
          "id": "stop-waiting",
          "label": "Stop waiting",
          "quiet": false
        }
      ]
    },
    "request-declined": {
      "status": "{{wallet}} did not approve this message.",
      "notice": "To try again, return to {{site}} in {{app}}.",
      "account": true,
      "request": true,
      "outcome": true,
      "primary": {
        "id": "open-request-app",
        "label": "Open {{app}}",
        "quiet": false
      },
      "focus": "open-request-app"
    },
    "request-timeout": {
      "status": "Time to answer ran out.",
      "notice": "The request may still be waiting in {{wallet}}. Reject or close it there, then check again.",
      "account": true,
      "request": true,
      "outcome": true,
      "primary": {
        "id": "check-access",
        "label": "Check again",
        "quiet": false
      },
      "secondary": [
        {
          "id": "close-window",
          "label": "Close window",
          "quiet": true
        }
      ],
      "focus": "check-access"
    },
    "request-done": {
      "status": "Message signed.",
      "account": true,
      "request": true,
      "outcome": true,
      "primary": {
        "id": "open-request-app",
        "label": "Open {{app}}",
        "quiet": false
      },
      "focus": "open-request-app"
    },
    "request-cancelled": {
      "status": "You stopped waiting.",
      "notice": "The request may still be waiting in {{wallet}}. Reject or close it there, then check again.",
      "account": true,
      "request": true,
      "outcome": true,
      "primary": {
        "id": "check-access",
        "label": "Check again",
        "quiet": false
      },
      "secondary": [
        {
          "id": "close-window",
          "label": "Close window",
          "quiet": true
        }
      ],
      "focus": "check-access"
    },
    "transaction-waiting": {
      "account": true,
      "request": true,
      "wait": true,
      "requestAction": {
        "id": "send-request",
        "label": "Send to {{wallet}}",
        "quiet": false
      },
      "reviewAction": {
        "id": "open-wallet",
        "label": "Review in Wallet",
        "quiet": true
      }
    },
    "transaction-deadline": {
      "status": "There is too little time to send this transaction.",
      "notice": "Start it again on {{site}} in {{app}}.",
      "account": true,
      "request": true,
      "wait": true,
      "outcome": true,
      "primary": {
        "id": "open-request-app",
        "label": "Open {{app}}",
        "quiet": false
      },
      "focus": "open-request-app"
    },
    "transaction-phone": {
      "status": "Waiting for {{wallet}}.",
      "notice": "Check the transaction in {{wallet}} on your phone. Stopping here leaves the request open in {{wallet}}.",
      "account": true,
      "request": true,
      "wait": true,
      "dispatched": true,
      "secondary": [
        {
          "id": "stop-waiting",
          "label": "Stop waiting",
          "quiet": false
        }
      ]
    },
    "transaction-declined": {
      "status": "{{wallet}} did not approve this transaction.",
      "notice": "Dismiss in Wallet clears this request. To try again, return to {{site}} in {{app}}.",
      "account": true,
      "request": true,
      "outcome": true,
      "primary": {
        "id": "open-request-app",
        "label": "Open {{app}}",
        "quiet": false
      },
      "secondary": [
        {
          "id": "open-wallet",
          "label": "Dismiss in Wallet",
          "quiet": true
        }
      ],
      "focus": "open-request-app"
    },
    "transaction-timeout": {
      "status": "Transaction result unknown.",
      "notice": "Check {{wallet}} on your phone before sending again. Wallet activity shows any result received.",
      "account": true,
      "request": true,
      "outcome": true,
      "primary": {
        "id": "open-wallet-activity",
        "label": "Open Wallet activity",
        "quiet": false
      },
      "focus": "open-wallet-activity"
    },
    "transaction-cancelled": {
      "status": "You stopped waiting. Result unknown.",
      "notice": "Check {{wallet}} on your phone before sending again. Wallet activity shows any result received.",
      "account": true,
      "request": true,
      "outcome": true,
      "primary": {
        "id": "open-wallet-activity",
        "label": "Open Wallet activity",
        "quiet": false
      },
      "focus": "open-wallet-activity"
    },
    "transaction-wallet-error": {
      "status": "Transaction result unknown.",
      "notice": "Check {{wallet}} on your phone before sending again. Wallet activity shows any result received.",
      "account": true,
      "request": true,
      "outcome": true,
      "primary": {
        "id": "open-wallet-activity",
        "label": "Open Wallet activity",
        "quiet": false
      },
      "focus": "open-wallet-activity"
    },
    "transaction-done": {
      "status": "Transaction sent.",
      "account": true,
      "request": true,
      "outcome": true,
      "primary": {
        "id": "open-wallet-activity",
        "label": "Open Wallet activity",
        "quiet": false
      },
      "focus": "open-wallet-activity"
    },
    "transaction-reopened": {
      "status": "Transaction result unknown.",
      "notice": "Check {{wallet}} on your phone before sending again. Wallet activity shows any result received.",
      "account": true,
      "request": true,
      "outcome": true,
      "primary": {
        "id": "open-wallet-activity",
        "label": "Open Wallet activity",
        "quiet": false
      },
      "focus": "open-wallet-activity"
    },
    "request-wallet-error": {
      "status": "{{wallet}} could not sign this message.",
      "notice": "To try again, return to {{site}} in {{app}}.",
      "account": true,
      "request": true,
      "outcome": true,
      "primary": {
        "id": "open-request-app",
        "label": "Open {{app}}",
        "quiet": false
      },
      "focus": "open-request-app"
    },
    "request-new-connection": {
      "status": "Connect on {{network}} to send this request.",
      "notice": "Choose the account and network shown on this request.",
      "account": true,
      "request": true,
      "wait": true,
      "primary": {
        "id": "start-over",
        "label": "Get new QR code",
        "quiet": false
      }
    },
    "request-network-unsupported": {
      "status": "This wallet does not support the requested network.",
      "notice": "Use a wallet that supports {{network}} and has this account. This request has not been sent.",
      "account": true,
      "request": true,
      "requiredAccount": true,
      "primary": {
        "id": "start-over",
        "label": "Get new QR code",
        "quiet": false
      },
      "secondary": [
        {
          "id": "open-wallet",
          "label": "Open Wallet",
          "quiet": true
        }
      ]
    },
    "request-wallet-removed": {
      "status": "{{wallet}} ended the connection.",
      "notice": "This request has not been sent. Reconnect, then send it.",
      "account": true,
      "request": true,
      "primary": {
        "id": "start-over",
        "label": "Get new QR code",
        "quiet": false
      },
      "focus": "start-over"
    },
    "request-sent-wallet-removed": {
      "status": "{{wallet}} ended the connection after this message was sent.",
      "notice": "To try again, return to {{site}} in {{app}}.",
      "account": true,
      "request": true,
      "outcome": true,
      "primary": {
        "id": "open-request-app",
        "label": "Open {{app}}",
        "quiet": false
      },
      "focus": "open-request-app"
    },
    "transaction-wallet-removed": {
      "status": "Transaction result unknown.",
      "notice": "Check {{wallet}} on your phone before sending again. Wallet activity shows any result received.",
      "account": true,
      "request": true,
      "outcome": true,
      "primary": {
        "id": "open-wallet-activity",
        "label": "Open Wallet activity",
        "quiet": false
      },
      "focus": "open-wallet-activity"
    },
    "request-internet-off": {
      "status": "Internet access is off for WalletConnect.",
      "notice": "After Allow, return here and send this request.",
      "account": true,
      "request": true,
      "primary": {
        "id": "inbox",
        "label": "Open Inbox",
        "quiet": false
      }
    },
    "request-internet-pending": {
      "status": "Allow WalletConnect to use the internet?",
      "notice": "Answer in Inbox to send this message.",
      "account": true,
      "request": true,
      "primary": {
        "id": "inbox",
        "label": "Show Request",
        "quiet": false
      },
      "secondary": [
        {
          "id": "cancel",
          "label": "Cancel",
          "quiet": false
        }
      ]
    },
    "disconnecting": {
      "status": "Disconnecting…",
      "account": true,
      "disconnect": false
    },
    "disconnected": {
      "status": "Disconnected. Your accounts remain in Wallet.",
      "notice": "To remove this account from Home, open Wallet, choose Manage, then Remove account. Your wallet and funds stay unchanged.",
      "primary": {
        "id": "connect",
        "label": "Connect wallet",
        "quiet": false
      },
      "focus": "connect"
    },
    "window-expired": {
      "status": "This window is no longer active.",
      "notice": "Close this window, then choose WalletConnect in Wallet.",
      "primary": {
        "id": "close-window",
        "label": "Close window",
        "quiet": false
      },
      "focus": "close-window"
    },
    "guest-access": {
      "status": "Internet access is not allowed.",
      "notice": "Only the person who set up this Home can allow it. This account cannot send them a question.",
      "primary": {
        "id": "check-status",
        "label": "Check again",
        "quiet": false
      },
      "focus": "check-status"
    },
    "link-error": {
      "status": "Could not connect.",
      "primary": {
        "id": "connect",
        "label": "Try again",
        "quiet": false
      },
      "focus": "connect"
    },
    "request-list": {
      "account": true,
      "request": true,
      "wait": true,
      "requestPicker": true,
      "requestAction": {
        "id": "send-request",
        "label": "Send to {{wallet}}",
        "quiet": false
      },
      "reviewAction": {
        "id": "open-wallet",
        "label": "Review in Wallet",
        "quiet": true
      },
      "focus": "select-request",
      "queueCount": 3,
      "choices": 3
    },
    "request-selected-second": {
      "account": true,
      "request": true,
      "wait": true,
      "requestAction": {
        "id": "send-request",
        "label": "Send to {{wallet}}",
        "quiet": false
      },
      "reviewAction": {
        "id": "open-wallet",
        "label": "Review in Wallet",
        "quiet": true
      },
      "focus": "send-request",
      "queueCount": 3,
      "choices": 0
    },
    "request-next": {
      "status": "{{app}} message signed.",
      "account": true,
      "request": true,
      "outcome": true,
      "focusOutcome": true,
      "afterAnswer": true,
      "queueCount": 2,
      "choices": 1
    },
    "transaction-late-result": {
      "status": "Transaction sent. The result arrived after waiting ended.",
      "notice": "Wallet activity has the transaction result.",
      "account": true,
      "request": true,
      "outcome": true,
      "primary": {
        "id": "open-wallet-activity",
        "label": "Open Wallet activity",
        "quiet": false
      },
      "focus": "open-wallet-activity"
    },
    "guest-ready": {
      "status": "Internet access is allowed.",
      "primary": {
        "id": "connect",
        "label": "Connect wallet",
        "quiet": false
      },
      "focus": "connect"
    },
    "link-busy": {
      "status": "{{wallet}} has not answered.",
      "notice": "Start again with a new QR code. This ends the earlier connection.",
      "selectedAccount": true,
      "primary": {
        "id": "start-over",
        "label": "Get new QR code",
        "quiet": false
      },
      "secondary": [
        {
          "id": "check-access",
          "label": "Check again",
          "quiet": true
        },
        {
          "id": "close-window",
          "label": "Close window",
          "quiet": true
        }
      ],
      "focus": "start-over"
    },
    "request-busy": {
      "status": "{{wallet}} has not answered.",
      "notice": "Close this window. The request may still be waiting in {{wallet}}. Reject or close it there.",
      "account": true,
      "request": true,
      "outcome": true,
      "primary": {
        "id": "close-window",
        "label": "Close window",
        "quiet": false
      },
      "secondary": [
        {
          "id": "check-access",
          "label": "Check again",
          "quiet": true
        }
      ],
      "focus": "close-window"
    },
    "link-late-ignored": {
      "status": "The signed message arrived after waiting ended.",
      "notice": "Try again to connect with a new QR code.",
      "selectedAccount": true,
      "primary": {
        "id": "connect",
        "label": "Try again",
        "quiet": false
      },
      "focus": "connect"
    },
    "focus": {
      "notice": "Connect a wallet app with a QR code, then sign a message.",
      "primary": {
        "id": "connect",
        "label": "Connect wallet",
        "quiet": false
      },
      "focus": "connect"
    }
  },
  "metamask": {
    "ready": {
      "notice": "Choose an account in the extension, then sign a message.",
      "primary": {
        "id": "connect",
        "label": "Connect wallet",
        "quiet": false
      }
    },
    "ready-multiple": {
      "notice": "Connect will use {{wallet}}. {{alternative}} is also available.",
      "primary": {
        "id": "connect",
        "label": "Connect wallet",
        "quiet": false
      }
    },
    "extension-missing": {
      "status": "{{wallet}} was not found here.",
      "notice": "Connect a wallet app with a QR code. If you enable {{wallet}} in this browser, reload Home using your browser’s Reload control.",
      "primary": {
        "id": "use-walletconnect",
        "label": "WalletConnect",
        "quiet": false
      },
      "focus": "use-walletconnect"
    },
    "extensions-unavailable": {
      "status": "No wallet extension was found here.",
      "notice": "Connect a wallet app with a QR code.",
      "primary": {
        "id": "use-walletconnect",
        "label": "WalletConnect",
        "quiet": false
      }
    },
    "extension-wait": {
      "status": "Open {{wallet}} to continue.",
      "notice": "Find {{wallet}} in your browser’s extensions menu. Unlock it if asked. Stopping here leaves its prompt open.",
      "wait": true,
      "dispatched": true,
      "secondary": [
        {
          "id": "stop-waiting",
          "label": "Stop waiting",
          "quiet": false
        }
      ]
    },
    "extension-timeout": {
      "status": "Time to connect ran out.",
      "notice": "The request may still be waiting in {{wallet}}. Reject or close it there, then check again. If {{wallet}} will not open, enable it in your browser, then use the browser’s Reload control.",
      "primary": {
        "id": "check-access",
        "label": "Check again",
        "quiet": false
      },
      "secondary": [
        {
          "id": "close-window",
          "label": "Close window",
          "quiet": true
        },
        {
          "id": "use-walletconnect",
          "label": "WalletConnect",
          "quiet": true
        }
      ],
      "focus": "check-access"
    },
    "extension-cancelled": {
      "status": "You stopped waiting.",
      "notice": "The request may still be waiting in {{wallet}}. Reject or close it there, then check again. If {{wallet}} will not open, enable it in your browser, then use the browser’s Reload control.",
      "primary": {
        "id": "check-access",
        "label": "Check again",
        "quiet": false
      },
      "secondary": [
        {
          "id": "close-window",
          "label": "Close window",
          "quiet": true
        },
        {
          "id": "use-walletconnect",
          "label": "WalletConnect",
          "quiet": true
        }
      ],
      "focus": "check-access"
    },
    "link-wait": {
      "status": "Open {{wallet}} and sign the message to confirm this account is yours.",
      "notice": "Find {{wallet}} in your browser’s extensions menu. Unlock it if asked. Stopping here leaves the request open in {{wallet}}.",
      "selectedAccount": true,
      "wait": true,
      "dispatched": true,
      "secondary": [
        {
          "id": "stop-waiting",
          "label": "Stop waiting",
          "quiet": false
        }
      ]
    },
    "connection-declined": {
      "status": "Connection declined.",
      "primary": {
        "id": "connect",
        "label": "Try again",
        "quiet": false
      },
      "focus": "connect"
    },
    "link-declined": {
      "status": "Account confirmation declined.",
      "notice": "Send another message to connect this account.",
      "selectedAccount": true,
      "primary": {
        "id": "send-message",
        "label": "Send new message",
        "quiet": false
      },
      "focus": "send-message"
    },
    "link-timeout": {
      "status": "Time to connect ran out.",
      "notice": "The request may still be waiting in {{wallet}}. Reject or close it there, then check again. If {{wallet}} will not open, enable it in your browser, then use the browser’s Reload control.",
      "selectedAccount": true,
      "primary": {
        "id": "check-access",
        "label": "Check again",
        "quiet": false
      },
      "secondary": [
        {
          "id": "close-window",
          "label": "Close window",
          "quiet": true
        },
        {
          "id": "use-walletconnect",
          "label": "WalletConnect",
          "quiet": true
        }
      ],
      "focus": "check-access"
    },
    "link-cancelled": {
      "status": "You stopped waiting.",
      "notice": "The request may still be waiting in {{wallet}}. Reject or close it there, then check again. If {{wallet}} will not open, enable it in your browser, then use the browser’s Reload control.",
      "selectedAccount": true,
      "primary": {
        "id": "check-access",
        "label": "Check again",
        "quiet": false
      },
      "secondary": [
        {
          "id": "close-window",
          "label": "Close window",
          "quiet": true
        },
        {
          "id": "use-walletconnect",
          "label": "WalletConnect",
          "quiet": true
        }
      ],
      "focus": "check-access"
    },
    "link-late-ignored": {
      "status": "The signed message arrived after waiting ended.",
      "notice": "Try again to confirm this account.",
      "selectedAccount": true,
      "primary": {
        "id": "connect",
        "label": "Try again",
        "quiet": false
      },
      "focus": "connect"
    },
    "account-unavailable": {
      "status": "{{wallet}} is not providing the linked account to Home.",
      "notice": "In {{wallet}}, open Account options → Permissions → {{home}} → Manage connected accounts. Select the required account, then Save.",
      "selectedAccount": true,
      "primary": {
        "id": "connect",
        "label": "Connect wallet",
        "quiet": false
      },
      "secondary": [
        {
          "id": "check-access",
          "label": "Check access",
          "quiet": true
        }
      ],
      "focus": "connect"
    },
    "site-access-ended": {
      "status": "{{wallet}} is not sharing this account with Home.",
      "notice": "Choose Connect wallet to restore access. In {{wallet}}, this Home is {{home}} under Account options → Permissions.",
      "selectedAccount": true,
      "primary": {
        "id": "restore-access",
        "label": "Connect wallet",
        "quiet": false
      }
    },
    "connect-already-open": {
      "status": "A connection request is already open in {{wallet}}.",
      "notice": "The request may still be waiting in {{wallet}}. Reject or close it there, then check again. If {{wallet}} will not open, enable it in your browser, then use the browser’s Reload control.",
      "primary": {
        "id": "check-access",
        "label": "Check again",
        "quiet": false
      },
      "secondary": [
        {
          "id": "close-window",
          "label": "Close window",
          "quiet": true
        },
        {
          "id": "use-walletconnect",
          "label": "WalletConnect",
          "quiet": true
        }
      ],
      "focus": "check-access"
    },
    "request-access-error": {
      "status": "{{wallet}} did not allow this message.",
      "notice": "To try again, return to {{site}} in {{app}}.",
      "account": true,
      "request": true,
      "outcome": true,
      "requiredAccount": true,
      "primary": {
        "id": "open-request-app",
        "label": "Open {{app}}",
        "quiet": false
      },
      "focus": "open-request-app"
    },
    "transaction-access-error": {
      "status": "{{wallet}} did not allow this transaction.",
      "notice": "Review Wallet activity before starting a new request.",
      "account": true,
      "request": true,
      "outcome": true,
      "requiredAccount": true,
      "primary": {
        "id": "open-wallet-activity",
        "label": "Open Wallet activity",
        "quiet": false
      },
      "focus": "open-wallet-activity"
    },
    "request-network-declined": {
      "status": "Network change declined in {{wallet}}.",
      "notice": "The transaction was not sent. Try again to choose its network.",
      "account": true,
      "request": true,
      "outcome": true,
      "primary": {
        "id": "send-request",
        "label": "Try again",
        "quiet": false
      },
      "focus": "send-request"
    },
    "request-network-unknown": {
      "status": "{{wallet}} does not know the requested network.",
      "notice": "Reject this request in Wallet, or ask {{app}} for a network available in {{wallet}}.",
      "account": true,
      "request": true,
      "outcome": true,
      "primary": {
        "id": "open-wallet",
        "label": "Open Wallet",
        "quiet": false
      },
      "focus": "open-wallet"
    },
    "linked": {
      "status": "Connected.",
      "afterActionsNote": "To stop sharing, open {{wallet}}’s Account options → Permissions → {{home}} → Disconnect.",
      "account": true,
      "disconnect": false,
      "primary": {
        "id": "open-wallet",
        "label": "Open Wallet",
        "quiet": false
      },
      "focus": "open-wallet"
    },
    "request-waiting": {
      "account": true,
      "request": true,
      "wait": true,
      "requestAction": {
        "id": "send-request",
        "label": "Send to {{wallet}}",
        "quiet": false
      },
      "reviewAction": {
        "id": "open-wallet",
        "label": "Review in Wallet",
        "quiet": true
      }
    },
    "request-multiple": {
      "account": true,
      "request": true,
      "wait": true,
      "requestAction": {
        "id": "send-request",
        "label": "Send to {{wallet}}",
        "quiet": false
      },
      "reviewAction": {
        "id": "open-wallet",
        "label": "Review in Wallet",
        "quiet": true
      },
      "queueCount": 3,
      "choices": 0
    },
    "request-unsendable": {
      "status": "{{wallet}} is not providing the account this request needs.",
      "notice": "In {{wallet}}, open Account options → Permissions → {{home}} → Manage connected accounts. Select the required account, then Save.",
      "account": true,
      "request": true,
      "outcome": true,
      "requiredAccount": true,
      "primary": {
        "id": "connect",
        "label": "Connect wallet",
        "quiet": false
      },
      "secondary": [
        {
          "id": "check-access",
          "label": "Check access",
          "quiet": true
        },
        {
          "id": "open-wallet",
          "label": "Open Wallet",
          "quiet": true
        }
      ],
      "focus": "connect"
    },
    "request-typed-data": {
      "account": true,
      "request": true,
      "wait": true,
      "requestAction": {
        "id": "send-request",
        "label": "Send to {{wallet}}",
        "quiet": false
      },
      "reviewAction": {
        "id": "open-wallet",
        "label": "Review in Wallet",
        "quiet": true
      }
    },
    "request-expired": {
      "status": "This request expired.",
      "notice": "To try again, return to {{site}} in {{app}}.",
      "account": true,
      "request": true,
      "outcome": true,
      "primary": {
        "id": "open-request-app",
        "label": "Open {{app}}",
        "quiet": false
      },
      "focus": "open-request-app"
    },
    "request-extension": {
      "status": "Waiting for {{wallet}}.",
      "notice": "Open {{wallet}} from your browser’s extensions menu. Stopping here leaves it open in {{wallet}}.",
      "account": true,
      "request": true,
      "wait": true,
      "dispatched": true,
      "secondary": [
        {
          "id": "stop-waiting",
          "label": "Stop waiting",
          "quiet": false
        }
      ]
    },
    "request-declined": {
      "status": "{{wallet}} did not approve this message.",
      "notice": "To try again, return to {{site}} in {{app}}.",
      "account": true,
      "request": true,
      "outcome": true,
      "primary": {
        "id": "open-request-app",
        "label": "Open {{app}}",
        "quiet": false
      },
      "focus": "open-request-app"
    },
    "request-timeout": {
      "status": "Time to answer ran out.",
      "notice": "The request may still be waiting in {{wallet}}. Reject or close it there, then check again. If {{wallet}} will not open, enable it in your browser, then use the browser’s Reload control.",
      "account": true,
      "request": true,
      "outcome": true,
      "primary": {
        "id": "check-access",
        "label": "Check again",
        "quiet": false
      },
      "secondary": [
        {
          "id": "close-window",
          "label": "Close window",
          "quiet": true
        }
      ],
      "focus": "check-access"
    },
    "request-done": {
      "status": "Message signed.",
      "account": true,
      "request": true,
      "outcome": true,
      "primary": {
        "id": "open-request-app",
        "label": "Open {{app}}",
        "quiet": false
      },
      "focus": "open-request-app"
    },
    "request-cancelled": {
      "status": "You stopped waiting.",
      "notice": "The request may still be waiting in {{wallet}}. Reject or close it there, then check again. If {{wallet}} will not open, enable it in your browser, then use the browser’s Reload control.",
      "account": true,
      "request": true,
      "outcome": true,
      "primary": {
        "id": "check-access",
        "label": "Check again",
        "quiet": false
      },
      "secondary": [
        {
          "id": "close-window",
          "label": "Close window",
          "quiet": true
        }
      ],
      "focus": "check-access"
    },
    "transaction-waiting": {
      "account": true,
      "request": true,
      "wait": true,
      "requestAction": {
        "id": "send-request",
        "label": "Send to {{wallet}}",
        "quiet": false
      },
      "reviewAction": {
        "id": "open-wallet",
        "label": "Review in Wallet",
        "quiet": true
      }
    },
    "transaction-extension": {
      "status": "Waiting for {{wallet}}.",
      "notice": "Check the transaction in {{wallet}}. Stopping here leaves the request open in {{wallet}}.",
      "account": true,
      "request": true,
      "wait": true,
      "dispatched": true,
      "secondary": [
        {
          "id": "stop-waiting",
          "label": "Stop waiting",
          "quiet": false
        }
      ]
    },
    "transaction-declined": {
      "status": "{{wallet}} did not approve this transaction.",
      "notice": "To try again, return to {{site}} in {{app}}.",
      "account": true,
      "request": true,
      "outcome": true,
      "primary": {
        "id": "open-request-app",
        "label": "Open {{app}}",
        "quiet": false
      },
      "focus": "open-request-app"
    },
    "transaction-timeout": {
      "status": "Transaction result unknown.",
      "notice": "Check {{wallet}} before sending again. Wallet activity shows any result received.",
      "account": true,
      "request": true,
      "outcome": true,
      "primary": {
        "id": "open-wallet-activity",
        "label": "Open Wallet activity",
        "quiet": false
      },
      "focus": "open-wallet-activity"
    },
    "transaction-cancelled": {
      "status": "You stopped waiting. Result unknown.",
      "notice": "Check {{wallet}} before sending again. Wallet activity shows any result received.",
      "account": true,
      "request": true,
      "outcome": true,
      "primary": {
        "id": "open-wallet-activity",
        "label": "Open Wallet activity",
        "quiet": false
      },
      "focus": "open-wallet-activity"
    },
    "transaction-wallet-error": {
      "status": "Transaction result unknown.",
      "notice": "Check {{wallet}} before sending again. Wallet activity shows any result received.",
      "account": true,
      "request": true,
      "outcome": true,
      "primary": {
        "id": "open-wallet-activity",
        "label": "Open Wallet activity",
        "quiet": false
      },
      "focus": "open-wallet-activity"
    },
    "transaction-done": {
      "status": "Transaction sent.",
      "account": true,
      "request": true,
      "outcome": true,
      "primary": {
        "id": "open-wallet-activity",
        "label": "Open Wallet activity",
        "quiet": false
      },
      "focus": "open-wallet-activity"
    },
    "request-wallet-error": {
      "status": "{{wallet}} could not sign this message.",
      "notice": "To try again, return to {{site}} in {{app}}.",
      "account": true,
      "request": true,
      "outcome": true,
      "primary": {
        "id": "open-request-app",
        "label": "Open {{app}}",
        "quiet": false
      },
      "focus": "open-request-app"
    },
    "request-late-ignored": {
      "status": "The signed message arrived after waiting ended.",
      "notice": "To try again, return to {{site}} in {{app}}.",
      "account": true,
      "request": true,
      "outcome": true,
      "primary": {
        "id": "open-request-app",
        "label": "Open {{app}}",
        "quiet": false
      },
      "focus": "open-request-app"
    },
    "window-expired": {
      "status": "This window is no longer active.",
      "notice": "Close this window, then choose {{wallet}} in Wallet.",
      "primary": {
        "id": "close-window",
        "label": "Close window",
        "quiet": false
      },
      "focus": "close-window"
    },
    "link-error": {
      "status": "Could not connect.",
      "primary": {
        "id": "connect",
        "label": "Try again",
        "quiet": false
      },
      "focus": "connect"
    },
    "request-list": {
      "account": true,
      "request": true,
      "wait": true,
      "requestPicker": true,
      "requestAction": {
        "id": "send-request",
        "label": "Send to {{wallet}}",
        "quiet": false
      },
      "reviewAction": {
        "id": "open-wallet",
        "label": "Review in Wallet",
        "quiet": true
      },
      "focus": "select-request",
      "queueCount": 3,
      "choices": 3
    },
    "request-selected-second": {
      "account": true,
      "request": true,
      "wait": true,
      "requestAction": {
        "id": "send-request",
        "label": "Send to {{wallet}}",
        "quiet": false
      },
      "reviewAction": {
        "id": "open-wallet",
        "label": "Review in Wallet",
        "quiet": true
      },
      "focus": "send-request",
      "queueCount": 3,
      "choices": 0
    },
    "request-next": {
      "status": "{{app}} message signed.",
      "account": true,
      "request": true,
      "outcome": true,
      "focusOutcome": true,
      "afterAnswer": true,
      "queueCount": 2,
      "choices": 1
    },
    "transaction-late-result": {
      "status": "Transaction sent. The result arrived after waiting ended.",
      "notice": "Wallet activity has the transaction result.",
      "account": true,
      "request": true,
      "outcome": true,
      "primary": {
        "id": "open-wallet-activity",
        "label": "Open Wallet activity",
        "quiet": false
      },
      "focus": "open-wallet-activity"
    },
    "other-ethereum-wallet": {
      "status": "{{wallet}} was not found here.",
      "notice": "Connect a wallet app with a QR code. If you enable {{wallet}} in this browser, reload Home using your browser’s Reload control.",
      "primary": {
        "id": "use-walletconnect",
        "label": "WalletConnect",
        "quiet": false
      },
      "focus": "use-walletconnect"
    },
    "access-wrong-account": {
      "status": "{{wallet}} returned a different account.",
      "notice": "Choose Connect wallet, then select the required account in {{wallet}}’s Manage connected accounts and Save.",
      "account": true,
      "request": true,
      "outcome": true,
      "requiredAccount": true,
      "primary": {
        "id": "connect",
        "label": "Connect wallet",
        "quiet": false
      },
      "secondary": [
        {
          "id": "check-access",
          "label": "Check access",
          "quiet": true
        },
        {
          "id": "open-wallet",
          "label": "Open Wallet",
          "quiet": true
        }
      ],
      "focus": "connect"
    },
    "link-busy": {
      "status": "{{wallet}} has not answered.",
      "notice": "Close this window. The request may still be waiting in {{wallet}}. Reject or close it there. If {{wallet}} will not open, enable it in your browser, then use the browser’s Reload control.",
      "selectedAccount": true,
      "primary": {
        "id": "close-window",
        "label": "Close window",
        "quiet": false
      },
      "secondary": [
        {
          "id": "check-access",
          "label": "Check again",
          "quiet": true
        },
        {
          "id": "use-walletconnect",
          "label": "WalletConnect",
          "quiet": true
        }
      ],
      "focus": "close-window"
    },
    "request-busy": {
      "status": "{{wallet}} has not answered.",
      "notice": "Close this window. The request may still be waiting in {{wallet}}. Reject or close it there. If {{wallet}} will not open, enable it in your browser, then use the browser’s Reload control.",
      "account": true,
      "request": true,
      "outcome": true,
      "primary": {
        "id": "close-window",
        "label": "Close window",
        "quiet": false
      },
      "secondary": [
        {
          "id": "check-access",
          "label": "Check again",
          "quiet": true
        }
      ],
      "focus": "close-window"
    },
    "extension-busy": {
      "status": "{{wallet}} has not answered.",
      "notice": "Close this window. The request may still be waiting in {{wallet}}. Reject or close it there. If {{wallet}} will not open, enable it in your browser, then use the browser’s Reload control.",
      "primary": {
        "id": "close-window",
        "label": "Close window",
        "quiet": false
      },
      "secondary": [
        {
          "id": "check-access",
          "label": "Check again",
          "quiet": true
        },
        {
          "id": "use-walletconnect",
          "label": "WalletConnect",
          "quiet": true
        }
      ],
      "focus": "close-window"
    },
    "extension-late-ignored": {
      "status": "{{wallet}} answered after waiting ended.",
      "notice": "Try again to connect.",
      "primary": {
        "id": "connect",
        "label": "Try again",
        "quiet": false
      },
      "focus": "connect"
    },
    "focus": {
      "notice": "Choose an account in the extension, then sign a message.",
      "primary": {
        "id": "connect",
        "label": "Connect wallet",
        "quiet": false
      },
      "focus": "connect"
    }
  },
  "unisat": {
    "ready": {
      "notice": "Choose an account in the extension, then sign a message.",
      "primary": {
        "id": "connect",
        "label": "Connect wallet",
        "quiet": false
      }
    },
    "extension-missing": {
      "status": "{{wallet}} was not found here.",
      "notice": "Enable {{wallet}} in this browser, then reload Home using the browser’s Reload control. Open {{wallet}} again from Wallet.",
      "primary": {
        "id": "close-window",
        "label": "Close window",
        "quiet": false
      },
      "focus": "close-window"
    },
    "extensions-unavailable": {
      "status": "No wallet extension was found here.",
      "notice": "Enable {{wallet}} in this browser, then reload Home using the browser’s Reload control. Open {{wallet}} again from Wallet.",
      "primary": {
        "id": "close-window",
        "label": "Close window",
        "quiet": false
      }
    },
    "extension-wait": {
      "status": "Open {{wallet}} to continue.",
      "notice": "Find {{wallet}} in your browser’s extensions menu. Unlock it if asked. Stopping here leaves its prompt open.",
      "wait": true,
      "dispatched": true,
      "secondary": [
        {
          "id": "stop-waiting",
          "label": "Stop waiting",
          "quiet": false
        }
      ]
    },
    "extension-timeout": {
      "status": "Time to connect ran out.",
      "notice": "The request may still be waiting in {{wallet}}. Reject or close it there, then check again. If {{wallet}} will not open, enable it in your browser, then use the browser’s Reload control.",
      "primary": {
        "id": "check-access",
        "label": "Check again",
        "quiet": false
      },
      "secondary": [
        {
          "id": "close-window",
          "label": "Close window",
          "quiet": true
        }
      ],
      "focus": "check-access"
    },
    "extension-cancelled": {
      "status": "You stopped waiting.",
      "notice": "The request may still be waiting in {{wallet}}. Reject or close it there, then check again. If {{wallet}} will not open, enable it in your browser, then use the browser’s Reload control.",
      "primary": {
        "id": "check-access",
        "label": "Check again",
        "quiet": false
      },
      "secondary": [
        {
          "id": "close-window",
          "label": "Close window",
          "quiet": true
        }
      ],
      "focus": "check-access"
    },
    "link-wait": {
      "status": "Open {{wallet}} and sign the message to confirm this account is yours.",
      "notice": "Find {{wallet}} in your browser’s extensions menu. Unlock it if asked. Stopping here leaves the request open in {{wallet}}.",
      "selectedAccount": true,
      "wait": true,
      "dispatched": true,
      "secondary": [
        {
          "id": "stop-waiting",
          "label": "Stop waiting",
          "quiet": false
        }
      ]
    },
    "connection-declined": {
      "status": "Connection declined.",
      "primary": {
        "id": "connect",
        "label": "Try again",
        "quiet": false
      },
      "focus": "connect"
    },
    "link-declined": {
      "status": "Account confirmation declined.",
      "notice": "Send another message to connect this account.",
      "selectedAccount": true,
      "primary": {
        "id": "send-message",
        "label": "Send new message",
        "quiet": false
      },
      "focus": "send-message"
    },
    "link-timeout": {
      "status": "Time to connect ran out.",
      "notice": "The request may still be waiting in {{wallet}}. Reject or close it there, then check again. If {{wallet}} will not open, enable it in your browser, then use the browser’s Reload control.",
      "selectedAccount": true,
      "primary": {
        "id": "check-access",
        "label": "Check again",
        "quiet": false
      },
      "secondary": [
        {
          "id": "close-window",
          "label": "Close window",
          "quiet": true
        }
      ],
      "focus": "check-access"
    },
    "link-cancelled": {
      "status": "You stopped waiting.",
      "notice": "The request may still be waiting in {{wallet}}. Reject or close it there, then check again. If {{wallet}} will not open, enable it in your browser, then use the browser’s Reload control.",
      "selectedAccount": true,
      "primary": {
        "id": "check-access",
        "label": "Check again",
        "quiet": false
      },
      "secondary": [
        {
          "id": "close-window",
          "label": "Close window",
          "quiet": true
        }
      ],
      "focus": "check-access"
    },
    "link-late-ignored": {
      "status": "The signed message arrived after waiting ended.",
      "notice": "Try again to confirm this account.",
      "selectedAccount": true,
      "primary": {
        "id": "connect",
        "label": "Try again",
        "quiet": false
      },
      "focus": "connect"
    },
    "account-unavailable": {
      "status": "{{wallet}} is not providing the linked account to Home.",
      "notice": "Choose the required account in {{wallet}}, then choose Connect wallet.",
      "selectedAccount": true,
      "primary": {
        "id": "connect",
        "label": "Connect wallet",
        "quiet": false
      },
      "secondary": [
        {
          "id": "check-access",
          "label": "Check access",
          "quiet": true
        }
      ],
      "focus": "connect"
    },
    "network-changed": {
      "status": "{{wallet}} is using a Bitcoin test network.",
      "notice": "Select Bitcoin mainnet in {{wallet}}, then try again.",
      "primary": {
        "id": "connect",
        "label": "Try again",
        "quiet": false
      }
    },
    "network-fractal": {
      "status": "Home supports Bitcoin mainnet only.",
      "notice": "Select Bitcoin mainnet in {{wallet}}, then try again.",
      "primary": {
        "id": "connect",
        "label": "Try again",
        "quiet": false
      }
    },
    "network-unknown": {
      "status": "Home cannot identify this {{wallet}} network.",
      "notice": "Select Bitcoin mainnet in {{wallet}}, then try again.",
      "primary": {
        "id": "connect",
        "label": "Try again",
        "quiet": false
      }
    },
    "linked": {
      "status": "Connected.",
      "account": true,
      "disconnect": false,
      "primary": {
        "id": "open-wallet",
        "label": "Open Wallet",
        "quiet": false
      },
      "focus": "open-wallet"
    },
    "request-waiting": {
      "account": true,
      "request": true,
      "wait": true,
      "requestAction": {
        "id": "send-request",
        "label": "Send to {{wallet}}",
        "quiet": false
      },
      "reviewAction": {
        "id": "open-wallet",
        "label": "Review in Wallet",
        "quiet": true
      }
    },
    "request-multiple": {
      "account": true,
      "request": true,
      "wait": true,
      "requestAction": {
        "id": "send-request",
        "label": "Send to {{wallet}}",
        "quiet": false
      },
      "reviewAction": {
        "id": "open-wallet",
        "label": "Review in Wallet",
        "quiet": true
      },
      "queueCount": 3,
      "choices": 0
    },
    "request-unsendable": {
      "status": "{{wallet}} is not providing the account this request needs.",
      "notice": "Choose the required account in {{wallet}}, then choose Connect wallet.",
      "account": true,
      "request": true,
      "outcome": true,
      "requiredAccount": true,
      "primary": {
        "id": "connect",
        "label": "Connect wallet",
        "quiet": false
      },
      "secondary": [
        {
          "id": "check-access",
          "label": "Check access",
          "quiet": true
        },
        {
          "id": "open-wallet",
          "label": "Open Wallet",
          "quiet": true
        }
      ],
      "focus": "connect"
    },
    "request-expired": {
      "status": "This request expired.",
      "notice": "Start a new request in {{app}} to try again.",
      "account": true,
      "request": true,
      "outcome": true,
      "primary": {
        "id": "open-request-app",
        "label": "Open {{app}}",
        "quiet": false
      },
      "focus": "open-request-app"
    },
    "request-extension": {
      "status": "Waiting for {{wallet}}.",
      "notice": "Open {{wallet}} from your browser’s extensions menu. Stopping here leaves it open in {{wallet}}.",
      "account": true,
      "request": true,
      "wait": true,
      "dispatched": true,
      "secondary": [
        {
          "id": "stop-waiting",
          "label": "Stop waiting",
          "quiet": false
        }
      ]
    },
    "request-declined": {
      "status": "{{wallet}} did not approve this message.",
      "notice": "Start a new request in {{app}} to try again.",
      "account": true,
      "request": true,
      "outcome": true,
      "primary": {
        "id": "open-request-app",
        "label": "Open {{app}}",
        "quiet": false
      },
      "focus": "open-request-app"
    },
    "request-timeout": {
      "status": "Time to answer ran out.",
      "notice": "The request may still be waiting in {{wallet}}. Reject or close it there, then check again. If {{wallet}} will not open, enable it in your browser, then use the browser’s Reload control.",
      "account": true,
      "request": true,
      "outcome": true,
      "primary": {
        "id": "check-access",
        "label": "Check again",
        "quiet": false
      },
      "secondary": [
        {
          "id": "close-window",
          "label": "Close window",
          "quiet": true
        }
      ],
      "focus": "check-access"
    },
    "request-done": {
      "status": "Message signed.",
      "account": true,
      "request": true,
      "outcome": true,
      "primary": {
        "id": "open-request-app",
        "label": "Open {{app}}",
        "quiet": false
      },
      "focus": "open-request-app"
    },
    "request-cancelled": {
      "status": "You stopped waiting.",
      "notice": "The request may still be waiting in {{wallet}}. Reject or close it there, then check again. If {{wallet}} will not open, enable it in your browser, then use the browser’s Reload control.",
      "account": true,
      "request": true,
      "outcome": true,
      "primary": {
        "id": "check-access",
        "label": "Check again",
        "quiet": false
      },
      "secondary": [
        {
          "id": "close-window",
          "label": "Close window",
          "quiet": true
        }
      ],
      "focus": "check-access"
    },
    "request-wallet-error": {
      "status": "{{wallet}} could not sign this message.",
      "notice": "Start a new request in {{app}} to try again.",
      "account": true,
      "request": true,
      "outcome": true,
      "primary": {
        "id": "open-request-app",
        "label": "Open {{app}}",
        "quiet": false
      },
      "focus": "open-request-app"
    },
    "request-late-ignored": {
      "status": "The signed message arrived after waiting ended.",
      "notice": "Start a new request in {{app}} to try again.",
      "account": true,
      "request": true,
      "outcome": true,
      "primary": {
        "id": "open-request-app",
        "label": "Open {{app}}",
        "quiet": false
      },
      "focus": "open-request-app"
    },
    "window-expired": {
      "status": "This window is no longer active.",
      "notice": "Close this window, then choose {{wallet}} in Wallet.",
      "primary": {
        "id": "close-window",
        "label": "Close window",
        "quiet": false
      },
      "focus": "close-window"
    },
    "link-error": {
      "status": "Could not connect.",
      "primary": {
        "id": "connect",
        "label": "Try again",
        "quiet": false
      },
      "focus": "connect"
    },
    "request-list": {
      "account": true,
      "request": true,
      "wait": true,
      "requestPicker": true,
      "requestAction": {
        "id": "send-request",
        "label": "Send to {{wallet}}",
        "quiet": false
      },
      "reviewAction": {
        "id": "open-wallet",
        "label": "Review in Wallet",
        "quiet": true
      },
      "focus": "select-request",
      "queueCount": 3,
      "choices": 3
    },
    "request-selected-second": {
      "account": true,
      "request": true,
      "wait": true,
      "requestAction": {
        "id": "send-request",
        "label": "Send to {{wallet}}",
        "quiet": false
      },
      "reviewAction": {
        "id": "open-wallet",
        "label": "Review in Wallet",
        "quiet": true
      },
      "focus": "send-request",
      "queueCount": 3,
      "choices": 0
    },
    "request-next": {
      "status": "{{app}} message signed.",
      "account": true,
      "request": true,
      "outcome": true,
      "focusOutcome": true,
      "afterAnswer": true,
      "queueCount": 2,
      "choices": 1
    },
    "request-network-testnet": {
      "status": "{{wallet}} is using a Bitcoin test network.",
      "notice": "Select Bitcoin mainnet in {{wallet}}, then check network.",
      "account": true,
      "request": true,
      "outcome": true,
      "primary": {
        "id": "check-access",
        "label": "Check network",
        "quiet": false
      },
      "secondary": [
        {
          "id": "open-wallet",
          "label": "Open Wallet",
          "quiet": true
        }
      ],
      "focus": "check-access"
    },
    "request-network-fractal": {
      "status": "Home supports Bitcoin mainnet only.",
      "notice": "Select Bitcoin mainnet in {{wallet}}, then check network.",
      "account": true,
      "request": true,
      "outcome": true,
      "primary": {
        "id": "check-access",
        "label": "Check network",
        "quiet": false
      },
      "secondary": [
        {
          "id": "open-wallet",
          "label": "Open Wallet",
          "quiet": true
        }
      ],
      "focus": "check-access"
    },
    "request-network-unknown": {
      "status": "Home cannot identify this {{wallet}} network.",
      "notice": "Select Bitcoin mainnet in {{wallet}}, then check network.",
      "account": true,
      "request": true,
      "outcome": true,
      "primary": {
        "id": "check-access",
        "label": "Check network",
        "quiet": false
      },
      "secondary": [
        {
          "id": "open-wallet",
          "label": "Open Wallet",
          "quiet": true
        }
      ],
      "focus": "check-access"
    },
    "link-busy": {
      "status": "{{wallet}} has not answered.",
      "notice": "Close this window. The request may still be waiting in {{wallet}}. Reject or close it there. If {{wallet}} will not open, enable it in your browser, then use the browser’s Reload control.",
      "selectedAccount": true,
      "primary": {
        "id": "close-window",
        "label": "Close window",
        "quiet": false
      },
      "secondary": [
        {
          "id": "check-access",
          "label": "Check again",
          "quiet": true
        }
      ],
      "focus": "close-window"
    },
    "request-busy": {
      "status": "{{wallet}} has not answered.",
      "notice": "Close this window. The request may still be waiting in {{wallet}}. Reject or close it there. If {{wallet}} will not open, enable it in your browser, then use the browser’s Reload control.",
      "account": true,
      "request": true,
      "outcome": true,
      "primary": {
        "id": "close-window",
        "label": "Close window",
        "quiet": false
      },
      "secondary": [
        {
          "id": "check-access",
          "label": "Check again",
          "quiet": true
        }
      ],
      "focus": "close-window"
    },
    "extension-busy": {
      "status": "{{wallet}} has not answered.",
      "notice": "Close this window. The request may still be waiting in {{wallet}}. Reject or close it there. If {{wallet}} will not open, enable it in your browser, then use the browser’s Reload control.",
      "primary": {
        "id": "close-window",
        "label": "Close window",
        "quiet": false
      },
      "secondary": [
        {
          "id": "check-access",
          "label": "Check again",
          "quiet": true
        }
      ],
      "focus": "close-window"
    },
    "extension-late-ignored": {
      "status": "{{wallet}} answered after waiting ended.",
      "notice": "Try again to connect.",
      "primary": {
        "id": "connect",
        "label": "Try again",
        "quiet": false
      },
      "focus": "connect"
    },
    "focus": {
      "notice": "Choose an account in the extension, then sign a message.",
      "primary": {
        "id": "connect",
        "label": "Connect wallet",
        "quiet": false
      },
      "focus": "connect"
    }
  },
  "panel": {
    "empty": {},
    "empty-alt": {},
    "linked": {
      "account": true
    },
    "linked-unisat": {
      "account": true
    },
    "unconfigured": {
      "walletconnectAvailable": false
    },
    "linked-metamask": {
      "account": true
    },
    "linked-unnamed": {
      "account": true
    },
    "empty-return": {
      "returnFocus": true
    },
    "linked-return": {
      "account": true,
      "returnFocus": true
    },
    "linked-metamask-return": {
      "account": true,
      "returnFocus": true
    },
    "linked-unisat-return": {
      "account": true,
      "returnFocus": true
    }
  }
};
