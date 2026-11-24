// Fixed local copy and closed stage definitions. Design source: 58aaafe6db48f8a3600f1e3bb8312499405502fc.
// Effects stay with the mounting window.
const definitions = {
  "walletconnect": {
    "nothing-saved": {
      "notice": "Connect a wallet with a QR code, then sign a message.",
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
        "label": "Show request",
        "quiet": false
      },
      "secondary": [
        {
          "id": "cancel",
          "label": "Cancel",
          "quiet": true
        }
      ]
    },
    "internet-refused": {
      "status": "Internet access for WalletConnect is off.",
      "notice": "Connect a wallet to ask Home for internet access again.",
      "primary": {
        "id": "connect",
        "label": "Connect wallet",
        "quiet": false
      }
    },
    "internet-off": {
      "status": "Internet access for WalletConnect is off.",
      "notice": "Connect again to ask for internet access, then answer in Inbox.",
      "primary": {
        "id": "connect",
        "label": "Connect wallet",
        "quiet": false
      },
      "secondary": [
        {
          "id": "inbox",
          "label": "Open Inbox",
          "quiet": true
        }
      ]
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
      "status": "Internet access for WalletConnect is off.",
      "notice": "Finish removing the saved connection in Inbox.",
      "primary": {
        "id": "inbox",
        "label": "Open Inbox",
        "quiet": false
      }
    },
    "internet-ready": {
      "notice": "Connect a wallet with a QR code, then sign a message.",
      "primary": {
        "id": "connect",
        "label": "Connect wallet",
        "quiet": false
      }
    },
    "preparing-qr": {
      "status": "Getting your QR code…",
      "secondary": [
        {
          "id": "cancel",
          "label": "Cancel",
          "quiet": true
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
      "status": "Open {{wallet}} and sign the message to confirm this account is yours.",
      "notice": "",
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
      "status": "Your wallet declined to sign the message.",
      "notice": "Send another message to confirm this account.",
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
      "notice": "Check {{wallet}} before connecting again; the request may still be waiting there.",
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
        "id": "close-window",
        "label": "Close window",
        "quiet": false
      },
      "focus": "close-window",
      "focusOutcome": true,
      "secondary": [
        {
          "id": "add-account",
          "label": "Add address",
          "quiet": true
        }
      ]
    },
    "linked-multiple": {
      "status": "Connected.",
      "account": true,
      "primary": {
        "id": "close-window",
        "label": "Close window",
        "quiet": false
      },
      "focus": "close-window",
      "focusOutcome": true,
      "secondary": [
        {
          "id": "add-account",
          "label": "Add address",
          "quiet": true
        }
      ]
    },
    "request-waiting": {
      "account": true,
      "request": true,
      "wait": true,
      "requestAction": {
        "id": "send-request",
        "label": "Continue in {{wallet}}",
        "quiet": false
      },
      "secondary": [
        {
          "id": "close-window",
          "label": "Cancel",
          "quiet": true
        }
      ]
    },
    "request-multiple": {
      "account": true,
      "request": true,
      "wait": true,
      "requestAction": {
        "id": "send-request",
        "label": "Continue in {{wallet}}",
        "quiet": false
      },
      "queueCount": 3,
      "choices": 0,
      "secondary": [
        {
          "id": "close-window",
          "label": "Cancel",
          "quiet": true
        }
      ]
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
      "notice": "To try again, go back to {{app}} and start a new request.",
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
      "status": "Continue in {{wallet}}.",
      "notice": "",
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
      "status": "{{wallet}} declined this request.",
      "notice": "To try again, go back to {{app}} and start a new request.",
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
      "status": "The request may still be in progress in {{wallet}}.",
      "notice": "Check your wallet and Activity in Wallet before making another request.",
      "account": true,
      "request": true,
      "outcome": true,
      "primary": {
        "id": "open-wallet",
        "label": "Open Wallet",
        "quiet": false
      },
      "secondary": [
        {
          "id": "close-window",
          "label": "Close window",
          "quiet": true
        }
      ],
      "focus": "open-wallet"
    },
    "transaction-waiting": {
      "account": true,
      "request": true,
      "wait": true,
      "requestAction": {
        "id": "send-request",
        "label": "Continue in {{wallet}}",
        "quiet": false
      },
      "secondary": [
        {
          "id": "close-window",
          "label": "Cancel",
          "quiet": true
        }
      ]
    },
    "transaction-deadline": {
      "status": "There is too little time to send this transaction.",
      "notice": "Start a new transaction in {{app}}.",
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
      "status": "The transaction may still be waiting in {{wallet}} or may already have been sent.",
      "notice": "Home disconnects when you stop waiting; check your wallet and Activity in Wallet.",
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
      "notice": "To try again, go back to {{app}}. In Wallet, choose Dismiss to clear this request.",
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
      "status": "Home could not confirm the transaction result.",
      "notice": "Before you send again, check {{wallet}} and Activity in Wallet.",
      "account": true,
      "request": true,
      "outcome": true,
      "primary": {
        "id": "open-wallet-activity",
        "label": "Open Activity in Wallet",
        "quiet": false
      },
      "focus": "open-wallet-activity",
      "secondary": [
        {
          "id": "close-window",
          "label": "Close window",
          "quiet": true
        }
      ]
    },
    "transaction-cancelled": {
      "status": "The transaction may have been sent.",
      "notice": "Check {{wallet}} and Activity in Wallet before sending again.",
      "account": true,
      "request": true,
      "outcome": true,
      "primary": {
        "id": "open-wallet",
        "label": "Open Wallet",
        "quiet": false
      },
      "focus": "open-wallet",
      "secondary": [
        {
          "id": "close-window",
          "label": "Close window",
          "quiet": true
        }
      ]
    },
    "transaction-wallet-error": {
      "status": "Home could not confirm the transaction result.",
      "notice": "Before you send again, check {{wallet}} and Activity in Wallet.",
      "account": true,
      "request": true,
      "outcome": true,
      "primary": {
        "id": "open-wallet-activity",
        "label": "Open Activity in Wallet",
        "quiet": false
      },
      "focus": "open-wallet-activity",
      "secondary": [
        {
          "id": "close-window",
          "label": "Close window",
          "quiet": true
        }
      ]
    },
    "transaction-done": {
      "status": "Transaction sent.",
      "account": true,
      "request": true,
      "outcome": true,
      "primary": {
        "id": "open-wallet-activity",
        "label": "Open Activity in Wallet",
        "quiet": false
      },
      "focus": "open-wallet-activity"
    },
    "transaction-reopened": {
      "status": "Home could not confirm the transaction result.",
      "notice": "Before you send again, check {{wallet}} and Activity in Wallet.",
      "account": true,
      "request": true,
      "outcome": true,
      "primary": {
        "id": "open-wallet-activity",
        "label": "Open Activity in Wallet",
        "quiet": false
      },
      "focus": "open-wallet-activity",
      "secondary": [
        {
          "id": "close-window",
          "label": "Close window",
          "quiet": true
        }
      ]
    },
    "request-wallet-error": {
      "status": "{{wallet}} could not sign this message.",
      "notice": "To try again, go back to {{app}} and start a new request.",
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
      "notice": "To try again, go back to {{app}} and start a new request.",
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
      "status": "Home could not confirm the transaction result.",
      "notice": "Before you send again, check {{wallet}} and Activity in Wallet.",
      "account": true,
      "request": true,
      "outcome": true,
      "primary": {
        "id": "open-wallet-activity",
        "label": "Open Activity in Wallet",
        "quiet": false
      },
      "focus": "open-wallet-activity",
      "secondary": [
        {
          "id": "close-window",
          "label": "Close window",
          "quiet": true
        }
      ]
    },
    "request-internet-off": {
      "status": "Internet access for WalletConnect is off.",
      "notice": "Choose Back to connection and connect again to ask for internet access. Allow it in Inbox, then return to this request and send it.",
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
      "notice": "Allow internet access in Inbox to continue with this request.",
      "account": true,
      "request": true,
      "primary": {
        "id": "inbox",
        "label": "Show request",
        "quiet": false
      },
      "secondary": [
        {
          "id": "cancel",
          "label": "Cancel",
          "quiet": true
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
      "primary": {
        "id": "connect",
        "label": "Connect wallet",
        "quiet": false
      },
      "focus": "connect"
    },
    "window-expired": {
      "status": "This window is no longer active.",
      "notice": "{{closeThen}} choose WalletConnect in Wallet.",
      "primary": {
        "id": "close-window",
        "label": "Close window",
        "quiet": false
      },
      "focus": "close-window"
    },
    "guest-access": {
      "status": "You cannot turn on internet access for WalletConnect.",
      "notice": "Ask an admin of this Home to open WalletConnect, choose Connect wallet, then allow internet access in Inbox.",
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
      "status": "Message signed.",
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
      "notice": "Activity in Wallet has the transaction result.",
      "account": true,
      "request": true,
      "outcome": true,
      "primary": {
        "id": "open-wallet-activity",
        "label": "Open Activity in Wallet",
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
      "notice": "{{close}} The request may still be waiting in {{wallet}}. Reject or close it there.",
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
      "notice": "Connect a wallet with a QR code, then sign a message.",
      "primary": {
        "id": "connect",
        "label": "Connect wallet",
        "quiet": false
      },
      "focus": "connect"
    },
    "request-unavailable": {
      "status": "This request is unavailable here. To try again, go back to {{app}} and start a new request.",
      "request": true,
      "account": true,
      "focusOutcome": true,
      "primary": {
        "id": "open-request-app",
        "label": "Open {{app}}",
        "quiet": false
      }
    },
    "wallet-loading": {
      "status": "Loading your wallet connections.",
      "primary": {
        "id": "close-window",
        "label": "Close window",
        "quiet": true
      }
    },
    "wallet-unavailable": {
      "status": "Home could not load your wallet connections.",
      "primary": {
        "id": "refresh-status",
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
      "focus": "refresh-status"
    },
    "home-wallet-required": {
      "status": "Create or import an account in Wallet to continue.",
      "primary": {
        "id": "open-wallet",
        "label": "Open Wallet",
        "quiet": false
      },
      "secondary": [
        {
          "id": "close-window",
          "label": "Close window",
          "quiet": true
        }
      ]
    },
    "provider-unavailable": {
      "status": "The connection to your wallet is unavailable.",
      "notice": "Open {{wallet}} to check its connection.",
      "primary": {
        "id": "refresh-status",
        "label": "Check again",
        "quiet": false
      },
      "secondary": [
        {
          "id": "close-window",
          "label": "Close window",
          "quiet": true
        }
      ]
    },
    "account-changed": {
      "requiresSafeRetry": true,
      "status": "Your wallet is using a different account.",
      "notice": "Confirm this account is yours before you use it in Home.",
      "primary": {
        "id": "send-message",
        "label": "Send message",
        "quiet": false
      },
      "secondary": [
        {
          "id": "start-over",
          "label": "Get new QR code",
          "quiet": false
        },
        {
          "id": "close-window",
          "label": "Close window",
          "quiet": true
        }
      ],
      "account": true
    },
    "account-unavailable-unknown": {
      "requiresSafeRetry": true,
      "status": "Your wallet is not showing an account.",
      "notice": "Choose an account in your wallet, then return here.",
      "primary": {
        "id": "start-over",
        "label": "Get new QR code",
        "quiet": false
      },
      "secondary": [
        {
          "id": "close-window",
          "label": "Close window",
          "quiet": true
        }
      ],
      "focus": "start-over"
    },
    "network-unsupported": {
      "status": "This network is not supported here.",
      "notice": "Choose Ethereum, Elastos Smart Chain, Base or Sepolia test network in {{wallet}}. {{close}}",
      "primary": {
        "id": "close-window",
        "label": "Close window",
        "quiet": true
      }
    },
    "preparing-request": {
      "status": "Preparing request.",
      "primary": {
        "id": "cancel",
        "label": "Cancel",
        "quiet": false
      }
    },
    "preparing-connection": {
      "status": "Preparing connection.",
      "primary": {
        "id": "cancel",
        "label": "Cancel",
        "quiet": false
      }
    },
    "add-account": {
      "status": "Add an address.",
      "notice": "Choose another account in {{wallet}}, then get a new QR code and scan it. You can also scan with another wallet. The new code replaces this connection. Your addresses stay in Wallet.",
      "account": true,
      "primary": {
        "id": "start-over",
        "label": "Get new QR code",
        "quiet": false
      },
      "secondary": [
        {
          "id": "back-to-connection",
          "label": "Back to connection",
          "quiet": true
        }
      ],
      "focus": "start-over"
    },
    "account-already-linked": {
      "status": "This address is already in Wallet.",
      "notice": "Choose another account in {{wallet}}, then get a new QR code and scan it. Your addresses stay in Wallet.",
      "account": true,
      "primary": {
        "id": "start-over",
        "label": "Try again",
        "quiet": false
      },
      "secondary": [
        {
          "id": "back-to-connection",
          "label": "Back to connection",
          "quiet": true
        }
      ],
      "focus": "start-over"
    },
    "add-qr-cancelled": {
      "status": "Connection cancelled.",
      "primary": {
        "id": "start-over",
        "label": "Get new QR code",
        "quiet": false
      },
      "focus": "start-over",
      "secondary": [],
      "notice": "Get a new QR code to connect again. Your addresses stay in Wallet."
    },
    "add-qr-expired": {
      "status": "QR code expired.",
      "primary": {
        "id": "start-over",
        "label": "Get new QR code",
        "quiet": false
      },
      "focus": "start-over",
      "secondary": [],
      "notice": "Get a new QR code to connect again. Your addresses stay in Wallet."
    },
    "add-connection-declined": {
      "status": "Connection declined.",
      "primary": {
        "id": "start-over",
        "label": "Get new QR code",
        "quiet": false
      },
      "focus": "start-over",
      "secondary": [],
      "notice": "Get a new QR code to connect again. Your addresses stay in Wallet."
    },
    "add-link-declined": {
      "status": "Your wallet declined to sign the message.",
      "notice": "Send a new message to confirm this account, or get a new QR code for another account. Your addresses stay in Wallet.",
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
    "add-link-timeout": {
      "status": "Time to connect ran out.",
      "notice": "The message may still be waiting in {{wallet}}. Reject or close it there, then get a new QR code to connect again. Your addresses stay in Wallet.",
      "selectedAccount": true,
      "primary": {
        "id": "start-over",
        "label": "Get new QR code",
        "quiet": false
      },
      "secondary": [],
      "focus": "start-over"
    },
    "add-link-error": {
      "status": "Could not connect.",
      "primary": {
        "id": "start-over",
        "label": "Get new QR code",
        "quiet": false
      },
      "focus": "start-over",
      "secondary": [],
      "notice": "Get a new QR code to connect again. Your addresses stay in Wallet."
    },
    "add-link-cancelled": {
      "status": "Home disconnected from {{wallet}}.",
      "notice": "The message may still be waiting there; get a new QR code to connect again.",
      "selectedAccount": true,
      "primary": {
        "id": "start-over",
        "label": "Get new QR code",
        "quiet": false
      },
      "secondary": [],
      "focus": "start-over"
    },
    "checking-response": {
      "status": "Checking your wallet answer.",
      "notice": "",
      "optionalRequest": true,
      "account": true,
      "dispatched": true,
      "primary": {
        "id": "stop-waiting",
        "label": "Stop waiting",
        "quiet": true
      },
      "secondary": [],
      "focus": "stop-waiting"
    },
    "home-read-unavailable": {
      "status": "Home could not load the wallet details.",
      "notice": "Check again to load them.",
      "primary": {
        "id": "refresh-status",
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
      "focus": "refresh-status"
    },
    "disconnect-error": {
      "status": "Home could not finish disconnecting this wallet.",
      "notice": "Try disconnecting again. Closing this window does not finish disconnecting.",
      "primary": {
        "id": "disconnect",
        "label": "Disconnect",
        "quiet": false
      },
      "secondary": [
        {
          "id": "close-window",
          "label": "Close window",
          "quiet": true
        }
      ],
      "focus": "disconnect"
    },
    "request-rejected": {
      "status": "This request was rejected.",
      "notice": "To try again, go back to {{app}} and start a new request.",
      "request": true,
      "account": true,
      "afterAnswer": true,
      "focusOutcome": true,
      "primary": {
        "id": "open-request-app",
        "label": "Open {{app}}",
        "quiet": false
      },
      "secondary": [
        {
          "id": "close-window",
          "label": "Close window",
          "quiet": true
        }
      ]
    },
    "request-dismissed": {
      "status": "This request was dismissed.",
      "notice": "The request may still be in progress in {{wallet}}. Check your wallet and Activity in Wallet before making another request.",
      "request": true,
      "account": true,
      "afterAnswer": true,
      "focusOutcome": true,
      "primary": {
        "id": "open-wallet-activity",
        "label": "Open Activity in Wallet",
        "quiet": false
      },
      "secondary": [
        {
          "id": "close-window",
          "label": "Close window",
          "quiet": true
        }
      ]
    }
  },
  "metamask": {
    "ready": {
      "notice": "Choose an account in {{wallet}}, then sign the message.",
      "primary": {
        "id": "connect",
        "label": "Connect wallet",
        "quiet": false
      }
    },
    "ready-multiple": {
      "notice": "Connect will use {{wallet}}. {{alternative}} is also available.",
      "paymentSafeNotice": "Connect will use {{wallet}}.",
      "primary": {
        "id": "connect",
        "label": "Connect wallet",
        "quiet": false
      }
    },
    "extension-choose-wallet": {
      "status": "Home could not find MetaMask in this browser.",
      "notice": "Choose a wallet.",
      "secondary": [
        {
          "id": "refresh-status",
          "label": "Check again",
          "quiet": true
        },
        {
          "id": "close-window",
          "label": "Close window",
          "quiet": true
        }
      ],
      "walletPicker": true,
      "account": true,
      "focus": "select-wallet"
    },
    "extension-missing": {
      "status": "Home could not find a wallet in this browser.",
      "notice": "Open Home in a browser where your wallet is available, then choose MetaMask in Wallet.",
      "paymentSafeNotice": "Open Home in a browser where your wallet is available, then choose MetaMask in Wallet.",
      "primary": {
        "id": "refresh-status",
        "label": "Check again",
        "quiet": false
      },
      "focus": "refresh-status",
      "account": true,
      "secondary": [
        {
          "id": "close-window",
          "label": "Close window",
          "quiet": true
        }
      ]
    },
    "extensions-unavailable": {
      "status": "Home could not find a wallet in this browser.",
      "notice": "Open Home in a browser where your wallet is available, then choose MetaMask in Wallet.",
      "paymentSafeNotice": "Open Home in a browser where your wallet is available, then choose MetaMask in Wallet.",
      "primary": {
        "id": "refresh-status",
        "label": "Check again",
        "quiet": false
      },
      "account": true,
      "secondary": [
        {
          "id": "close-window",
          "label": "Close window",
          "quiet": true
        }
      ],
      "focus": "refresh-status"
    },
    "extension-wait": {
      "status": "Waiting for {{wallet}}.",
      "notice": "",
      "wait": true,
      "dispatched": true,
      "secondary": [
        {
          "id": "stop-waiting",
          "label": "Cancel",
          "quiet": true
        }
      ]
    },
    "extension-timeout": {
      "status": "Time to connect ran out.",
      "notice": "The request may still be waiting in {{wallet}}. Reject or close it there, then check again. If {{wallet}} will not open, enable it in your browser, then use the browser's Reload control.",
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
      "notice": "Check {{wallet}} before connecting again; the request may still be waiting there.",
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
      "status": "Waiting for {{wallet}}.",
      "notice": "",
      "selectedAccount": true,
      "wait": true,
      "dispatched": true,
      "secondary": [
        {
          "id": "stop-waiting",
          "label": "Cancel",
          "quiet": true
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
      "notice": "The request may still be waiting in {{wallet}}. Reject or close it there, then check again. If {{wallet}} will not open, enable it in your browser, then use the browser's Reload control.",
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
      "notice": "Check {{wallet}} before connecting again; the request may still be waiting there.",
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
      "status": "Home cannot confirm access to this account in {{wallet}}.",
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
      "notice": "The request may still be waiting in {{wallet}}. Reject or close it there, then check again. If {{wallet}} will not open, enable it in your browser, then use the browser's Reload control.",
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
      "notice": "To try again, go back to {{app}} and start a new request.",
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
      "notice": "Review Activity in Wallet before starting a new request.",
      "account": true,
      "request": true,
      "outcome": true,
      "requiredAccount": true,
      "primary": {
        "id": "open-wallet-activity",
        "label": "Open Activity in Wallet",
        "quiet": false
      },
      "focus": "open-wallet-activity"
    },
    "request-network-declined": {
      "status": "Home could not confirm the requested network in {{wallet}}.",
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
      "status": "Address saved in Wallet.",
      "account": true,
      "disconnect": false,
      "primary": {
        "id": "close-window",
        "label": "Close window",
        "quiet": false
      },
      "focus": "close-window",
      "notice": "To stop sharing, remove this Home's connection in {{wallet}}. Your address stays in Wallet."
    },
    "request-waiting": {
      "account": true,
      "request": true,
      "wait": true,
      "requestAction": {
        "id": "send-request",
        "label": "Continue in {{wallet}}",
        "quiet": false
      },
      "secondary": [
        {
          "id": "close-window",
          "label": "Cancel",
          "quiet": true
        }
      ]
    },
    "request-multiple": {
      "account": true,
      "request": true,
      "wait": true,
      "requestAction": {
        "id": "send-request",
        "label": "Continue in {{wallet}}",
        "quiet": false
      },
      "queueCount": 3,
      "choices": 0,
      "secondary": [
        {
          "id": "close-window",
          "label": "Cancel",
          "quiet": true
        }
      ]
    },
    "request-unsendable": {
      "status": "Home cannot confirm access to the account this request needs in your wallet.",
      "notice": "",
      "account": true,
      "request": true,
      "outcome": true,
      "requiredAccount": true,
      "primary": {
        "id": "refresh-status",
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
      "focus": "refresh-status"
    },
    "request-typed-data": {
      "account": true,
      "request": true,
      "wait": true,
      "requestAction": {
        "id": "send-request",
        "label": "Continue in {{wallet}}",
        "quiet": false
      },
      "secondary": [
        {
          "id": "close-window",
          "label": "Cancel",
          "quiet": true
        }
      ]
    },
    "request-expired": {
      "status": "This request expired.",
      "notice": "To try again, go back to {{app}} and start a new request.",
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
      "notice": "Open {{wallet}} from your browser's extensions menu to check the request.",
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
      "status": "{{wallet}} declined this request.",
      "notice": "To try again, go back to {{app}} and start a new request.",
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
      "notice": "The request may still be waiting in {{wallet}}. Reject or close it there, then check again. If {{wallet}} will not open, enable it in your browser, then use the browser's Reload control.",
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
      "status": "The request may still be in progress in {{wallet}}.",
      "notice": "Check your wallet and Activity in Wallet before making another request.",
      "account": true,
      "request": true,
      "outcome": true,
      "primary": {
        "id": "open-wallet",
        "label": "Open Wallet",
        "quiet": false
      },
      "secondary": [
        {
          "id": "close-window",
          "label": "Close window",
          "quiet": true
        }
      ],
      "focus": "open-wallet"
    },
    "transaction-waiting": {
      "account": true,
      "request": true,
      "wait": true,
      "requestAction": {
        "id": "send-request",
        "label": "Continue in {{wallet}}",
        "quiet": false
      },
      "secondary": [
        {
          "id": "close-window",
          "label": "Cancel",
          "quiet": true
        }
      ]
    },
    "transaction-extension": {
      "status": "Waiting for {{wallet}}.",
      "notice": "Check {{wallet}}; your wallet may still send the transaction after you stop waiting here.",
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
      "notice": "To try again, go back to {{app}} and start a new request.",
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
      "status": "Home does not know if the transaction was sent.",
      "notice": "Before you send again, check {{wallet}}, then open Wallet from Home and check Activity. Closing this window does not cancel the request in {{wallet}}.",
      "account": true,
      "request": true,
      "outcome": true,
      "primary": {
        "id": "open-wallet-activity",
        "label": "Open Activity in Wallet",
        "quiet": false
      },
      "focus": "open-wallet-activity",
      "secondary": [
        {
          "id": "close-window",
          "label": "Close window",
          "quiet": true
        }
      ]
    },
    "transaction-cancelled": {
      "status": "The transaction may have been sent.",
      "notice": "Check {{wallet}} and Activity in Wallet before sending again.",
      "account": true,
      "request": true,
      "outcome": true,
      "primary": {
        "id": "open-wallet",
        "label": "Open Wallet",
        "quiet": false
      },
      "focus": "open-wallet",
      "secondary": [
        {
          "id": "close-window",
          "label": "Close window",
          "quiet": true
        }
      ]
    },
    "transaction-wallet-error": {
      "status": "Home does not know if the transaction was sent.",
      "notice": "Before you send again, check {{wallet}}, then open Wallet from Home and check Activity. Closing this window does not cancel the request in {{wallet}}.",
      "account": true,
      "request": true,
      "outcome": true,
      "primary": {
        "id": "open-wallet-activity",
        "label": "Open Activity in Wallet",
        "quiet": false
      },
      "focus": "open-wallet-activity",
      "secondary": [
        {
          "id": "close-window",
          "label": "Close window",
          "quiet": true
        }
      ]
    },
    "transaction-done": {
      "status": "Transaction sent.",
      "account": true,
      "request": true,
      "outcome": true,
      "primary": {
        "id": "open-wallet-activity",
        "label": "Open Activity in Wallet",
        "quiet": false
      },
      "focus": "open-wallet-activity"
    },
    "request-wallet-error": {
      "status": "{{wallet}} could not sign this message.",
      "notice": "To try again, go back to {{app}} and start a new request.",
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
      "notice": "To try again, go back to {{app}} and start a new request.",
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
      "notice": "{{closeThen}} open Wallet from Home and choose MetaMask.",
      "primary": {
        "id": "close-window",
        "label": "Close window",
        "quiet": false
      },
      "focus": "close-window"
    },
    "link-error": {
      "status": "Home could not confirm the connection.",
      "primary": {
        "id": "refresh-status",
        "label": "Check again",
        "quiet": false
      },
      "focus": "refresh-status",
      "secondary": [
        {
          "id": "close-window",
          "label": "Close window",
          "quiet": true
        }
      ]
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
      "status": "Message signed.",
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
      "notice": "Activity in Wallet has the transaction result.",
      "account": true,
      "request": true,
      "outcome": true,
      "primary": {
        "id": "open-wallet-activity",
        "label": "Open Activity in Wallet",
        "quiet": false
      },
      "focus": "open-wallet-activity"
    },
    "other-ethereum-wallet": {
      "status": "Home could not find a wallet in this browser.",
      "notice": "Open Home in a browser where your wallet is available, then choose MetaMask in Wallet.",
      "paymentSafeNotice": "Open Home in a browser where your wallet is available, then choose MetaMask in Wallet.",
      "primary": {
        "id": "refresh-status",
        "label": "Check again",
        "quiet": false
      },
      "focus": "refresh-status",
      "account": true,
      "secondary": [
        {
          "id": "close-window",
          "label": "Close window",
          "quiet": true
        }
      ]
    },
    "access-wrong-account": {
      "status": "{{wallet}} returned a different account.",
      "notice": "Choose Connect wallet, then select the required account in {{wallet}}'s Manage connected accounts and Save.",
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
      "notice": "{{close}} The request may still be waiting in {{wallet}}. Reject or close it there. If {{wallet}} will not open, enable it in your browser, then use the browser's Reload control.",
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
      "notice": "{{close}} The request may still be waiting in {{wallet}}. Reject or close it there. If {{wallet}} will not open, enable it in your browser, then use the browser's Reload control.",
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
      "notice": "{{close}} The request may still be waiting in {{wallet}}. Reject or close it there. If {{wallet}} will not open, enable it in your browser, then use the browser's Reload control.",
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
      "notice": "Choose an account in {{wallet}}, then sign the message.",
      "primary": {
        "id": "connect",
        "label": "Connect wallet",
        "quiet": false
      },
      "focus": "connect"
    },
    "request-unavailable": {
      "status": "Home cannot use this request. Go back to {{app}} and start a new request.",
      "request": true,
      "account": true,
      "focusOutcome": true,
      "primary": {
        "id": "open-request-app",
        "label": "Open {{app}}",
        "quiet": false
      }
    },
    "wallet-loading": {
      "status": "Loading your wallet connections.",
      "primary": {
        "id": "close-window",
        "label": "Close window",
        "quiet": true
      }
    },
    "wallet-unavailable": {
      "status": "Home could not load your wallet connections.",
      "primary": {
        "id": "refresh-status",
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
      "focus": "refresh-status"
    },
    "home-wallet-required": {
      "status": "Create or import an account in Wallet to continue.",
      "primary": {
        "id": "open-wallet",
        "label": "Open Wallet",
        "quiet": false
      },
      "secondary": [
        {
          "id": "close-window",
          "label": "Close window",
          "quiet": true
        }
      ]
    },
    "provider-unavailable": {
      "status": "The connection to your wallet is unavailable.",
      "notice": "Open {{wallet}} to check its connection.",
      "primary": {
        "id": "refresh-status",
        "label": "Check again",
        "quiet": false
      },
      "secondary": [
        {
          "id": "close-window",
          "label": "Close window",
          "quiet": true
        }
      ]
    },
    "account-changed": {
      "requiresSafeRetry": true,
      "status": "Your wallet is using a different account.",
      "notice": "Confirm this account is yours before you use it in Home.",
      "primary": {
        "id": "connect",
        "label": "Connect",
        "quiet": false
      },
      "secondary": [
        {
          "id": "close-window",
          "label": "Close window",
          "quiet": true
        }
      ],
      "account": true
    },
    "account-unavailable-unknown": {
      "requiresSafeRetry": true,
      "status": "Your wallet is not showing an account.",
      "notice": "Open {{wallet}} and choose an account, then connect again.",
      "primary": {
        "id": "connect",
        "label": "Connect",
        "quiet": false
      },
      "secondary": [
        {
          "id": "close-window",
          "label": "Close window",
          "quiet": true
        }
      ]
    },
    "network-unsupported": {
      "status": "This network is not supported here.",
      "notice": "Choose a supported network in {{wallet}}.",
      "primary": {
        "id": "close-window",
        "label": "Close window",
        "quiet": true
      }
    },
    "preparing-request": {
      "status": "Preparing request.",
      "primary": {
        "id": "cancel",
        "label": "Cancel",
        "quiet": false
      }
    },
    "preparing-connection": {
      "status": "Preparing connection.",
      "primary": {
        "id": "cancel",
        "label": "Cancel",
        "quiet": false
      }
    },
    "request-rejected": {
      "status": "This request was rejected.",
      "notice": "To try again, go back to {{app}} and start a new request.",
      "request": true,
      "account": true,
      "afterAnswer": true,
      "focusOutcome": true,
      "primary": {
        "id": "open-request-app",
        "label": "Open {{app}}",
        "quiet": false
      },
      "secondary": [
        {
          "id": "close-window",
          "label": "Close window",
          "quiet": true
        }
      ]
    },
    "request-dismissed": {
      "status": "This request was dismissed.",
      "notice": "The request may still be in progress in {{wallet}}. Check your wallet and Activity in Wallet before making another request.",
      "request": true,
      "account": true,
      "afterAnswer": true,
      "focusOutcome": true,
      "primary": {
        "id": "open-wallet-activity",
        "label": "Open Activity in Wallet",
        "quiet": false
      },
      "secondary": [
        {
          "id": "close-window",
          "label": "Close window",
          "quiet": true
        }
      ]
    }
  },
  "unisat": {
    "ready": {
      "notice": "Choose an account in UniSat, then sign a message.",
      "primary": {
        "id": "connect",
        "label": "Connect wallet",
        "quiet": false
      }
    },
    "extension-missing": {
      "status": "Home could not find UniSat in this browser.",
      "notice": "{{close}} Open Home in a browser where UniSat is available, then open this connection from Wallet.",
      "primary": {
        "id": "close-window",
        "label": "Close window",
        "quiet": false
      },
      "focus": "close-window",
      "paymentSafeNotice": "{{close}} Open Home in a browser where UniSat is available, then open this connection from Wallet."
    },
    "extensions-unavailable": {
      "status": "Home could not find UniSat in this browser.",
      "notice": "{{close}} Open Home in a browser where UniSat is available, then open this connection from Wallet.",
      "primary": {
        "id": "close-window",
        "label": "Close window",
        "quiet": false
      },
      "paymentSafeNotice": "{{close}} Open Home in a browser where UniSat is available, then open this connection from Wallet."
    },
    "extension-wait": {
      "status": "Waiting for {{wallet}}.",
      "notice": "",
      "wait": true,
      "dispatched": true,
      "secondary": [
        {
          "id": "stop-waiting",
          "label": "Cancel",
          "quiet": true
        }
      ]
    },
    "extension-timeout": {
      "status": "Time to connect ran out.",
      "notice": "The request may still be waiting in {{wallet}}. Reject or close it there, then check again. If {{wallet}} will not open, enable it in your browser, then use the browser's Reload control.",
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
      "notice": "Check {{wallet}} before connecting again; the request may still be waiting there.",
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
      "status": "Waiting for {{wallet}}.",
      "notice": "",
      "selectedAccount": true,
      "wait": true,
      "dispatched": true,
      "secondary": [
        {
          "id": "stop-waiting",
          "label": "Cancel",
          "quiet": true
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
      "notice": "The request may still be waiting in {{wallet}}. Reject or close it there, then check again. If {{wallet}} will not open, enable it in your browser, then use the browser's Reload control.",
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
      "notice": "Check {{wallet}} before connecting again; the request may still be waiting there.",
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
      "status": "Home cannot use this UniSat account right now.",
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
        "id": "close-window",
        "label": "Close window",
        "quiet": false
      },
      "focus": "close-window"
    },
    "request-waiting": {
      "account": true,
      "request": true,
      "wait": true,
      "requestAction": {
        "id": "send-request",
        "label": "Continue in {{wallet}}",
        "quiet": false
      },
      "secondary": [
        {
          "id": "close-window",
          "label": "Cancel",
          "quiet": true
        }
      ]
    },
    "request-multiple": {
      "account": true,
      "request": true,
      "wait": true,
      "requestAction": {
        "id": "send-request",
        "label": "Continue in {{wallet}}",
        "quiet": false
      },
      "queueCount": 3,
      "choices": 0,
      "secondary": [
        {
          "id": "close-window",
          "label": "Cancel",
          "quiet": true
        }
      ]
    },
    "request-unsendable": {
      "status": "Home cannot use the UniSat account this request needs.",
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
      "notice": "To try again, go back to {{app}} and start a new request.",
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
      "notice": "Open UniSat from your browser's extensions menu to check the request.",
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
      "status": "{{wallet}} declined this request.",
      "notice": "To try again, go back to {{app}} and start a new request.",
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
      "notice": "The request may still be waiting in {{wallet}}. Reject or close it there, then check again. If {{wallet}} will not open, enable it in your browser, then use the browser's Reload control.",
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
      "status": "The request may still be in progress in {{wallet}}.",
      "notice": "Check your wallet and Activity in Wallet before making another request.",
      "account": true,
      "request": true,
      "outcome": true,
      "primary": {
        "id": "open-wallet",
        "label": "Open Wallet",
        "quiet": false
      },
      "secondary": [
        {
          "id": "close-window",
          "label": "Close window",
          "quiet": true
        }
      ],
      "focus": "open-wallet"
    },
    "request-wallet-error": {
      "status": "{{wallet}} could not sign this message.",
      "notice": "To try again, go back to {{app}} and start a new request.",
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
      "notice": "To try again, go back to {{app}} and start a new request.",
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
      "notice": "{{closeThen}} choose {{wallet}} in Wallet.",
      "primary": {
        "id": "close-window",
        "label": "Close window",
        "quiet": false
      },
      "focus": "close-window"
    },
    "wallet-locked": {
      "status": "UniSat is locked.",
      "notice": "Unlock UniSat, then select Try again.",
      "primary": {"id":"connect","label":"Try again","quiet":false},
      "secondary": [{"id":"close-window","label":"Cancel","quiet":true}],
      "focus":"connect"
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
      "status": "Message signed.",
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
      "notice": "{{close}} The request may still be waiting in {{wallet}}. Reject or close it there. If {{wallet}} will not open, enable it in your browser, then use the browser's Reload control.",
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
      "notice": "{{close}} The request may still be waiting in {{wallet}}. Reject or close it there. If {{wallet}} will not open, enable it in your browser, then use the browser's Reload control.",
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
      "notice": "{{close}} The request may still be waiting in {{wallet}}. Reject or close it there. If {{wallet}} will not open, enable it in your browser, then use the browser's Reload control.",
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
      "notice": "Choose an account in UniSat, then sign a message.",
      "primary": {
        "id": "connect",
        "label": "Connect wallet",
        "quiet": false
      },
      "focus": "connect"
    },
    "request-unavailable": {
      "status": "This request is unavailable. Go back to the app and start a new request.",
      "request": true,
      "account": true,
      "focusOutcome": true,
      "primary": {
        "id": "open-request-app",
        "label": "Open {{app}}",
        "quiet": false
      }
    },
    "wallet-loading": {
      "status": "Loading your wallet connections.",
      "primary": {
        "id": "close-window",
        "label": "Close window",
        "quiet": true
      }
    },
    "wallet-unavailable": {
      "status": "Home could not load your wallet connections.",
      "primary": {
        "id": "refresh-status",
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
      "focus": "refresh-status"
    },
    "home-wallet-required": {
      "status": "Create or import an account in Wallet to continue.",
      "primary": {
        "id": "open-wallet",
        "label": "Open Wallet",
        "quiet": false
      },
      "secondary": [
        {
          "id": "close-window",
          "label": "Close window",
          "quiet": true
        }
      ]
    },
    "provider-unavailable": {
      "status": "The connection to your wallet is unavailable.",
      "notice": "Open {{wallet}} to check its connection.",
      "primary": {
        "id": "refresh-status",
        "label": "Check again",
        "quiet": false
      },
      "secondary": [
        {
          "id": "close-window",
          "label": "Close window",
          "quiet": true
        }
      ]
    },
    "account-changed": {
      "requiresSafeRetry": true,
      "status": "Your wallet is using a different account.",
      "notice": "Confirm this account is yours before you use it in Home.",
      "primary": {
        "id": "connect",
        "label": "Connect",
        "quiet": false
      },
      "secondary": [
        {
          "id": "close-window",
          "label": "Close window",
          "quiet": true
        }
      ],
      "account": true
    },
    "account-unavailable-unknown": {
      "requiresSafeRetry": true,
      "status": "Your wallet is not showing an account.",
      "notice": "Open {{wallet}} and choose an account, then connect again.",
      "primary": {
        "id": "connect",
        "label": "Connect",
        "quiet": false
      },
      "secondary": [
        {
          "id": "close-window",
          "label": "Close window",
          "quiet": true
        }
      ]
    },
    "network-unsupported": {
      "status": "This network is not supported here.",
      "notice": "Choose a supported network in {{wallet}}.",
      "primary": {
        "id": "close-window",
        "label": "Close window",
        "quiet": true
      }
    },
    "preparing-request": {
      "status": "Preparing request.",
      "primary": {
        "id": "cancel",
        "label": "Cancel",
        "quiet": false
      }
    },
    "preparing-connection": {
      "status": "Preparing connection.",
      "primary": {
        "id": "cancel",
        "label": "Cancel",
        "quiet": false
      }
    },
    "request-rejected": {
      "status": "This request was rejected.",
      "notice": "To try again, go back to {{app}} and start a new request.",
      "request": true,
      "account": true,
      "afterAnswer": true,
      "focusOutcome": true,
      "primary": {
        "id": "open-request-app",
        "label": "Open {{app}}",
        "quiet": false
      },
      "secondary": [
        {
          "id": "close-window",
          "label": "Close window",
          "quiet": true
        }
      ]
    },
    "request-dismissed": {
      "status": "This request was dismissed.",
      "notice": "A request may still be waiting in UniSat. Before trying again, check UniSat and Activity in Wallet. Open Wallet from Home to review this request.",
      "request": true,
      "account": true,
      "afterAnswer": true,
      "focusOutcome": true,
      "primary": {
        "id": "open-wallet-activity",
        "label": "Open Activity in Wallet",
        "quiet": false
      },
      "secondary": [
        {
          "id": "close-window",
          "label": "Close window",
          "quiet": true
        }
      ]
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
const freeze = value => { if(value && typeof value==='object'){Object.values(value).forEach(freeze);Object.freeze(value);}return value;};
export const screens = freeze(definitions);
