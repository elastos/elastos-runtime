use super::wallet_unicode::{LETTERS_DIGITS, MARKS};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalletDisplayIdentity {
    pub provider_id: Option<String>,
    pub wallet_display_name: Option<String>,
    pub wallet_mark: &'static str,
}

/// Validate optional wire metadata independently of proof verification.
pub fn validate_wallet_display_fields(
    connector: &str,
    provider_id: Option<&str>,
    peer_name: Option<&str>,
) -> Result<(), &'static str> {
    if peer_name.is_some_and(|s| s.len() > 1024) {
        return Err("invalid_request");
    }
    if provider_id.is_some() && peer_name.is_some()
        || peer_name.is_some() && connector != "wallet-walletconnect"
        || provider_id.is_some_and(|id| {
            !matches!(
                (connector, id),
                ("wallet-metamask", "io.metamask" | "com.brave.wallet")
                    | ("wallet-unisat", "unisat")
            )
        })
    {
        return Err("denied");
    }
    Ok(())
}

/// The single storage/projection derivation for untrusted wallet display data.
pub fn wallet_display_identity(
    connector: &str,
    provider_id: Option<&str>,
    peer_name: Option<&str>,
) -> WalletDisplayIdentity {
    let mut result = WalletDisplayIdentity {
        provider_id: None,
        wallet_display_name: None,
        wallet_mark: "wallet",
    };
    if validate_wallet_display_fields(connector, provider_id, peer_name).is_err() {
        return result;
    }
    if let Some(id) = provider_id {
        let (name, mark) = match id {
            "io.metamask" => ("MetaMask", "metamask"),
            "com.brave.wallet" => ("Brave Wallet", "wallet"),
            "unisat" => ("UniSat", "unisat"),
            _ => return result,
        };
        result.provider_id = Some(id.into());
        result.wallet_display_name = Some(name.into());
        result.wallet_mark = mark;
    } else if connector == "wallet-walletconnect" {
        result.wallet_display_name = peer_name.and_then(clean_peer_name);
    }
    result
}

fn in_ranges(c: char, ranges: &[(u32, u32)]) -> bool {
    let cp = u32::from(c);
    let index = ranges.partition_point(|(_, end)| *end < cp);
    ranges.get(index).is_some_and(|(start, _)| *start <= cp)
}

fn whitespace(c: char) -> bool {
    matches!(u32::from(c), 0x9..=0xD | 0x20 | 0x85 | 0xA0 | 0x1680 | 0x2000..=0x200A | 0x2028..=0x2029 | 0x202F | 0x205F | 0x3000)
}

fn removed(c: char) -> bool {
    matches!(u32::from(c), 0x0..=0x1F | 0x7F..=0x9F | 0xAD | 0x600..=0x605 | 0x61C | 0x6DD | 0x70F | 0x890..=0x891 | 0x8E2 | 0x180E
        | 0x200B..=0x200F | 0x202A..=0x202E | 0x2060..=0x2064 | 0x2066..=0x206F | 0xFEFF | 0xFFF9..=0xFFFB
        | 0x110BD | 0x110CD | 0x13430..=0x1343F | 0x1BCA0..=0x1BCA3 | 0x1D173..=0x1D17A | 0xE0001 | 0xE0020..=0xE007F
        | 0x34F | 0x115F..=0x1160 | 0x17B4..=0x17B5 | 0x2800 | 0x3164 | 0xFFA0 | 0x180B..=0x180D | 0x180F | 0xFE00..=0xFE0F | 0xE0100..=0xE01EF | 0xFFFD)
}

fn clean_peer_name(raw: &str) -> Option<String> {
    let mut text = String::new();
    let mut base = false;
    let mut marks = 0;
    for c in raw.chars() {
        if whitespace(c) {
            if !text.is_empty() && !text.ends_with(' ') {
                text.push(' ');
            }
            base = false;
            marks = 0;
        } else if removed(c) {
            continue;
        } else if in_ranges(c, MARKS) {
            if base && marks < 2 {
                text.push(c);
                marks += 1;
            }
        } else {
            text.push(c);
            base = true;
            marks = 0;
        }
    }
    let name: String = text.trim_matches(' ').chars().take(40).collect();
    let name = name.trim_matches(' ');
    if !name.chars().any(|c| in_ranges(c, LETTERS_DIGITS)) {
        return None;
    }
    let lower = name.to_ascii_lowercase();
    if matches!(lower.as_str(), "wallet" | "your wallet") {
        return None;
    }
    let tokens: Vec<_> = lower
        .split(|c| !in_ranges(c, LETTERS_DIGITS))
        .filter(|s| !s.is_empty())
        .collect();
    if tokens.iter().any(|t| {
        matches!(
            *t,
            "home"
                | "elastos"
                | "runtime"
                | "system"
                | "inbox"
                | "people"
                | "library"
                | "documents"
                | "assistant"
        )
    }) {
        return None;
    }
    Some(name.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn n4_cleaning_vectors_shared() {
        let packets: serde_json::Value = serde_json::from_str(include_str!(
            "../../../../scripts/fixtures/wallet-connector-v2-messages.json"
        ))
        .unwrap();
        for fixture in packets["n4IdentityFields"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|f| f["expect"] == "accept")
        {
            assert!(validate_wallet_display_fields(
                fixture["actor"].as_str().unwrap(),
                fixture["fields"]["provider_id"].as_str(),
                fixture["fields"]["wallet_peer_name"].as_str()
            )
            .is_ok());
        }
        for (raw, expected) in [
            ("  Alice\tKey App  ", Some("Alice Key App")),
            ("Meta\u{202E}Mask\u{200B}", Some("MetaMask")),
            ("\u{3164}\u{2800}\u{FE0F}", None),
            ("😀", None),
            ("\u{301}A", Some("A")),
            (
                "a\u{301}\u{301}\u{301}\u{301}\u{301}",
                Some("a\u{301}\u{301}"),
            ),
            ("\u{FFFD}Alice", Some("Alice")),
            ("H\u{43E}me", Some("H\u{43E}me")),
            ("Home", None),
            ("SYSTEM support", None),
            ("Alice Home Wallet", None),
            ("Wallet", None),
            (" wallet ", None),
            ("Your wallet", None),
            ("YOUR WALLET", None),
            ("Trust Wallet", Some("Trust Wallet")),
            ("Coinbase Wallet", Some("Coinbase Wallet")),
            ("OKX Wallet", Some("OKX Wallet")),
            ("钱包", Some("钱包")),
        ] {
            let identity = wallet_display_identity("wallet-walletconnect", None, Some(raw));
            assert_eq!(identity.wallet_display_name.as_deref(), expected, "{raw:?}");
            assert_eq!(identity.wallet_mark, "wallet");
        }
        assert_eq!(
            wallet_display_identity("wallet-walletconnect", None, Some(&"A".repeat(41)))
                .wallet_display_name,
            Some("A".repeat(40))
        );
        assert_eq!(
            wallet_display_identity("wallet-metamask", None, Some("MetaMask")).wallet_display_name,
            None
        );
        assert_eq!(
            wallet_display_identity("wallet-metamask", Some("io.metamask"), None).wallet_mark,
            "metamask"
        );
        assert_eq!(
            wallet_display_identity("wallet-metamask", Some("com.brave.wallet"), None)
                .wallet_display_name
                .as_deref(),
            Some("Brave Wallet")
        );
    }
}
