//! Recipients for a send, read from a CSV file with one `address,amount_sat[,label]` line per
//! recipient.

use bdk_chain::bitcoin::{self, Network};
use frostsnap_core::{
    bitcoin_transaction::SilentPaymentOutput,
    silent_payments::{
        SignedSpContact, SilentPaymentRecipient, SpContactDetails, MAX_CONTACT_NAME_LEN,
    },
};
use std::str::FromStr;

/// A recipient line from a recipients file. Its address is not checked until `validate`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecipientEntry {
    /// The 1-based line the recipient was read from.
    pub line: usize,
    pub address: String,
    pub amount_sat: u64,
    pub label: Option<String>,
}

/// Parses `address,amount_sat[,label]` lines. A first row whose address field is `address` is a
/// header and is skipped, as are blank lines and lines starting with `#`. Every malformed line is
/// reported with its line number.
pub fn parse_csv(contents: &str) -> Result<Vec<RecipientEntry>, String> {
    let mut entries = Vec::new();
    let mut errors = Vec::new();
    let mut first_row = true;

    for (i, line) in contents.lines().enumerate() {
        let line_no = i + 1;
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        let is_first_row = first_row;
        first_row = false;

        let fields: Vec<&str> = trimmed
            .splitn(3, ',')
            .map(|field| field.trim().trim_matches('"'))
            .collect();
        if is_first_row && fields[0].eq_ignore_ascii_case("address") {
            continue;
        }
        if fields.len() < 2 {
            errors.push(format!(
                "Line {line_no}: expected 'address,amount_sat[,label]'"
            ));
            continue;
        }

        match fields[1].parse::<u64>() {
            Ok(amount_sat) => entries.push(RecipientEntry {
                line: line_no,
                address: fields[0].to_string(),
                amount_sat,
                label: fields
                    .get(2)
                    .filter(|label| !label.is_empty())
                    .map(|label| label.to_string()),
            }),
            Err(_) => errors.push(format!("Line {line_no}: invalid amount '{}'", fields[1])),
        }
    }

    if !errors.is_empty() {
        return Err(errors.join("\n"));
    }
    if entries.is_empty() {
        return Err("No recipients found in CSV file".to_string());
    }
    Ok(entries)
}

/// Checks each address on `network` and each amount against the dust limit, as the send builder
/// does for a single recipient. Every failing line is reported with its line number.
pub fn validate(entries: &[RecipientEntry], network: Network) -> Result<(), String> {
    let mut errors = Vec::new();

    for entry in entries {
        let line = entry.line;
        let min_non_dust =
            if SilentPaymentRecipient::from_address(&entry.address, network).is_some() {
                silent_payment_min_non_dust()
            } else {
                let address = bitcoin::Address::from_str(&entry.address)
                    .ok()
                    .and_then(|address| address.require_network(network).ok());
                match address {
                    Some(address) => address.script_pubkey().minimal_non_dust().to_sat(),
                    None => {
                        errors.push(format!(
                            "Line {line}: invalid address \"{}\"",
                            entry.address
                        ));
                        continue;
                    }
                }
            };

        if entry.amount_sat < min_non_dust {
            errors.push(format!(
                "Line {line}: amount {} sat is below dust threshold ({min_non_dust} sat)",
                entry.amount_sat
            ));
        }
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors.join("\n"))
    }
}

/// The dust limit of a silent payment output. Its script depends on the inputs, but it is always
/// P2TR, so its placeholder has the same limit.
pub fn silent_payment_min_non_dust() -> u64 {
    SilentPaymentOutput::placeholder_script()
        .minimal_non_dust()
        .to_sat()
}

/// The contact each line pays, by its index in `contacts`, or `None` for an ordinary address or,
/// with `allow_new`, a new contact.
///
/// A silent payment line pays one of `contacts`, found by its address. A label must agree with
/// the contacts: on a contact's line it must be that contact's name, and a label that names a
/// contact must be on that contact's line, since that is how an address substitution would look.
/// Names compare ignoring case, as contact names do.
///
/// With `allow_new`, a silent payment address that is not a contact is a new contact named by its
/// label, which must be a valid contact name. The caller adds the new contacts before the send.
/// A new name on any other address, or one new address under two names, is refused, since the
/// name will be a contact's by the time the send is built. Without `allow_new`, such a line is
/// refused.
///
/// Every line that disagrees is reported, and the file has to be fixed.
pub fn match_contacts(
    entries: &[RecipientEntry],
    network: Network,
    contacts: &[SignedSpContact],
    allow_new: bool,
) -> Result<Vec<Option<usize>>, String> {
    let mut errors = Vec::new();
    let mut matched = Vec::with_capacity(entries.len());
    // The new contacts so far: the line that named each, its address and name.
    let mut new: Vec<(usize, SilentPaymentRecipient, &str)> = Vec::new();
    // The labels of ordinary address lines so far, with their lines.
    let mut ordinary: Vec<(usize, &str)> = Vec::new();

    for entry in entries {
        let line = entry.line;
        let recipient = SilentPaymentRecipient::from_address(&entry.address, network);
        let paid = recipient.and_then(|recipient| {
            contacts
                .iter()
                .position(|contact| contact.contact.details.recipient == recipient)
        });
        if let (Some(recipient), None) = (recipient, paid) {
            if !allow_new {
                errors.push(format!(
                    "Line {line}: this silent payment address is not a contact. Add it as a contact first."
                ));
            } else if let Some(error) = new_contact_error(entry, recipient, &new, &ordinary) {
                errors.push(error);
            } else if let Some(label) = &entry.label {
                new.push((line, recipient, label));
            }
        }

        if let (None, Some(label)) = (recipient, &entry.label) {
            if let Some((other_line, _, _)) = new
                .iter()
                .find(|(_, _, name)| name.eq_ignore_ascii_case(label))
            {
                errors.push(format!(
                    "Line {line}: \"{label}\" is a new contact with a different address on line {other_line}"
                ));
            }
            ordinary.push((line, label));
        }

        if let Some(label) = &entry.label {
            let named = contacts
                .iter()
                .position(|contact| contact.contact.details.name.eq_ignore_ascii_case(label));
            match (paid, named) {
                (Some(paid), named) if named != Some(paid) => errors.push(format!(
                    "Line {line}: label \"{label}\" is not \"{}\", the contact at this address",
                    contacts[paid].contact.details.name
                )),
                (None, Some(_)) => errors.push(format!(
                    "Line {line}: \"{label}\" is a contact with a different address"
                )),
                _ => {}
            }
        }

        matched.push(paid);
    }

    if errors.is_empty() {
        Ok(matched)
    } else {
        Err(errors.join("\n"))
    }
}

/// Why `entry`, at `recipient`, which is not a contact, cannot be the new contact its label names,
/// given the new contacts and the labels of ordinary addresses on earlier lines.
fn new_contact_error(
    entry: &RecipientEntry,
    recipient: SilentPaymentRecipient,
    new: &[(usize, SilentPaymentRecipient, &str)],
    ordinary: &[(usize, &str)],
) -> Option<String> {
    let line = entry.line;
    let Some(label) = &entry.label else {
        return Some(format!(
            "Line {line}: this silent payment address is not a contact. Give it a label to add it as one."
        ));
    };
    let details = SpContactDetails {
        name: label.clone(),
        recipient,
    };
    if !details.has_valid_name() {
        return Some(format!(
            "Line {line}: label \"{label}\" can't be a contact name. Use 1 to {MAX_CONTACT_NAME_LEN} plain letters, numbers and symbols."
        ));
    }
    if let Some((other_line, _)) = ordinary
        .iter()
        .find(|(_, other)| other.eq_ignore_ascii_case(label))
    {
        return Some(format!(
            "Line {line}: \"{label}\" is the label of line {other_line}, which has a different address"
        ));
    }
    new.iter().find_map(|(other_line, other, name)| {
        let same_name = name.eq_ignore_ascii_case(label);
        if *other == recipient && !same_name {
            Some(format!(
                "Line {line}: this address is \"{name}\" on line {other_line}"
            ))
        } else if *other != recipient && same_name {
            Some(format!(
                "Line {line}: \"{label}\" is a new contact with a different address on line {other_line}"
            ))
        } else {
            None
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use frostsnap_core::{
        schnorr_fun::fun::{g, marker::*, Point, Scalar, G},
        silent_payments::SpContact,
    };

    const TB1_ADDR: &str = "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx";

    /// A silent payment address whose keys are `byte` times the generator.
    fn other_sp_address(byte: u8) -> String {
        let secret = Scalar::<Secret, Zero>::from_bytes_mod_order([byte; 32])
            .non_zero()
            .unwrap();
        let point = g!(secret * G).normalize();
        let recipient = SilentPaymentRecipient {
            scan_key: point,
            spend_key: point,
        };
        recipient.address(Network::Testnet).unwrap()
    }

    fn sp_address() -> String {
        let scan = [
            0x02, 0x20, 0xbc, 0xfa, 0xc5, 0xb9, 0x9e, 0x04, 0xad, 0x1a, 0x06, 0xdd, 0xfb, 0x01,
            0x6e, 0xe1, 0x35, 0x82, 0x60, 0x9d, 0x60, 0xb6, 0x29, 0x1e, 0x98, 0xd0, 0x1a, 0x9b,
            0xc9, 0xa1, 0x6c, 0x96, 0xd4,
        ];
        let spend = [
            0x02, 0x5c, 0xc9, 0x85, 0x6d, 0x6f, 0x83, 0x75, 0x35, 0x0e, 0x12, 0x39, 0x78, 0xda,
            0xac, 0x20, 0x0c, 0x26, 0x0c, 0xb5, 0xb5, 0xae, 0x83, 0x10, 0x6c, 0xab, 0x90, 0x48,
            0x4d, 0xcd, 0x8f, 0xcf, 0x36,
        ];
        let recipient = SilentPaymentRecipient {
            scan_key: Point::from_slice(&scan).unwrap(),
            spend_key: Point::from_slice(&spend).unwrap(),
        };
        recipient.address(Network::Testnet).unwrap()
    }

    /// A contact named `name` at `address`. Its signature is never checked here.
    fn contact(name: &str, address: &str) -> SignedSpContact {
        let recipient = SilentPaymentRecipient::from_address(address, Network::Testnet).unwrap();
        SignedSpContact {
            contact: SpContact {
                details: SpContactDetails {
                    name: name.into(),
                    recipient,
                },
                account_ecdh: recipient.scan_key,
            },
            added_at: frostsnap_core::silent_payments::BookHead::empty(),
            signature: [0u8; 64],
        }
    }

    fn labelled(line: usize, address: &str, label: &str) -> RecipientEntry {
        RecipientEntry {
            label: Some(label.to_string()),
            ..entry(line, address, 50_000)
        }
    }

    fn entry(line: usize, address: &str, amount_sat: u64) -> RecipientEntry {
        RecipientEntry {
            line,
            address: address.to_string(),
            amount_sat,
            label: None,
        }
    }

    #[test]
    fn parse_skips_header_blanks_and_comments() {
        let csv = format!(
            "address,amount_sat,label\n\n# Payroll\n{TB1_ADDR},50000,Bob\n{TB1_ADDR},75000\n"
        );
        let entries = parse_csv(&csv).unwrap();
        assert_eq!(
            entries,
            vec![
                RecipientEntry {
                    line: 4,
                    address: TB1_ADDR.to_string(),
                    amount_sat: 50_000,
                    label: Some("Bob".to_string()),
                },
                entry(5, TB1_ADDR, 75_000),
            ]
        );
    }

    #[test]
    fn parse_without_header_and_with_quoted_fields() {
        let csv = format!("\"{TB1_ADDR}\", \"1000\" ,\"\"\n{TB1_ADDR},2000,a, b\n");
        let entries = parse_csv(&csv).unwrap();
        assert_eq!(entries[0], entry(1, TB1_ADDR, 1_000));
        assert_eq!(entries[1].label, Some("a, b".to_string()));
    }

    #[test]
    fn parse_reports_every_malformed_line() {
        let csv = format!("{TB1_ADDR}\n{TB1_ADDR},lots\n{TB1_ADDR},5\n");
        let err = parse_csv(&csv).unwrap_err();
        assert_eq!(
            err,
            "Line 1: expected 'address,amount_sat[,label]'\nLine 2: invalid amount 'lots'"
        );
    }

    #[test]
    fn parse_rejects_empty_file() {
        assert_eq!(
            parse_csv("# nothing here\n\n").unwrap_err(),
            "No recipients found in CSV file"
        );
    }

    #[test]
    fn validate_accepts_addresses_and_silent_payments_above_dust() {
        let entries = vec![entry(1, TB1_ADDR, 50_000), entry(2, &sp_address(), 50_000)];
        validate(&entries, Network::Testnet).unwrap();
    }

    #[test]
    fn validate_reports_bad_address_with_line() {
        let entries = vec![entry(3, "badaddress123", 50_000)];
        let err = validate(&entries, Network::Testnet).unwrap_err();
        assert_eq!(err, "Line 3: invalid address \"badaddress123\"");
    }

    #[test]
    fn validate_rejects_a_corrupted_checksum() {
        for address in [TB1_ADDR.to_string(), sp_address()] {
            let mut corrupted = address.clone();
            let last = corrupted.pop().unwrap();
            corrupted.push(if last == 'q' { 'p' } else { 'q' });
            let err = validate(&[entry(4, &corrupted, 50_000)], Network::Testnet).unwrap_err();
            assert_eq!(err, format!("Line 4: invalid address \"{corrupted}\""));
        }
    }

    #[test]
    fn validate_rejects_address_from_another_network() {
        let mainnet = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
        let err = validate(&[entry(1, mainnet, 50_000)], Network::Testnet).unwrap_err();
        assert_eq!(err, format!("Line 1: invalid address \"{mainnet}\""));
    }

    #[test]
    fn validate_reports_dust_with_line() {
        let entries = vec![entry(1, TB1_ADDR, 10), entry(2, &sp_address(), 10)];
        let err = validate(&entries, Network::Testnet).unwrap_err();
        // P2WPKH dust is 294 sat, P2TR (silent payment) dust is 330 sat.
        assert_eq!(
            err,
            "Line 1: amount 10 sat is below dust threshold (294 sat)\n\
             Line 2: amount 10 sat is below dust threshold (330 sat)"
        );
    }

    #[test]
    fn a_silent_payment_line_pays_the_contact_at_its_address() {
        let contacts = [contact("Alice", &sp_address())];
        let entries = [
            entry(1, TB1_ADDR, 50_000),
            entry(2, &sp_address(), 50_000),
            labelled(3, &sp_address(), "alice"),
        ];
        assert_eq!(
            match_contacts(&entries, Network::Testnet, &contacts, false).unwrap(),
            vec![None, Some(0), Some(0)]
        );
    }

    #[test]
    fn an_unknown_silent_payment_address_is_refused() {
        let err = match_contacts(
            &[entry(2, &sp_address(), 50_000)],
            Network::Testnet,
            &[],
            false,
        )
        .unwrap_err();
        assert_eq!(
            err,
            "Line 2: this silent payment address is not a contact. Add it as a contact first."
        );
    }

    #[test]
    fn a_label_that_disagrees_with_the_contacts_is_refused() {
        let contacts = [contact("Alice", &sp_address())];
        let entries = [
            labelled(1, &sp_address(), "Bob"),
            labelled(2, TB1_ADDR, "Alice"),
            labelled(3, TB1_ADDR, "Carol"),
        ];
        let err = match_contacts(&entries, Network::Testnet, &contacts, false).unwrap_err();
        assert_eq!(
            err,
            "Line 1: label \"Bob\" is not \"Alice\", the contact at this address\n\
             Line 2: \"Alice\" is a contact with a different address"
        );
    }

    #[test]
    fn a_new_address_is_a_new_contact_named_by_its_label() {
        let contacts = [contact("Alice", &sp_address())];
        let bob = other_sp_address(0x11);
        let entries = [
            entry(1, &sp_address(), 50_000),
            labelled(2, &bob, "Bob"),
            // The same new address again, under its name in another case.
            labelled(3, &bob, "BOB"),
            entry(4, TB1_ADDR, 50_000),
        ];
        assert_eq!(
            match_contacts(&entries, Network::Testnet, &contacts, true).unwrap(),
            vec![Some(0), None, None, None]
        );
    }

    #[test]
    fn a_new_address_needs_a_label_that_can_be_a_new_name() {
        let contacts = [contact("Alice", &sp_address())];
        let entries = [
            entry(1, &other_sp_address(0x11), 50_000),
            labelled(2, &other_sp_address(0x12), "a name longer than twenty"),
            labelled(3, &other_sp_address(0x13), "caf\u{e9}"),
            labelled(4, &other_sp_address(0x14), "alice"),
            labelled(5, &other_sp_address(0x15), "Dan"),
            labelled(6, &other_sp_address(0x16), "dan"),
            labelled(7, &other_sp_address(0x15), "Eve"),
        ];
        let err = match_contacts(&entries, Network::Testnet, &contacts, true).unwrap_err();
        assert_eq!(
            err,
            "Line 1: this silent payment address is not a contact. Give it a label to add it as one.\n\
             Line 2: label \"a name longer than twenty\" can't be a contact name. Use 1 to 20 plain letters, numbers and symbols.\n\
             Line 3: label \"caf\u{e9}\" can't be a contact name. Use 1 to 20 plain letters, numbers and symbols.\n\
             Line 4: \"alice\" is a contact with a different address\n\
             Line 6: \"dan\" is a new contact with a different address on line 5\n\
             Line 7: this address is \"Dan\" on line 5"
        );
    }

    /// A new name is a contact by the time the send is built, so a line paying another address
    /// under it is refused now, whichever comes first.
    #[test]
    fn a_new_name_on_an_ordinary_address_is_refused() {
        let dan = other_sp_address(0x15);
        for (first, second) in [(1, 2), (2, 1)] {
            let entries = [
                labelled(first, &dan, "Dan"),
                labelled(second, TB1_ADDR, "dan"),
            ];
            let mut entries = entries.to_vec();
            entries.sort_by_key(|entry| entry.line);
            let err = match_contacts(&entries, Network::Testnet, &[], true).unwrap_err();
            let expected = if first == 1 {
                "Line 2: \"dan\" is a new contact with a different address on line 1"
            } else {
                "Line 2: \"Dan\" is the label of line 1, which has a different address"
            };
            assert_eq!(err, expected);
        }
    }
}
