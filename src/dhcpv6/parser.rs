use std::net::{Ipv4Addr, Ipv6Addr};

use crate::error::MapEError;
use crate::map::rule::{MapRule, PortParams};

// DHCPv6 message types
const MSG_ADVERTISE: u8 = 2;
const MSG_REPLY: u8 = 7;

// DHCPv6 option codes
const OPTION_S46_RULE: u16 = 89;
const OPTION_S46_BR: u16 = 90;
const OPTION_S46_PORTPARAMS: u16 = 93;
const OPTION_S46_CONT_MAPE: u16 = 94;

/// Parse DHCPv6 payload bytes and extract a list of MapRule from OPTION_S46_CONT_MAPE.
///
/// Returns:
/// - `Ok(None)` if the message type is not Advertise(2) or Reply(7)
/// - `Ok(None)` if no OPTION_S46_CONT_MAPE is present
/// - `Ok(Some(rules))` if rules were successfully parsed
/// - `Err(MapEError::MissingBrAddress)` if OPTION_S46_BR is absent inside CONT_MAPE
/// - `Err(MapEError::InvalidConfig)` if PORTPARAMS contain invalid values
pub fn parse_mape_option(payload: &[u8]) -> Result<Option<Vec<MapRule>>, MapEError> {
    if payload.len() < 4 {
        return Ok(None);
    }

    let msg_type = payload[0];
    if msg_type != MSG_ADVERTISE && msg_type != MSG_REPLY {
        return Ok(None);
    }

    // Skip 1-byte message type + 3-byte transaction ID
    let options = &payload[4..];
    let cont_mape_data = find_option(options, OPTION_S46_CONT_MAPE);

    let Some(cont_mape_data) = cont_mape_data else {
        return Ok(None);
    };

    // Parse sub-options inside CONT_MAPE
    let mut rules: Vec<MapRule> = Vec::new();
    let mut br_addr: Option<Ipv6Addr> = None;

    let mut pos = 0;
    while pos + 4 <= cont_mape_data.len() {
        let code = u16::from_be_bytes([cont_mape_data[pos], cont_mape_data[pos + 1]]);
        let len = u16::from_be_bytes([cont_mape_data[pos + 2], cont_mape_data[pos + 3]]) as usize;
        pos += 4;

        if pos + len > cont_mape_data.len() {
            break;
        }

        let data = &cont_mape_data[pos..pos + len];

        match code {
            OPTION_S46_RULE => {
                let rule = parse_s46_rule(data)?;
                rules.push(rule);
            }
            OPTION_S46_BR => {
                if br_addr.is_none() {
                    if data.len() >= 16 {
                        let mut octets = [0u8; 16];
                        octets.copy_from_slice(&data[..16]);
                        br_addr = Some(Ipv6Addr::from(octets));
                    }
                }
            }
            _ => {}
        }

        pos += len;
    }

    let br_addr = br_addr.ok_or(MapEError::MissingBrAddress)?;

    for rule in &mut rules {
        rule.br_addr = br_addr;
    }

    Ok(Some(rules))
}

/// Search for an option with the given code in the options slice.
/// Options are TLV: 2-byte code (big-endian), 2-byte length (big-endian), variable data.
fn find_option(options: &[u8], target_code: u16) -> Option<&[u8]> {
    let mut pos = 0;
    while pos + 4 <= options.len() {
        let code = u16::from_be_bytes([options[pos], options[pos + 1]]);
        let len = u16::from_be_bytes([options[pos + 2], options[pos + 3]]) as usize;
        pos += 4;

        if pos + len > options.len() {
            break;
        }

        if code == target_code {
            return Some(&options[pos..pos + len]);
        }

        pos += len;
    }
    None
}

/// Parse OPTION_S46_RULE data bytes into a MapRule.
/// Layout:
///   1 byte: flags (bit0 = FMR)
///   1 byte: ea_len
///   1 byte: prefix4_len
///   4 bytes: ipv4_prefix
///   1 byte: ipv6_prefix_len
///   ceil(ipv6_prefix_len / 8) bytes: ipv6_prefix (padded to 16 bytes with zeros)
///   then: sub-options (may include OPTION_S46_PORTPARAMS)
fn parse_s46_rule(data: &[u8]) -> Result<MapRule, MapEError> {
    if data.len() < 8 {
        return Err(MapEError::InvalidConfig(
            "S46_RULE too short".to_string(),
        ));
    }

    let flags = data[0];
    let is_fmr = (flags & 0x01) != 0;
    let ea_len = data[1];
    let prefix4_len = data[2];

    let ipv4_prefix = Ipv4Addr::new(data[3], data[4], data[5], data[6]);

    let ipv6_prefix_len = data[7];
    let ipv6_bytes_needed = (ipv6_prefix_len as usize + 7) / 8;

    if data.len() < 8 + ipv6_bytes_needed {
        return Err(MapEError::InvalidConfig(
            "S46_RULE IPv6 prefix truncated".to_string(),
        ));
    }

    let mut ipv6_octets = [0u8; 16];
    ipv6_octets[..ipv6_bytes_needed].copy_from_slice(&data[8..8 + ipv6_bytes_needed]);
    let ipv6_prefix = Ipv6Addr::from(ipv6_octets);

    // Parse sub-options after the fixed prefix fields
    let sub_options_start = 8 + ipv6_bytes_needed;
    let sub_options = &data[sub_options_start..];

    let port_params = if let Some(pp_data) = find_option(sub_options, OPTION_S46_PORTPARAMS) {
        parse_portparams(pp_data)?
    } else {
        PortParams {
            psid_offset: 0,
            psid_len: 0,
            psid: 0,
        }
    };

    Ok(MapRule {
        ipv4_prefix,
        prefix4_len,
        ipv6_prefix,
        prefix6_len: ipv6_prefix_len,
        ea_len,
        port_params,
        // br_addr will be set after parsing OPTION_S46_BR
        br_addr: Ipv6Addr::UNSPECIFIED,
        is_fmr,
    })
}

/// Parse OPTION_S46_PORTPARAMS data (3 bytes).
/// Byte 0: upper 4 bits = psid_offset, lower 4 bits = psid_len
/// Bytes 1-2: PSID left-aligned (>> (16 - psid_len) to right-align; if psid_len == 0, psid = 0)
fn parse_portparams(data: &[u8]) -> Result<PortParams, MapEError> {
    if data.len() < 3 {
        return Err(MapEError::InvalidConfig(
            "PORTPARAMS too short".to_string(),
        ));
    }

    let psid_offset = (data[0] >> 4) & 0x0F;
    let psid_len = data[0] & 0x0F;

    if psid_offset as u16 + psid_len as u16 >= 16 {
        return Err(MapEError::InvalidConfig(
            "psid_offset + psid_len >= 16".to_string(),
        ));
    }

    let raw_psid = u16::from_be_bytes([data[1], data[2]]);
    let psid = if psid_len == 0 {
        0
    } else {
        raw_psid >> (16 - psid_len)
    };

    Ok(PortParams {
        psid_offset,
        psid_len,
        psid,
    })
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use super::*;

    // Valid DHCPv6 Reply with 1 MAP rule + PORTPARAMS + BR
    // Packet layout (bytes):
    // 07 11 22 33 - Reply header
    // 00 5e 00 2f - OPTION_S46_CONT_MAPE (code=94, length=47)
    //   00 59 00 17 - OPTION_S46_RULE (code=89, length=23)
    //     01 - flags (FMR=true)
    //     10 - ea_len=16
    //     0f - prefix4_len=15
    //     6a 49 00 00 - ipv4_prefix=106.73.0.0
    //     40 - ipv6_prefix_len=64
    //     24 04 92 00 02 25 01 00 - ipv6_prefix=2404:9200:225:100::
    //     00 5d 00 03 - OPTION_S46_PORTPARAMS (code=93, length=3)
    //       48 - offset=4 (bits 7-4), psid_len=8 (bits 3-0)
    //       00 00 - psid=0 (left-aligned)
    //   00 5a 00 10 - OPTION_S46_BR (code=90, length=16)
    //     24 04 92 00 02 25 01 00 00 00 00 00 00 00 00 64 - BR=2404:9200:225:100::64
    const VALID_REPLY: &[u8] = &[
        0x07, 0x11, 0x22, 0x33,
        0x00, 0x5e, 0x00, 0x2f,
        0x00, 0x59, 0x00, 0x17,
        0x01, 0x10, 0x0f,
        0x6a, 0x49, 0x00, 0x00,
        0x40,
        0x24, 0x04, 0x92, 0x00, 0x02, 0x25, 0x01, 0x00,
        0x00, 0x5d, 0x00, 0x03,
        0x48, 0x00, 0x00,
        0x00, 0x5a, 0x00, 0x10,
        0x24, 0x04, 0x92, 0x00, 0x02, 0x25, 0x01, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x64,
    ];

    #[test]
    fn test_parse_valid_reply() {
        let result = parse_mape_option(VALID_REPLY).unwrap();
        assert!(result.is_some());
        let rules = result.unwrap();
        assert_eq!(rules.len(), 1);

        let rule = &rules[0];
        assert_eq!(rule.ipv4_prefix, Ipv4Addr::new(106, 73, 0, 0));
        assert_eq!(rule.prefix4_len, 15);
        assert_eq!(rule.ea_len, 16);
        assert_eq!(
            rule.ipv6_prefix,
            "2404:9200:225:100::".parse::<Ipv6Addr>().unwrap()
        );
        assert_eq!(rule.prefix6_len, 64);
        assert_eq!(rule.port_params.psid_offset, 4);
        assert_eq!(rule.port_params.psid_len, 8);
        assert_eq!(rule.port_params.psid, 0);
        assert_eq!(
            rule.br_addr,
            "2404:9200:225:100::64".parse::<Ipv6Addr>().unwrap()
        );
        assert!(rule.is_fmr);
    }

    #[test]
    fn test_parse_advertise() {
        let mut packet = VALID_REPLY.to_vec();
        packet[0] = 0x02; // Advertise
        let result = parse_mape_option(&packet).unwrap();
        assert!(result.is_some());
        let rules = result.unwrap();
        assert_eq!(rules.len(), 1);
    }

    #[test]
    fn test_ignore_solicit() {
        let mut packet = VALID_REPLY.to_vec();
        packet[0] = 0x01; // Solicit
        let result = parse_mape_option(&packet).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_no_mape_option() {
        // Reply with just the header (no options)
        let packet = &[0x07u8, 0x11, 0x22, 0x33];
        let result = parse_mape_option(packet).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_missing_br() {
        // Same as VALID_REPLY but without the OPTION_S46_BR bytes.
        // CONT_MAPE starts at byte 4. The total length in the header says 0x2f=47.
        // OPTION_S46_RULE occupies 4 + 23 = 27 bytes.
        // BR would start at 4 + 4 + 27 = 35, total packet length = 4+4+27+4+16 = 55
        // We truncate CONT_MAPE to only include the RULE (no BR):
        // Rewrite length of CONT_MAPE to 27 (0x1b) and truncate after the rule.
        let mut packet = VALID_REPLY.to_vec();
        // CONT_MAPE length is at bytes 6-7; set to 27 (0x00 0x1b)
        packet[6] = 0x00;
        packet[7] = 0x1b;
        // Truncate to header(4) + CONT_MAPE header(4) + RULE(4+23)
        packet.truncate(4 + 4 + 4 + 23);
        let result = parse_mape_option(&packet);
        assert!(matches!(result, Err(MapEError::MissingBrAddress)));
    }

    #[test]
    fn test_invalid_portparams() {
        // PORTPARAMS with psid_offset=8, psid_len=8 → sum=16 ≥ 16 → InvalidConfig
        // In VALID_REPLY, PORTPARAMS data byte is at offset:
        // header(4) + CONT_MAPE_hdr(4) + RULE_hdr(4) + flags/ea/prefix4(3) + ipv4(4) + ipv6len(1) + ipv6(8) = 28
        // then PORTPARAMS_hdr(4) then data byte at 32
        // Actually let's compute carefully:
        // 0..3: msg hdr
        // 4..7: CONT_MAPE header
        // 8..11: RULE header
        // 12: flags
        // 13: ea_len
        // 14: prefix4_len
        // 15..18: ipv4_prefix
        // 19: ipv6_prefix_len (=64)
        // 20..27: ipv6_prefix (8 bytes for /64)
        // 28..31: PORTPARAMS header
        // 32: PORTPARAMS byte 0 (offset/psid_len)
        // 33..34: PSID
        let mut packet = VALID_REPLY.to_vec();
        packet[32] = 0x88; // offset=8 (bits 7-4), psid_len=8 (bits 3-0) → 8+8=16 ≥ 16
        let result = parse_mape_option(&packet);
        assert!(matches!(result, Err(MapEError::InvalidConfig(_))));
    }

    #[test]
    fn test_no_portparams() {
        // Build VALID_REPLY without PORTPARAMS inside the RULE.
        // Original RULE data (23 bytes):
        //   01 10 0f 6a 49 00 00 40 24 04 92 00 02 25 01 00 00 5d 00 03 48 00 00
        // Without PORTPARAMS = first 16 bytes (flags + ea + prefix4 + ipv4 + prefix6len + ipv6prefix):
        //   01 10 0f 6a 49 00 00 40 24 04 92 00 02 25 01 00
        // New RULE length = 16 (0x10), new CONT_MAPE length = 4+16+4+16 = 40 (0x28)
        let new_rule_data: &[u8] = &[
            0x01, 0x10, 0x0f,
            0x6a, 0x49, 0x00, 0x00,
            0x40,
            0x24, 0x04, 0x92, 0x00, 0x02, 0x25, 0x01, 0x00,
        ];
        let br_data: &[u8] = &[
            0x24, 0x04, 0x92, 0x00, 0x02, 0x25, 0x01, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x64,
        ];
        let rule_len = new_rule_data.len() as u16;
        let br_len = br_data.len() as u16;
        let cont_mape_len = 4 + rule_len + 4 + br_len; // rule_hdr + rule + br_hdr + br

        let mut packet: Vec<u8> = Vec::new();
        // DHCPv6 Reply header
        packet.extend_from_slice(&[0x07, 0x11, 0x22, 0x33]);
        // CONT_MAPE header
        packet.extend_from_slice(&[0x00, 0x5e]);
        packet.extend_from_slice(&cont_mape_len.to_be_bytes());
        // RULE header
        packet.extend_from_slice(&[0x00, 0x59]);
        packet.extend_from_slice(&rule_len.to_be_bytes());
        // RULE data
        packet.extend_from_slice(new_rule_data);
        // BR header
        packet.extend_from_slice(&[0x00, 0x5a]);
        packet.extend_from_slice(&br_len.to_be_bytes());
        // BR data
        packet.extend_from_slice(br_data);

        let result = parse_mape_option(&packet).unwrap();
        assert!(result.is_some());
        let rules = result.unwrap();
        assert_eq!(rules.len(), 1);
        let rule = &rules[0];
        assert_eq!(rule.port_params.psid_offset, 0);
        assert_eq!(rule.port_params.psid_len, 0);
        assert_eq!(rule.port_params.psid, 0);
    }
}
