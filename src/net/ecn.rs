//! ECN helpers for inner IP packets.
//!
//! ArkIris carries the inner packet's ECN state in the authenticated tunnel
//! header. This preserves ECN semantics across the encrypted hop without
//! pretending that a portable UDP API exposes outer IP ancillary data.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EcnCodepoint { NotEct, Ect0, Ect1, Ce }

pub fn classify_ip(packet: &[u8]) -> EcnCodepoint {
    if packet.is_empty() { return EcnCodepoint::NotEct; }
    match packet[0] >> 4 {
        4 if packet.len() >= 2 => match packet[1] & 0x03 { 0 => EcnCodepoint::NotEct, 1 => EcnCodepoint::Ect1, 2 => EcnCodepoint::Ect0, _ => EcnCodepoint::Ce },
        6 if packet.len() >= 2 => match packet[0] & 0x03 { 0 => EcnCodepoint::NotEct, 1 => EcnCodepoint::Ect1, 2 => EcnCodepoint::Ect0, _ => EcnCodepoint::Ce },
        _ => EcnCodepoint::NotEct,
    }
}

pub fn flags_for(packet: &[u8]) -> u8 {
    match classify_ip(packet) {
        EcnCodepoint::Ect0 => crate::constants::FLAG_ECT0,
        EcnCodepoint::Ect1 => crate::constants::FLAG_ECT0,
        EcnCodepoint::Ce => crate::constants::FLAG_ECN_CE,
        EcnCodepoint::NotEct => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipv4_ecn_codepoints() {
        let mut p = [0u8; 20]; p[0] = 0x45;
        p[1] = 0x00; assert_eq!(classify_ip(&p), EcnCodepoint::NotEct);
        p[1] = 0x01; assert_eq!(classify_ip(&p), EcnCodepoint::Ect1);
        p[1] = 0x02; assert_eq!(classify_ip(&p), EcnCodepoint::Ect0);
        p[1] = 0x03; assert_eq!(classify_ip(&p), EcnCodepoint::Ce);
    }
}
