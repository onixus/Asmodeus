//! asmodeus-dsl — declarative scenario manifests (`AttackScenario`,
//! `ChaosExperiment`), type validation and safety whitelisting of paths/ports.
//! The REST API accepts only a validated, signed `scenario_id` — never a body.
//!
//! Enforces the root invariant INV-0 (Synthetic-Only, see ARCHITECTURE.md §0):
//! a manifest whose action is operational/weaponizable is rejected here, before
//! it can ever reach a runner.

pub mod manifest;
pub mod mitre;

pub use manifest::*;
pub use mitre::{lookup_technique, MitreTechnique, ALL_TECHNIQUES};

use asmodeus_common::{ActionNature, RunState};

/// Canary filesystem sandbox: the only paths any runner action may touch.
pub const CANARY_PREFIXES: [&str; 2] = ["/var/tmp/asmodeus-canary/", "/tmp/asmodeus-canary/"];

/// True iff `path` is confined to the canary blast radius. A bare prefix check
/// is not enough: `..` components let a prefixed path escape the sandbox, so
/// any traversal component rejects the path before the prefix check (INV-0).
pub fn path_in_scope(path: &str) -> bool {
    if path.split('/').any(|component| component == "..") {
        return false;
    }
    let trimmed = path.trim_end_matches('/');
    trimmed == "/var/tmp/asmodeus-canary"
        || trimmed == "/tmp/asmodeus-canary"
        || CANARY_PREFIXES.iter().any(|p| path.starts_with(p))
}

/// Network blast radius: the only address blocks a chaos action may perturb.
/// All are non-routable reserved ranges — loopback and the three RFC 5737
/// documentation nets (TEST-NET-1/2/3) — so a network-chaos rule can never
/// reach a production host, only a synthetic test segment (INV-0, FTT §4.3).
pub const NET_TEST_BLOCKS: [(u32, u32); 4] = [
    (0x7F00_0000, 8),  // 127.0.0.0/8    loopback
    (0xC000_0200, 24), // 192.0.2.0/24   TEST-NET-1
    (0xC633_6400, 24), // 198.51.100.0/24 TEST-NET-2
    (0xCB00_7100, 24), // 203.0.113.0/24 TEST-NET-3
];

/// Parse an IPv4 `a.b.c.d/len` CIDR into `(network_u32, prefix_len)`. Returns
/// `None` for any malformed input — no panics on bad operator data.
pub fn parse_ipv4_cidr(cidr: &str) -> Option<(u32, u32)> {
    let (addr, len) = cidr.split_once('/')?;
    let prefix: u32 = len.parse().ok()?;
    if prefix > 32 {
        return None;
    }
    let mut octets = [0u8; 4];
    let mut n = 0;
    for part in addr.split('.') {
        if n == 4 {
            return None; // too many octets
        }
        octets[n] = part.parse().ok()?;
        n += 1;
    }
    if n != 4 {
        return None; // too few octets
    }
    let ip = u32::from_be_bytes(octets);
    // Normalise: host bits below the prefix must be zero to name a network.
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    Some((ip & mask, prefix))
}

/// True iff `cidr` is an IPv4 block fully contained in one reserved test block.
/// A target is in scope only when it is at least as specific as a test block
/// (`prefix >= block_prefix`) and its network falls inside that block — so a
/// broad supernet like `0.0.0.0/0` can never smuggle in production addresses.
pub fn net_target_in_scope(cidr: &str) -> bool {
    let Some((net, prefix)) = parse_ipv4_cidr(cidr) else {
        return false;
    };
    NET_TEST_BLOCKS.iter().any(|&(block_net, block_prefix)| {
        if prefix < block_prefix {
            return false;
        }
        let mask = if block_prefix == 0 {
            0
        } else {
            u32::MAX << (32 - block_prefix)
        };
        net & mask == block_net
    })
}

/// Reason a manifest is refused validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RejectReason {
    /// INV-0 breach: the action carries operational capability.
    NotSynthetic,
    /// Filesystem target lies outside the canary scope.
    OutOfScope,
    /// Network target lies outside the reserved test blocks.
    OutOfNetScope,
}

/// INV-0 gate. Returns the next state (`Validated`) only for synthetic actions
/// confined to canary scope; otherwise the manifest is refused and never armed.
pub fn validate(nature: ActionNature, target_path: &str) -> Result<RunState, RejectReason> {
    if !nature.is_permitted() {
        return Err(RejectReason::NotSynthetic);
    }
    if !path_in_scope(target_path) {
        return Err(RejectReason::OutOfScope);
    }
    Ok(RunState::Validated)
}

/// INV-0 gate for a network-chaos action. Returns `Validated` only for a
/// synthetic action whose target CIDR is confined to the reserved test blocks;
/// otherwise the chaos experiment is refused and never armed.
pub fn validate_net(nature: ActionNature, target_cidr: &str) -> Result<RunState, RejectReason> {
    if !nature.is_permitted() {
        return Err(RejectReason::NotSynthetic);
    }
    if !net_target_in_scope(target_cidr) {
        return Err(RejectReason::OutOfNetScope);
    }
    Ok(RunState::Validated)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn synthetic_action_in_scope_validates() {
        let r = validate(ActionNature::Synthetic, "/tmp/asmodeus-canary/doc1");
        assert_eq!(r, Ok(RunState::Validated));
    }

    #[test]
    fn operational_action_is_rejected_by_inv0() {
        let r = validate(ActionNature::Operational, "/tmp/asmodeus-canary/doc1");
        assert_eq!(r, Err(RejectReason::NotSynthetic));
    }

    #[test]
    fn out_of_scope_path_is_rejected() {
        let r = validate(ActionNature::Synthetic, "/etc/passwd");
        assert_eq!(r, Err(RejectReason::OutOfScope));
    }

    #[test]
    fn traversal_out_of_canary_is_rejected() {
        // A prefixed path that escapes via `..` must not pass the gate.
        assert!(!path_in_scope("/tmp/asmodeus-canary/../../etc/asmodeus"));
        assert!(!path_in_scope("/tmp/asmodeus-canary/a/../../b"));
        assert_eq!(
            validate(ActionNature::Synthetic, "/tmp/asmodeus-canary/../../etc"),
            Err(RejectReason::OutOfScope)
        );
        // A clean path inside the sandbox still passes.
        assert!(path_in_scope("/tmp/asmodeus-canary/canary_000.docx"));
    }

    #[test]
    fn test_net_blocks_are_in_scope() {
        // Loopback and each RFC 5737 documentation net, host and subnet.
        assert!(net_target_in_scope("127.0.0.1/32"));
        assert!(net_target_in_scope("127.0.0.0/8"));
        assert!(net_target_in_scope("192.0.2.0/24"));
        assert!(net_target_in_scope("192.0.2.42/32"));
        assert!(net_target_in_scope("198.51.100.0/25"));
        assert!(net_target_in_scope("203.0.113.7/32"));
    }

    #[test]
    fn production_ranges_are_out_of_net_scope() {
        // Real/routable and RFC1918 addresses must never be in chaos scope.
        assert!(!net_target_in_scope("10.0.0.0/8"));
        assert!(!net_target_in_scope("192.168.1.0/24"));
        assert!(!net_target_in_scope("8.8.8.8/32"));
        assert!(!net_target_in_scope("203.0.114.0/24")); // one net past TEST-NET-3
    }

    #[test]
    fn broad_supernet_cannot_smuggle_production() {
        // A supernet less specific than a test block is refused even though it
        // technically overlaps it — it also spans production space.
        assert!(!net_target_in_scope("0.0.0.0/0"));
        assert!(!net_target_in_scope("192.0.0.0/16")); // covers 192.0.2.0/24 but wider
        assert_eq!(
            validate_net(ActionNature::Synthetic, "0.0.0.0/0"),
            Err(RejectReason::OutOfNetScope)
        );
    }

    #[test]
    fn malformed_cidr_is_rejected_without_panic() {
        assert!(parse_ipv4_cidr("not-an-ip").is_none());
        assert!(parse_ipv4_cidr("192.0.2.0").is_none()); // missing prefix
        assert!(parse_ipv4_cidr("192.0.2.0/33").is_none()); // prefix too large
        assert!(parse_ipv4_cidr("192.0.2.256/24").is_none()); // octet overflow
        assert!(parse_ipv4_cidr("1.2.3.4.5/24").is_none()); // too many octets
        assert!(parse_ipv4_cidr("1.2.3/24").is_none()); // too few octets
        assert!(!net_target_in_scope("garbage"));
    }

    #[test]
    fn net_gate_rejects_operational_and_out_of_scope() {
        assert_eq!(
            validate_net(ActionNature::Synthetic, "192.0.2.0/24"),
            Ok(RunState::Validated)
        );
        assert_eq!(
            validate_net(ActionNature::Operational, "192.0.2.0/24"),
            Err(RejectReason::NotSynthetic)
        );
        assert_eq!(
            validate_net(ActionNature::Synthetic, "10.0.0.0/8"),
            Err(RejectReason::OutOfNetScope)
        );
    }
}
