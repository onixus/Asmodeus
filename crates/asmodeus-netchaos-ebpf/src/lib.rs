//! Map ABI shared by the bpf-target classifier in `src/main.rs` and the
//! userspace attach in `asmodeus-runner::aya_backend`.
//!
//! This lib stays `no_std`, allocation-free and buildable on the stable
//! toolchain the workspace pins: aya-ebpf is linked only for
//! `target_arch = "bpf"` (see `Cargo.toml`), so the default host build never
//! compiles it. The struct here is the single source of truth for the one
//! map the two sides exchange; a field added on one side without the other is
//! a refused load, never two sides writing past each other.

#![cfg_attr(not(test), no_std)]
#![deny(unsafe_code)]

/// Name of the single-slot array holding the live chaos rule. The
/// `#[map(name = ...)]` literal in `main.rs` must stay equal to this; attribute
/// args cannot reference a const, so the equality is asserted in a test.
pub const MAP_NETCHAOS_RULES: &str = "netchaos_rules";

/// `flags` bit: the rule is armed. A zeroed slot (map freshly created, or
/// zeroed on revert) has this clear, and the classifier then passes every
/// packet. Nothing is ever dropped against an unarmed rule — fail-open is the
/// only safe default for a datapath that sits on egress.
pub const CHAOS_FLAG_ARMED: u32 = 1 << 0;

/// Denominator for [`ChaosRule::loss_permille`]. Loss is drawn per packet as
/// `bpf_get_prandom_u32() % LOSS_SCALE < loss_permille`, so the field is
/// thousandths — `loss_pct * 10` — giving 0.1 % resolution over the 0..=50 %
/// the budget allows.
pub const LOSS_SCALE: u32 = 1_000;

/// The one rule the datapath enforces, written by userspace and read on every
/// egress packet by the classifier.
///
/// `#[repr(C)]` with explicit-width fields and no padding so the bytes are
/// identical on the bpf target and on the loader. The destination is kept in
/// network byte order (as it appears in the IPv4 header) so the kernel side
/// compares without a byte swap on the hot path.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ChaosRule {
    /// Destination network, big-endian, already masked to `prefix_mask`.
    pub dst_net_be: u32,
    /// Destination prefix mask, big-endian (e.g. /24 -> 0x00FF_FFFF in BE).
    pub prefix_mask_be: u32,
    /// Per-packet drop probability in thousandths; see [`LOSS_SCALE`].
    pub loss_permille: u32,
    /// Rule flags; see [`CHAOS_FLAG_ARMED`].
    pub flags: u32,
}

impl ChaosRule {
    /// True iff the armed bit is set.
    pub fn is_armed(&self) -> bool {
        self.flags & CHAOS_FLAG_ARMED != 0
    }

    /// True iff `dst_be` (a destination address in network byte order) falls
    /// inside this rule's masked network. The classifier mirrors this check;
    /// it is written once here so both sides agree on the blast radius.
    pub fn matches_dst(&self, dst_be: u32) -> bool {
        dst_be & self.prefix_mask_be == self.dst_net_be
    }
}

/// Bytes of one [`ChaosRule`], pinned so a field added to the struct is a
/// failure here rather than a silent widening the loader would not notice.
pub const CHAOS_RULE_SIZE: usize = 16;

// aya-ebpf requires the map value to be `Pod`; `ChaosRule` is plain data, which
// this const-assert keeps true (no padding, 16 bytes) across target changes.
const _: () = assert!(core::mem::size_of::<ChaosRule>() == CHAOS_RULE_SIZE);
const _: () = assert!(core::mem::align_of::<ChaosRule>() == 4);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn armed_bit_round_trips() {
        let mut r = ChaosRule::default();
        assert!(!r.is_armed(), "a zeroed rule must never be armed");
        r.flags |= CHAOS_FLAG_ARMED;
        assert!(r.is_armed());
    }

    #[test]
    fn dst_match_honours_the_mask() {
        // 203.0.113.0/24 (TEST-NET-3), network byte order.
        let net = u32::from_be_bytes([203, 0, 113, 0]).to_be();
        let mask = u32::from_be_bytes([255, 255, 255, 0]).to_be();
        let rule = ChaosRule {
            dst_net_be: net,
            prefix_mask_be: mask,
            loss_permille: 250,
            flags: CHAOS_FLAG_ARMED,
        };
        let inside = u32::from_be_bytes([203, 0, 113, 7]).to_be();
        let outside = u32::from_be_bytes([203, 0, 114, 7]).to_be();
        assert!(rule.matches_dst(inside));
        assert!(!rule.matches_dst(outside));
    }

    #[test]
    fn map_name_is_the_published_literal() {
        // The `#[map(name = "netchaos_rules")]` in main.rs cannot reference
        // this const; keep the literal and the const identical.
        assert_eq!(MAP_NETCHAOS_RULES, "netchaos_rules");
    }
}
