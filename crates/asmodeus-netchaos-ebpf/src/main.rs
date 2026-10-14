//! Egress `SchedClassifier` that applies synthetic, scope-confined packet loss
//! — the kernel half of the `LATENCY_SPIKE_VM` net-chaos action (FTT §4.2.1).
//!
//! Built only for `target_arch = "bpf"` (bpfel-unknown-none, nightly +
//! build-std); the host build compiles to an empty stub so the stable
//! workspace gates stay green and the object is never a build artefact of the
//! default `cargo build` (ARCHITECTURE.md §8). The Jenkins `netchaos BPF ELF`
//! stage builds it; `netchaos BPF attach` is the only place one of these
//! instructions meets a verifier.
//!
//! INV-0 / D7: the program is a *marker for the reserved test segment*, never a
//! weaponised black-hole. It drops a packet only when all three hold — the rule
//! is armed, the destination is inside the rule's masked test-block network,
//! and a per-packet pseudo-random draw lands under the configured loss. Any
//! header it cannot parse is passed (`TC_ACT_OK`): fail-open is the only safe
//! default on egress, and userspace has already confined the rule to a test
//! block and a test interface before it ever reaches this map.

#![cfg_attr(target_arch = "bpf", no_std, no_main)]

#[cfg(target_arch = "bpf")]
mod progs {
    use asmodeus_netchaos_ebpf::{ChaosRule, LOSS_SCALE};
    use aya_ebpf::{
        bindings::{TC_ACT_OK, TC_ACT_SHOT},
        cty::c_long,
        helpers::bpf_get_prandom_u32,
        macros::{classifier, map},
        maps::Array,
        programs::TcContext,
    };

    // The uapi `TC_ACT_*` are `u32` in the bindings, but a sched_cls program
    // returns `i32`; cast once here so the verdicts below read plainly.
    const PASS: i32 = TC_ACT_OK as i32;
    const DROP: i32 = TC_ACT_SHOT as i32;

    // Must stay equal to `asmodeus_netchaos_ebpf::MAP_NETCHAOS_RULES`; a
    // `#[map]` name literal cannot reference a const (asserted in lib.rs).
    #[map(name = "netchaos_rules")]
    static NETCHAOS_RULES: Array<ChaosRule> = Array::with_max_entries(1, 0);

    // Ethernet II framing on a test interface (veth/dummy): EtherType at byte
    // 12, payload after the 14-byte header. Only untagged IPv4-over-Ethernet is
    // matched — a VLAN tag (0x8100) shifts the header and the frame is passed,
    // and loopback (no L2 header) is refused by the userspace backend before
    // attach, so a frame reaching here always has this layout. The IPv4
    // destination sits 16 bytes into the IP header, so at absolute offset 30 —
    // in network byte order,
    // which is how the rule stores its network too (no swap on the hot path).
    const ETH_P_IP: u16 = 0x0800;
    const OFF_ETHERTYPE: usize = 12;
    const OFF_IPV4_DST: usize = 14 + 16;

    #[classifier]
    pub fn netchaos_egress(ctx: TcContext) -> i32 {
        match decide(&ctx) {
            Ok(verdict) => verdict,
            // Unreadable map or unparseable frame (not IPv4, too short): never
            // our synthetic target, so pass it untouched (fail-open).
            Err(_) => PASS,
        }
    }

    // `TcContext::load` fails with `c_long`; this chain propagates that so a
    // short frame falls through to the fail-open arm above.
    fn decide(ctx: &TcContext) -> Result<i32, c_long> {
        let rule = match NETCHAOS_RULES.get(0) {
            Some(rule) => rule,
            None => return Ok(PASS),
        };
        if !rule.is_armed() {
            return Ok(PASS);
        }
        // EtherType is on the wire big-endian; `load` copies raw bytes, so fold
        // to host order before comparing with the host-order literal.
        let ethertype: u16 = u16::from_be(ctx.load(OFF_ETHERTYPE)?);
        if ethertype != ETH_P_IP {
            return Ok(PASS);
        }
        // Raw network-order destination; `ChaosRule` keeps its network the same
        // way, so this compares directly.
        let dst_be: u32 = ctx.load(OFF_IPV4_DST)?;
        if !rule.matches_dst(dst_be) {
            return Ok(PASS);
        }
        // Armed, in scope: draw the synthetic loss. `% LOSS_SCALE` keeps the
        // comparison in thousandths to match `loss_permille`.
        let draw = unsafe { bpf_get_prandom_u32() } % LOSS_SCALE;
        if draw < rule.loss_permille {
            Ok(DROP)
        } else {
            Ok(PASS)
        }
    }

    #[panic_handler]
    fn panic(_info: &core::panic::PanicInfo) -> ! {
        loop {}
    }
}

#[cfg(not(target_arch = "bpf"))]
fn main() {}
