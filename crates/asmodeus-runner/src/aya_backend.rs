//! Linux-stand eBPF/TC network-chaos backend (real `aya` attach).
//!
//! Compiled only under `--features ebpf` on Linux, and **not verified on
//! macOS by construction** (ARCHITECTURE.md §8) — this crate's default build,
//! on every platform, uses [`crate::netchaos::SimBackend`]. The compiled BPF
//! object comes from `asmodeus-netchaos-ebpf` (nightly, bpfel-unknown-none)
//! and is provisioned on the stand; its path is read from
//! `ASMODEUS_NETCHAOS_BPF_OBJECT`.
//!
//! ## What it does (D7: aya, never shelling out to `tc`/`iptables`)
//!
//! 1. Raise `RLIMIT_MEMLOCK`, then `aya::Bpf::load` the object bytes.
//! 2. `tc::qdisc_add_clsact(iface)` — idempotent; an existing clsact is reused.
//! 3. Attach the `netchaos_egress` [`aya::programs::SchedClassifier`] to the
//!    interface's egress.
//! 4. Write one armed [`ChaosRule`] into the `netchaos_rules` map. The kernel
//!    program drops a packet only when it is armed, the destination is inside
//!    the rule's masked test-block network, and a per-packet draw lands under
//!    the configured loss — a synthetic marker for the test segment, never a
//!    weaponised black-hole.
//! 5. `revert` disarms the rule (zeroes the map) and drops the loaded program,
//!    which detaches the classifier, so `CLEANUP` leaves no residual drop.
//!
//! The spec is already scope/budget-validated by [`crate::netchaos::NetChaosSpec`]
//! before it reaches here, so this module only parses the (validated) CIDR and
//! installs the rule. A missing object or any load/attach failure returns a
//! clear [`NetChaosError::Backend`] — an operator gets an actionable signal and
//! INV-0 is never at risk because no partial rule is installed.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use aya::maps::Array as AyaArray;
use aya::programs::{tc, SchedClassifier, TcAttachType};
use aya::Bpf;

use asmodeus_netchaos_ebpf::{ChaosRule, CHAOS_FLAG_ARMED, LOSS_SCALE, MAP_NETCHAOS_RULES};

use crate::netchaos::{NetChaosBackend, NetChaosError, NetChaosSpec, RuleHandle};

/// Path to the compiled eBPF object, provisioned on the Linux stand.
const BPF_OBJECT_ENV: &str = "ASMODEUS_NETCHAOS_BPF_OBJECT";

/// The classifier program name, matching `#[classifier] fn netchaos_egress` in
/// `asmodeus-netchaos-ebpf`.
const PROGRAM: &str = "netchaos_egress";

/// `aya::Pod` newtype over the shared [`ChaosRule`]. `ChaosRule` lives in a
/// no_std crate that must not depend on aya, so the `Pod` marker — which aya
/// requires to write a value into a map — is carried by this local,
/// `repr(transparent)` wrapper instead (the orphan rule forbids implementing a
/// foreign trait on the foreign struct directly).
#[repr(transparent)]
#[derive(Clone, Copy)]
struct PodRule(ChaosRule);

// SAFETY: `ChaosRule` is `#[repr(C)]` plain data with no padding, no pointers
// and no invalid bit patterns (asserted 16 bytes / align 4 in the ABI crate);
// `repr(transparent)` gives `PodRule` the identical layout.
unsafe impl aya::Pod for PodRule {}

/// One live rule: the loaded program (whose `Drop` detaches the classifier) and
/// the interface it is attached to.
struct LoadedRule {
    bpf: Bpf,
    iface: String,
}

/// eBPF/TC backend. Owns the live `aya` state for every rule it installs,
/// keyed by the opaque token it hands back in a [`RuleHandle`]; the plain-data
/// handle cannot carry the loaded `Bpf` itself, and one backend instance serves
/// both `apply` and `revert` within a single [`crate::netchaos::NetChaosSession`].
#[derive(Default)]
pub struct AyaTcBackend {
    rules: Mutex<HashMap<u64, LoadedRule>>,
    next_token: AtomicU64,
}

impl std::fmt::Debug for AyaTcBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let live = self.rules.lock().map(|r| r.len()).unwrap_or(0);
        f.debug_struct("AyaTcBackend")
            .field("live_rules", &live)
            .finish()
    }
}

impl AyaTcBackend {
    pub fn new() -> Self {
        Self::default()
    }
}

impl NetChaosBackend for AyaTcBackend {
    fn apply(&self, spec: &NetChaosSpec) -> Result<RuleHandle, NetChaosError> {
        // The classifier parses an Ethernet II frame (EtherType + IPv4 header at
        // fixed offsets). Loopback carries no L2 header, so the program could
        // never match on `lo`, and dropping there would hit unrelated localhost
        // traffic rather than a reserved test segment. Refuse it up front with an
        // actionable signal instead of attaching a rule that silently drops
        // nothing. The SimBackend (default build) still accepts loopback for the
        // off-stand demo; the real datapath wants a dedicated test interface.
        if is_loopback(&spec.iface) {
            return Err(NetChaosError::Backend(format!(
                "aya eBPF/TC loss datapath needs an Ethernet test interface \
                 (veth/dummy/test/chaos); loopback `{}` has no L2 header and is \
                 refused — provision a dedicated test interface on the stand",
                spec.iface
            )));
        }
        let (dst_net_be, prefix_mask_be) = parse_cidr_be(&spec.target_cidr)?;
        let rule = ChaosRule {
            dst_net_be,
            prefix_mask_be,
            loss_permille: u32::from(spec.loss_pct) * (LOSS_SCALE / 100),
            flags: CHAOS_FLAG_ARMED,
        };

        let object = std::env::var(BPF_OBJECT_ENV).map_err(|_| {
            NetChaosError::Backend(format!(
                "aya eBPF/TC backend selected but {BPF_OBJECT_ENV} is unset — \
                 build the netchaos BPF object on the Linux stand and point this \
                 env at it (see aya_backend.rs)"
            ))
        })?;

        // The charge happens inside `Bpf::load`; raise the lock first so a
        // failure on a pre-5.11 kernel names what it ran under.
        let memlock = raise_memlock();
        let mut bpf = Bpf::load_file(&object).map_err(|e| {
            NetChaosError::Backend(format!("load eBPF object {object}: {e} [{memlock}]"))
        })?;

        // clsact is a prerequisite for an egress filter; adding it is
        // idempotent, so an interface that already carries one is reused.
        if let Err(e) = tc::qdisc_add_clsact(&spec.iface) {
            // Tolerate an already-present clsact whether aya surfaces it as the
            // raw EEXIST errno or as a kind-only AlreadyExists io::Error.
            let already_present = e.raw_os_error() == Some(libc::EEXIST)
                || e.kind() == std::io::ErrorKind::AlreadyExists;
            if !already_present {
                return Err(NetChaosError::Backend(format!(
                    "add clsact qdisc on {}: {e}",
                    spec.iface
                )));
            }
        }

        let program: &mut SchedClassifier = bpf
            .program_mut(PROGRAM)
            .ok_or_else(|| {
                NetChaosError::Backend(format!("program {PROGRAM} missing from eBPF object"))
            })?
            .try_into()
            .map_err(|e| NetChaosError::Backend(format!("{PROGRAM} is not a classifier: {e}")))?;
        program
            .load()
            .map_err(|e| NetChaosError::Backend(format!("load {PROGRAM}: {e}")))?;
        program
            .attach(&spec.iface, TcAttachType::Egress)
            .map_err(|e| {
                NetChaosError::Backend(format!("attach {PROGRAM} to {} egress: {e}", spec.iface))
            })?;

        // Arm the rule last: the program is live but the map is zeroed until
        // now, so nothing is dropped before the scope is written.
        write_rule(&mut bpf, rule)?;

        let token = self.next_token.fetch_add(1, Ordering::Relaxed);
        self.rules.lock().expect("aya backend lock").insert(
            token,
            LoadedRule {
                bpf,
                iface: spec.iface.clone(),
            },
        );
        Ok(RuleHandle {
            iface: spec.iface.clone(),
            target_cidr: spec.target_cidr.clone(),
            token,
        })
    }

    fn revert(&self, handle: &RuleHandle) -> Result<(), NetChaosError> {
        let mut loaded = self
            .rules
            .lock()
            .expect("aya backend lock")
            .remove(&handle.token)
            .ok_or_else(|| {
                NetChaosError::Backend(format!("no such rule token={}", handle.token))
            })?;
        // Disarm before detaching so that even if the detach is delayed, the
        // kernel passes every packet from this instant. A zeroed rule has the
        // armed bit clear.
        let _ = write_rule(&mut loaded.bpf, ChaosRule::default());
        // Log the interface the program was actually attached to (not the
        // handle's copy), then drop: dropping the loaded program detaches the
        // classifier. The (now empty) clsact qdisc may remain on the test
        // interface — aya 0.12 exposes no removal — but it carries no rule and
        // injects no chaos.
        let iface = loaded.iface.clone();
        drop(loaded);
        tracing::info!(iface = %iface, "netchaos aya rule detached");
        Ok(())
    }

    fn name(&self) -> &'static str {
        "aya-tc"
    }
}

/// Write one rule into slot 0 of the `netchaos_rules` array.
fn write_rule(bpf: &mut Bpf, rule: ChaosRule) -> Result<(), NetChaosError> {
    let map = bpf.map_mut(MAP_NETCHAOS_RULES).ok_or_else(|| {
        NetChaosError::Backend(format!("map {MAP_NETCHAOS_RULES} missing from eBPF object"))
    })?;
    let mut array: AyaArray<_, PodRule> = AyaArray::try_from(map).map_err(|e| {
        NetChaosError::Backend(format!("{MAP_NETCHAOS_RULES} is not an array: {e}"))
    })?;
    array
        .set(0, PodRule(rule), 0)
        .map_err(|e| NetChaosError::Backend(format!("write {MAP_NETCHAOS_RULES}[0]: {e}")))
}

/// True iff `iface` names the loopback device (`lo`, or `lo` followed by an
/// index such as `lo0`). Matched precisely, like the net-scope check in
/// [`crate::netchaos`], so it cannot accept `flow0`/`silo0` as a loose prefix.
fn is_loopback(iface: &str) -> bool {
    iface == "lo"
        || iface
            .strip_prefix("lo")
            .is_some_and(|rest| !rest.is_empty() && rest.bytes().all(|b| b.is_ascii_digit()))
}

/// Parse a validated `a.b.c.d/len` CIDR into `(network_be, mask_be)`, both in
/// network byte order to match [`ChaosRule`]. The spec is already in scope by
/// the time it reaches here, so a parse failure is a backend error rather than
/// a scope decision.
fn parse_cidr_be(cidr: &str) -> Result<(u32, u32), NetChaosError> {
    let bad = || NetChaosError::Backend(format!("unparseable target CIDR: {cidr}"));
    let (addr, prefix) = cidr.split_once('/').ok_or_else(bad)?;
    let prefix: u32 = prefix.parse().map_err(|_| bad())?;
    if prefix > 32 {
        return Err(bad());
    }
    let mut octets = [0u8; 4];
    let mut parts = addr.split('.');
    for octet in octets.iter_mut() {
        *octet = parts.next().and_then(|p| p.parse().ok()).ok_or_else(bad)?;
    }
    if parts.next().is_some() {
        return Err(bad());
    }
    let mask_host: u32 = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    let net_host = u32::from_be_bytes(octets) & mask_host;
    Ok((net_host.to_be(), mask_host.to_be()))
}

/// Raise the soft `RLIMIT_MEMLOCK` to the hard limit and describe the result
/// for a load error. On 5.11+ the charge moved off memlock and this decides
/// nothing; on older kernels it is the difference between a load and an EPERM.
fn raise_memlock() -> String {
    let mut lim = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: both calls read/write exactly one `rlimit` through a pointer to a
    // live local and touch nothing else.
    let read = unsafe { libc::getrlimit(libc::RLIMIT_MEMLOCK, &mut lim) };
    if read != 0 {
        return "RLIMIT_MEMLOCK unreadable".to_string();
    }
    if lim.rlim_cur == lim.rlim_max {
        return format!("RLIMIT_MEMLOCK soft already at hard ({})", lim.rlim_max);
    }
    let want = libc::rlimit {
        rlim_cur: lim.rlim_max,
        rlim_max: lim.rlim_max,
    };
    // SAFETY: as above.
    let set = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &want) };
    if set != 0 {
        format!("RLIMIT_MEMLOCK soft {} could not be raised", lim.rlim_cur)
    } else {
        format!("RLIMIT_MEMLOCK soft {} -> {}", lim.rlim_cur, lim.rlim_max)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cidr_parses_to_network_order() {
        // 203.0.113.0/24
        let (net, mask) = parse_cidr_be("203.0.113.0/24").unwrap();
        assert_eq!(net, u32::from_be_bytes([203, 0, 113, 0]).to_be());
        assert_eq!(mask, u32::from_be_bytes([255, 255, 255, 0]).to_be());
    }

    #[test]
    fn cidr_masks_host_bits() {
        // Host bits in the address are dropped so the stored network is canonical.
        let (net, _) = parse_cidr_be("203.0.113.7/24").unwrap();
        assert_eq!(net, u32::from_be_bytes([203, 0, 113, 0]).to_be());
    }

    #[test]
    fn host_route_keeps_all_octets() {
        let (net, mask) = parse_cidr_be("127.0.0.1/32").unwrap();
        assert_eq!(net, u32::from_be_bytes([127, 0, 0, 1]).to_be());
        assert_eq!(mask, u32::MAX.to_be());
    }

    #[test]
    fn malformed_cidr_is_a_backend_error() {
        for bad in [
            "127.0.0.1",
            "127.0.0.1/33",
            "1.2.3/24",
            "1.2.3.4.5/24",
            "x/24",
        ] {
            assert!(parse_cidr_be(bad).is_err(), "{bad} must not parse");
        }
    }

    #[test]
    fn loss_pct_scales_to_permille() {
        // The apply path converts loss_pct (0..=50) to thousandths.
        assert_eq!(25u32 * (LOSS_SCALE / 100), 250);
        assert_eq!(50u32 * (LOSS_SCALE / 100), 500);
    }

    #[test]
    fn loopback_is_detected_precisely() {
        for lo in ["lo", "lo0", "lo1"] {
            assert!(is_loopback(lo), "{lo} is loopback");
        }
        for not in [
            "veth0", "dummy0", "chaos0", "eth-test", "flow0", "silo0", "eth0",
        ] {
            assert!(!is_loopback(not), "{not} is not loopback");
        }
    }

    #[test]
    fn apply_refuses_loopback_before_touching_the_kernel() {
        // latency_spike_demo() targets `lo`; the aya datapath must refuse it
        // with an actionable error rather than attach a silent no-op. This
        // short-circuits before any env/BPF-object access, so it needs no stand.
        let backend = AyaTcBackend::new();
        let spec = NetChaosSpec::latency_spike_demo();
        assert!(is_loopback(&spec.iface));
        match backend.apply(&spec) {
            Err(NetChaosError::Backend(msg)) => assert!(
                msg.contains("loopback"),
                "error should explain the loopback refusal, got: {msg}"
            ),
            other => panic!("expected a loopback Backend error, got {other:?}"),
        }
    }
}
