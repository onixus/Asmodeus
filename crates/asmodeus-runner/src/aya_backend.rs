//! Linux-stand eBPF/TC network-chaos backend (design seam for `aya`).
//!
//! Compiled only under `--features ebpf` on Linux, and **not verified on
//! macOS by construction** (ARCHITECTURE.md §8) — this crate's default build,
//! on every platform, uses [`crate::netchaos::SimBackend`].
//!
//! ## Intended implementation (D7: aya, no shelling out to `tc`/`iptables`)
//!
//! The chaos rule is installed as a `clsact` qdisc plus an eBPF
//! `SchedClassifier` attached to the target interface's egress, exactly as
//! Ferrum / BSDM attach their programs:
//!
//! 1. `aya::programs::tc::qdisc_add_clsact(&spec.iface)` — idempotent; the
//!    handle to remove on revert.
//! 2. Load the compiled BPF object (built from a `no_std` companion crate on
//!    the Linux stand) and attach a `SchedClassifier` to
//!    `TcAttachType::Egress`.
//! 3. Push the rule parameters (dst CIDR, latency, jitter, loss) into a BPF
//!    map. The program matches the reserved test-block destination and applies
//!    probabilistic `TC_ACT_SHOT` (loss) / a delay redirect (latency); it is a
//!    synthetic marker for the test segment, never a weaponised black-hole.
//! 4. `revert` detaches the classifier and removes the clsact qdisc, so
//!    `CLEANUP` leaves the interface exactly as found.
//!
//! Until the compiled BPF object is provisioned on the stand, [`apply`]
//! returns a clear [`NetChaosError::Backend`] rather than silently doing
//! nothing — an operator gets an actionable signal, and INV-0 is never at
//! risk because no partial rule is installed.
//!
//! [`apply`]: NetChaosBackend::apply

use crate::netchaos::{NetChaosBackend, NetChaosError, NetChaosSpec, RuleHandle};

/// Path to the compiled eBPF object, provisioned on the Linux stand.
const BPF_OBJECT_ENV: &str = "ASMODEUS_NETCHAOS_BPF_OBJECT";

/// eBPF/TC backend. Holds no state until a rule is applied; the real
/// implementation would carry the loaded `aya::Ebpf` handle per rule.
#[derive(Debug, Default, Clone)]
pub struct AyaTcBackend;

impl AyaTcBackend {
    pub fn new() -> Self {
        AyaTcBackend
    }
}

impl NetChaosBackend for AyaTcBackend {
    fn apply(&self, spec: &NetChaosSpec) -> Result<RuleHandle, NetChaosError> {
        // The spec is already scope/budget-validated by the session; here we
        // only need the eBPF object to install the TC classifier.
        let object = std::env::var(BPF_OBJECT_ENV).map_err(|_| {
            NetChaosError::Backend(format!(
                "aya eBPF/TC backend selected but {BPF_OBJECT_ENV} is unset — \
                 build the netchaos BPF object on the Linux stand and point this \
                 env at it (see aya_backend.rs)"
            ))
        })?;
        // TODO(linux-stand): aya clsact + SchedClassifier attach using `object`.
        Err(NetChaosError::Backend(format!(
            "aya eBPF/TC attach not yet wired on this stand (object={object}, \
             iface={}, target={})",
            spec.iface, spec.target_cidr
        )))
    }

    fn revert(&self, _handle: &RuleHandle) -> Result<(), NetChaosError> {
        // Detach classifier + remove clsact qdisc. A no-op is safe because
        // `apply` never returns a live handle on this stand yet.
        Ok(())
    }

    fn name(&self) -> &'static str {
        "aya-tc"
    }
}
