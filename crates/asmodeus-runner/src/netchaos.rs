//! Synthetic network-chaos injector — the `LATENCY_SPIKE_VM` imitation
//! (FTT §4.2.1). It perturbs a *reserved test segment only* (loopback / RFC
//! 5737 TEST-NET) with added latency, jitter and packet loss to exercise the
//! Blue Team's failover, then unconditionally reverts every rule on cleanup.
//!
//! INV-0 / D7 (ARCHITECTURE.md): the effect is a synthetic, fully reversible
//! traffic-control rule, never a weaponised disruption, and Asmodeus never
//! shells out to `tc`/`iptables`. On a Linux stand the rule is installed via
//! an `aya` eBPF/TC program (compiled in only under `--features ebpf`); on
//! every other platform — and by default — a [`SimBackend`] records the rule
//! in-process so the whole engine, scope guard and rollback contract stay
//! testable off-Linux, where aya cannot load (ARCHITECTURE.md §8).

use std::fmt;

use asmodeus_dsl::net_target_in_scope;

/// Resource envelope for one chaos rule, derived from the FTT scenario
/// (2500 ms latency / 25 % drop, §4.2.1) with headroom. A spec that exceeds
/// any bound is refused before a rule is ever installed, so an operator typo
/// cannot black-hole the test segment or run chaos unbounded.
pub const MAX_LATENCY_MS: u32 = 5_000;
pub const MAX_JITTER_MS: u32 = 1_000;
pub const MAX_LOSS_PCT: u8 = 50;
pub const MAX_DURATION_MS: u32 = 120_000;

/// Distinctive test-interface markers (defence in depth on top of the CIDR
/// scope). Loopback is matched separately and precisely; these are specific
/// enough that a substring match cannot catch a production NIC.
const IFACE_MARKERS: [&str; 4] = ["test", "chaos", "veth", "dummy"];

/// Declarative network-chaos rule. Cross-platform and dependency-free so it can
/// be validated and unit-tested anywhere; the backend turns it into a real rule
/// only on a Linux stand.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetChaosSpec {
    /// Interface to attach the rule to (must be loopback or a test iface).
    pub iface: String,
    /// Destination block to perturb — MUST be within the reserved test blocks.
    pub target_cidr: String,
    /// Added one-way latency in milliseconds.
    pub latency_ms: u32,
    /// Latency jitter (+/-) in milliseconds.
    pub jitter_ms: u32,
    /// Packet-loss percentage applied to matching flows.
    pub loss_pct: u8,
    /// How long the rule stays installed before mandatory revert.
    pub duration_ms: u32,
}

impl NetChaosSpec {
    /// A `LATENCY_SPIKE_VM`-shaped spec against loopback (safe demo default).
    pub fn latency_spike_demo() -> Self {
        NetChaosSpec {
            iface: "lo".into(),
            target_cidr: "127.0.0.1/32".into(),
            latency_ms: 2_500,
            jitter_ms: 250,
            loss_pct: 25,
            duration_ms: 5_000,
        }
    }

    /// INV-0 + budget gate. Confines the rule to the reserved test blocks and a
    /// test interface, and refuses anything over budget — all before a backend
    /// touches the kernel.
    pub fn validate(&self) -> Result<(), NetChaosError> {
        if !net_target_in_scope(&self.target_cidr) {
            return Err(NetChaosError::OutOfScope(self.target_cidr.clone()));
        }
        if !iface_in_scope(&self.iface) {
            return Err(NetChaosError::IfaceOutOfScope(self.iface.clone()));
        }
        if self.latency_ms > MAX_LATENCY_MS {
            return Err(NetChaosError::BudgetExceeded(format!(
                "latency_ms={} (max {MAX_LATENCY_MS})",
                self.latency_ms
            )));
        }
        if self.jitter_ms > MAX_JITTER_MS {
            return Err(NetChaosError::BudgetExceeded(format!(
                "jitter_ms={} (max {MAX_JITTER_MS})",
                self.jitter_ms
            )));
        }
        if self.loss_pct > MAX_LOSS_PCT {
            return Err(NetChaosError::BudgetExceeded(format!(
                "loss_pct={} (max {MAX_LOSS_PCT})",
                self.loss_pct
            )));
        }
        if self.duration_ms == 0 || self.duration_ms > MAX_DURATION_MS {
            return Err(NetChaosError::BudgetExceeded(format!(
                "duration_ms={} (allowed 1..={MAX_DURATION_MS})",
                self.duration_ms
            )));
        }
        Ok(())
    }
}

/// True iff `iface` is a loopback or an explicit test interface.
fn iface_in_scope(iface: &str) -> bool {
    if iface.is_empty() || iface.len() > 15 {
        return false; // IFNAMSIZ is 16 incl. NUL
    }
    // Loopback: exactly `lo`, or `lo` followed by an index (`lo`, `lo0`, ...).
    // Matched precisely so it can't accept `flow0`/`silo0` as a loose substring.
    let is_loopback = iface == "lo"
        || iface
            .strip_prefix("lo")
            .is_some_and(|rest| !rest.is_empty() && rest.bytes().all(|b| b.is_ascii_digit()));
    is_loopback || IFACE_MARKERS.iter().any(|m| iface.contains(m))
}

/// Why a chaos rule was refused or failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetChaosError {
    /// Target CIDR is outside the reserved test blocks (INV-0 blast radius).
    OutOfScope(String),
    /// Interface is not a loopback/test interface.
    IfaceOutOfScope(String),
    /// A field is over its resource budget.
    BudgetExceeded(String),
    /// The backend failed to install or revert the rule.
    Backend(String),
}

impl fmt::Display for NetChaosError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NetChaosError::OutOfScope(c) => {
                write!(f, "target out of net scope (not a test block): {c}")
            }
            NetChaosError::IfaceOutOfScope(i) => write!(f, "interface out of scope: {i}"),
            NetChaosError::BudgetExceeded(d) => write!(f, "resource budget exceeded: {d}"),
            NetChaosError::Backend(e) => write!(f, "netchaos backend error: {e}"),
        }
    }
}

impl std::error::Error for NetChaosError {}

/// Opaque handle to an installed rule, returned by a backend on apply and
/// consumed on revert. Carries whatever the backend needs to undo the rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleHandle {
    pub iface: String,
    pub target_cidr: String,
    /// Backend-defined identifier (e.g. a qdisc handle on Linux).
    pub token: u64,
}

/// A pluggable network-chaos backend. The Linux stand implements this with
/// `aya`; the default [`SimBackend`] records rules in-process.
pub trait NetChaosBackend {
    /// Install the rule. Must be a no-op on the host beyond the returned
    /// handle if it returns `Err`.
    fn apply(&self, spec: &NetChaosSpec) -> Result<RuleHandle, NetChaosError>;
    /// Remove a previously installed rule. Reverting an unknown handle is an
    /// error, never a panic.
    fn revert(&self, handle: &RuleHandle) -> Result<(), NetChaosError>;
    /// Human name for logs.
    fn name(&self) -> &'static str;
}

/// In-process backend: records applied rules and drops them on revert. Used off
/// Linux and in every unit test, so the scope guard and mandatory-rollback
/// contract are exercised without touching a real kernel.
#[derive(Debug, Default, Clone)]
pub struct SimBackend {
    installed: std::sync::Arc<std::sync::Mutex<Vec<RuleHandle>>>,
    next_token: std::sync::Arc<std::sync::atomic::AtomicU64>,
}

impl SimBackend {
    pub fn new() -> Self {
        Self::default()
    }

    /// Rules currently installed (for tests / operator introspection). A clean
    /// run leaves this empty — proof the chaos carried no residual effect.
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn active_rules(&self) -> Vec<RuleHandle> {
        self.installed.lock().expect("sim lock").clone()
    }
}

impl NetChaosBackend for SimBackend {
    fn apply(&self, spec: &NetChaosSpec) -> Result<RuleHandle, NetChaosError> {
        let token = self
            .next_token
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let handle = RuleHandle {
            iface: spec.iface.clone(),
            target_cidr: spec.target_cidr.clone(),
            token,
        };
        self.installed
            .lock()
            .expect("sim lock")
            .push(handle.clone());
        Ok(handle)
    }

    fn revert(&self, handle: &RuleHandle) -> Result<(), NetChaosError> {
        let mut rules = self.installed.lock().expect("sim lock");
        let before = rules.len();
        rules.retain(|r| r.token != handle.token);
        if rules.len() == before {
            return Err(NetChaosError::Backend(format!(
                "no such rule token={}",
                handle.token
            )));
        }
        Ok(())
    }

    fn name(&self) -> &'static str {
        "sim"
    }
}

/// A live chaos rule with a guaranteed rollback. Applying goes through
/// [`NetChaosSpec::validate`] first; dropping the session reverts the rule even
/// on panic/early return, so `CLEANUP` (D7) can never be skipped.
pub struct NetChaosSession<'b, B: NetChaosBackend> {
    backend: &'b B,
    handle: Option<RuleHandle>,
}

impl<'b, B: NetChaosBackend> NetChaosSession<'b, B> {
    /// Validate the spec, then install the rule through `backend`.
    pub fn start(backend: &'b B, spec: &NetChaosSpec) -> Result<Self, NetChaosError> {
        spec.validate()?;
        let handle = backend.apply(spec)?;
        tracing::info!(
            iface = %handle.iface,
            target = %handle.target_cidr,
            backend = backend.name(),
            "netchaos rule installed"
        );
        Ok(NetChaosSession {
            backend,
            handle: Some(handle),
        })
    }

    /// The installed rule handle, while the session is live.
    pub fn handle(&self) -> Option<&RuleHandle> {
        self.handle.as_ref()
    }

    /// Explicitly revert now. Idempotent: a second call (or the `Drop` guard)
    /// is a no-op.
    pub fn revert(&mut self) -> Result<(), NetChaosError> {
        if let Some(handle) = self.handle.take() {
            self.backend.revert(&handle)?;
            tracing::info!(target = %handle.target_cidr, "netchaos rule reverted");
        }
        Ok(())
    }
}

impl<B: NetChaosBackend> Drop for NetChaosSession<'_, B> {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.take() {
            // Mandatory rollback — best effort on drop; log but never panic.
            if let Err(e) = self.backend.revert(&handle) {
                tracing::error!(error = %e, "netchaos rollback on drop FAILED");
            }
        }
    }
}

/// The default backend for this platform. On a Linux stand built with
/// `--features ebpf` this is the aya/TC backend; otherwise the in-process
/// simulator (which is also what every host uses by default).
#[cfg(all(target_os = "linux", feature = "ebpf"))]
pub fn default_backend() -> crate::aya_backend::AyaTcBackend {
    crate::aya_backend::AyaTcBackend::new()
}

/// The default backend for this platform (simulator).
#[cfg(not(all(target_os = "linux", feature = "ebpf")))]
pub fn default_backend() -> SimBackend {
    SimBackend::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn demo_spec_validates() {
        assert!(NetChaosSpec::latency_spike_demo().validate().is_ok());
    }

    #[test]
    fn out_of_scope_target_is_refused() {
        let mut spec = NetChaosSpec::latency_spike_demo();
        spec.target_cidr = "10.0.0.0/8".into();
        assert!(matches!(spec.validate(), Err(NetChaosError::OutOfScope(_))));
    }

    #[test]
    fn production_iface_is_refused() {
        let mut spec = NetChaosSpec::latency_spike_demo();
        spec.iface = "eth0".into();
        assert!(matches!(
            spec.validate(),
            Err(NetChaosError::IfaceOutOfScope(_))
        ));
        // en0 (macOS NIC) is likewise refused.
        spec.iface = "en0".into();
        assert!(matches!(
            spec.validate(),
            Err(NetChaosError::IfaceOutOfScope(_))
        ));
    }

    #[test]
    fn iface_scope_is_precise_not_loose_substring() {
        // Loopback and its indexed forms (lo0 is the macOS loopback) pass.
        for ok in ["lo", "lo0", "lo1", "veth7", "chaos0", "eth-test"] {
            assert!(iface_in_scope(ok), "{ok} should be in scope");
        }
        // Names that merely *contain* "lo" must NOT pass — the old loose
        // substring check wrongly accepted these.
        for bad in ["flow0", "silo0", "velo1", "eth0", "en0", "wlan0"] {
            assert!(!iface_in_scope(bad), "{bad} must be out of scope");
        }
    }

    #[test]
    fn over_budget_specs_are_refused() {
        for mutate in [
            (|s: &mut NetChaosSpec| s.latency_ms = MAX_LATENCY_MS + 1) as fn(&mut NetChaosSpec),
            |s| s.jitter_ms = MAX_JITTER_MS + 1,
            |s| s.loss_pct = MAX_LOSS_PCT + 1,
            |s| s.duration_ms = MAX_DURATION_MS + 1,
            |s| s.duration_ms = 0,
        ] {
            let mut spec = NetChaosSpec::latency_spike_demo();
            mutate(&mut spec);
            assert!(matches!(
                spec.validate(),
                Err(NetChaosError::BudgetExceeded(_))
            ));
        }
    }

    #[test]
    fn session_applies_and_reverts_leaving_no_residue() {
        let backend = SimBackend::new();
        let spec = NetChaosSpec::latency_spike_demo();
        {
            let session = NetChaosSession::start(&backend, &spec).unwrap();
            assert!(session.handle().is_some());
            assert_eq!(backend.active_rules().len(), 1);
        } // dropped here -> mandatory revert
        assert!(
            backend.active_rules().is_empty(),
            "rule must be reverted on drop (D7 CLEANUP)"
        );
    }

    #[test]
    fn explicit_revert_is_idempotent() {
        let backend = SimBackend::new();
        let spec = NetChaosSpec::latency_spike_demo();
        let mut session = NetChaosSession::start(&backend, &spec).unwrap();
        session.revert().unwrap();
        assert!(backend.active_rules().is_empty());
        // Second revert (and the Drop) must be a clean no-op.
        session.revert().unwrap();
    }

    #[test]
    fn invalid_spec_never_installs_a_rule() {
        let backend = SimBackend::new();
        let mut spec = NetChaosSpec::latency_spike_demo();
        spec.target_cidr = "0.0.0.0/0".into();
        assert!(NetChaosSession::start(&backend, &spec).is_err());
        assert!(
            backend.active_rules().is_empty(),
            "a refused spec must not touch the backend"
        );
    }

    #[test]
    fn reverting_unknown_handle_errors_without_panic() {
        let backend = SimBackend::new();
        let bogus = RuleHandle {
            iface: "lo".into(),
            target_cidr: "127.0.0.1/32".into(),
            token: 999,
        };
        assert!(matches!(
            backend.revert(&bogus),
            Err(NetChaosError::Backend(_))
        ));
    }
}
