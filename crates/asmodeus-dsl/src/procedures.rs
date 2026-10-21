//! Versioned MITRE first-wave **procedure corpus** (S02).
//!
//! S01 pinned the taxonomy and the per-scenario fidelity model. S02 adds a
//! small, *fixed-before-run* corpus of six reproducible synthetic procedure
//! slots — the unit an operator actually executes on a stand. Each slot is
//! honest about three separate things that reports routinely conflate:
//!
//! * which ATT&CK technique(s) it *references* and in what **role** (a full
//!   behavioural candidate vs. a measurable precondition/signal only — `T1611`
//!   is signal-only and never a promise of a real host escape);
//! * at what [`ExecutionMode`] it can run, which bounds the [`Fidelity`] it may
//!   claim (marker/replay are indicator-only; only behavioural reaches a
//!   behavioural signal — the same gate as S01);
//! * whether it is even *supported* in the current environment. An unsupported
//!   slot is `NOT_RUN`; it stays in the coverage **denominator** and is never
//!   dropped to manufacture a PASS.
//!
//! This module is pure data + logic (no I/O). The runner side
//! (`asmodeus-runner::procedures`) owns the injectors, the safety harness
//! (scope rejection, timeout, cancellation, kill switch, resource budget,
//! mandatory cleanup) and the per-attempt manifest. INV-0 holds throughout:
//! every slot is synthetic and confined to canary filesystem / reserved
//! loopback+RFC 5737 test scope.

use serde::Serialize;

use crate::fidelity::{Fidelity, Platform};
use crate::mitre::ATTACK_VERSION;

/// Identifier of this frozen corpus. Bumping it is a corpus revision: it
/// requires an impact review and a re-run of the affected procedures (the
/// results of an old corpus version do not carry over to a new one).
pub const CORPUS_VERSION: &str = "asmodeus-mitre-wave1-v2";

/// How faithfully a procedure is exercised on a given run. This bounds the
/// fidelity it may claim and keeps a cheap local run from masquerading as a
/// representative behavioural one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionMode {
    /// Creates/reads a synthetic marker or command record. Indicator-only.
    Marker,
    /// Re-emits a previously captured observation set without re-running the
    /// live behaviour (detector regression without a stand). Indicator-only —
    /// a replayed artifact is not fresh behaviour.
    Replay,
    /// Runs a representative synthetic behaviour confined to canary/loopback
    /// test scope (e.g. a real loopback round-trip to an in-process test
    /// receiver). Produces a behavioural signal — an imitation, never impact.
    Behavioral,
}

impl ExecutionMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Marker => "marker",
            Self::Replay => "replay",
            Self::Behavioral => "behavioral",
        }
    }

    /// The strongest [`Fidelity`] a result in this mode may be scored at.
    /// Marker and replay are both indicator-only; only behavioural reaches a
    /// behavioural signal. This is the single clamp that stops a marker/replay
    /// run from being read as behavioural coverage.
    pub fn fidelity_ceiling(self) -> Fidelity {
        match self {
            Self::Marker | Self::Replay => Fidelity::MarkerOnly,
            Self::Behavioral => Fidelity::Behavioral,
        }
    }
}

/// The role a referenced technique plays in a slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CandidateRole {
    /// The slot can exercise a representative behaviour of this technique
    /// (subject to its [`ExecutionMode`]).
    BehavioralCandidate,
    /// The slot can only produce a *measurable precondition or signal* related
    /// to this technique — never the technique's actual effect. `T1611` is
    /// modelled this way: reaching a test runtime socket is a precondition
    /// signal, not a host escape, and must never be read as escape coverage.
    PreconditionSignal,
}

impl CandidateRole {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::BehavioralCandidate => "behavioral_candidate",
            Self::PreconditionSignal => "precondition_signal",
        }
    }
}

/// One referenced ATT&CK technique and the role it plays in the slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct CandidateTechnique {
    pub technique_id: &'static str,
    pub role: CandidateRole,
}

/// The local resource a slot needs before it can run. Absent ⇒ the slot is
/// `NOT_RUN` (unsupported in this environment), never a silent PASS.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Requirement {
    /// Nothing beyond the canary filesystem — always runnable.
    CanaryFilesystem,
    /// An in-process loopback/RFC 5737 test receiver the harness stands up.
    LoopbackTestReceiver,
    /// A canary-scoped container admin socket supplied by a runtime stand.
    ContainerAdminSocket,
    /// A canary-scoped test runtime socket supplied by a runtime stand.
    RuntimeTestSocket,
}

/// Which capabilities the current environment offers. The default local
/// environment stands up loopback receivers but has no runtime-stand sockets,
/// so the two execution/escape slots are `NOT_RUN` unless an operator points
/// the harness at a stand.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Capabilities {
    pub loopback_receiver: bool,
    pub container_admin_socket: bool,
    pub runtime_test_socket: bool,
}

impl Capabilities {
    /// The capabilities of a plain local canary environment: loopback test
    /// receivers only. No runtime-stand sockets are fabricated.
    pub const LOCAL_CANARY: Capabilities = Capabilities {
        loopback_receiver: true,
        container_admin_socket: false,
        runtime_test_socket: false,
    };

    /// A fully provisioned stand (every capability present). Used by tests and
    /// by an operator who has wired the stand's canary-scoped sockets.
    pub const FULL_STAND: Capabilities = Capabilities {
        loopback_receiver: true,
        container_admin_socket: true,
        runtime_test_socket: true,
    };

    pub fn meets(self, req: Requirement) -> bool {
        match req {
            Requirement::CanaryFilesystem => true,
            Requirement::LoopbackTestReceiver => self.loopback_receiver,
            Requirement::ContainerAdminSocket => self.container_admin_socket,
            Requirement::RuntimeTestSocket => self.runtime_test_socket,
        }
    }
}

/// A benign paired control: what a correctly behaving defensive product should
/// do when this procedure runs, and how an operator confirms the real effect
/// (rather than trusting a green checkmark).
#[derive(Debug, Clone, Copy, Serialize)]
pub struct BenignControl {
    pub expected_product_behavior: &'static str,
    pub verification: &'static str,
}

/// Hard ceiling on what one attempt may consume. The harness refuses to exceed
/// any bound and trips into cleanup — an operator typo cannot run unbounded.
#[derive(Debug, Clone, Copy, Serialize)]
pub struct ResourceBudget {
    pub max_duration_ms: u64,
    pub max_bytes: u64,
    pub max_files: u32,
}

/// One fixed, versioned, synthetic-only procedure slot.
#[derive(Debug, Clone, Copy, Serialize)]
pub struct ProcedureSlot {
    pub slot_id: &'static str,
    pub procedure_id: &'static str,
    pub procedure_revision: u32,
    pub title: &'static str,
    /// Referenced techniques; the first is the primary. Each carries its role.
    pub techniques: &'static [CandidateTechnique],
    pub platforms: &'static [Platform],
    /// The local resource this slot needs; absent ⇒ `NOT_RUN`.
    pub requirement: Requirement,
    /// Mode achieved on a local run when the requirement is met.
    pub local_mode: ExecutionMode,
    /// Strongest mode a full runtime stand reaches. For a precondition-signal
    /// slot this stays indicator-only on purpose.
    pub stand_mode: ExecutionMode,
    pub preconditions: &'static str,
    pub expected_observables: &'static [&'static str],
    pub limitations: &'static str,
    pub safety_scope: &'static str,
    pub benign_control: BenignControl,
    pub budget: ResourceBudget,
}

impl ProcedureSlot {
    /// The primary (first) referenced technique id, if any.
    pub fn primary_technique(&self) -> Option<&'static str> {
        self.techniques.first().map(|t| t.technique_id)
    }

    /// True iff this slot can run at all in `caps`. A `false` here means the
    /// slot is `NOT_RUN` — still counted in the denominator.
    pub fn supported_in(&self, caps: Capabilities) -> bool {
        caps.meets(self.requirement)
    }

    /// The mode a local run would use given `caps`, or `None` when the slot is
    /// unsupported (`NOT_RUN`).
    pub fn planned_mode_in(&self, caps: Capabilities) -> Option<ExecutionMode> {
        self.supported_in(caps).then_some(self.local_mode)
    }
}

const SCOPE_CANARY_FS: &str = "canary filesystem sandbox (/tmp|/var/tmp/asmodeus-canary)";
const SCOPE_CANARY_NS: &str =
    "canary namespace + filesystem sandbox (namespace \"asmodeus-canary\", /tmp|/var/tmp/asmodeus-canary)";
const SCOPE_LOOPBACK: &str =
    "canary filesystem + reserved test nets only (loopback + RFC 5737 TEST-NET-1/2/3)";

/// The frozen six-slot corpus. Order is stable and part of the contract.
pub const PROCEDURE_SLOTS: &[ProcedureSlot] = &[
    // 1 — container administration command execution.
    ProcedureSlot {
        slot_id: "WAVE1-EXEC-CONTAINER",
        procedure_id: "ASMOD-WAVE1-0001",
        procedure_revision: 1,
        title: "synthetic container administration command",
        techniques: &[CandidateTechnique {
            technique_id: "T1609",
            role: CandidateRole::BehavioralCandidate,
        }],
        platforms: &[Platform::Containers, Platform::Kubernetes, Platform::Linux],
        requirement: Requirement::ContainerAdminSocket,
        local_mode: ExecutionMode::Marker,
        stand_mode: ExecutionMode::Marker,
        preconditions:
            "a canary-scoped container admin socket supplied by a runtime stand; absent on a plain host",
        expected_observables: &[
            "a synthetic exec-command record delivered to the canary admin socket",
            "an exec-into-container event raised by the runtime sensor (on a stand)",
        ],
        limitations:
            "sends a synthetic command record to a canary test socket only; contacts NO real \
             container runtime and executes nothing in a container — marker-only, not behavioural \
             coverage of T1609",
        safety_scope: SCOPE_CANARY_NS,
        benign_control: BenignControl {
            expected_product_behavior:
                "the container runtime sensor logs an administration-command / exec event for the \
                 canary namespace",
            verification:
                "confirm a runtime telemetry event references the attempt's canary command id and \
                 namespace; absence of the event is a miss, not a pass",
        },
        budget: ResourceBudget {
            max_duration_ms: 10_000,
            max_bytes: 64 * 1024,
            max_files: 4,
        },
    },
    // 2 — Unix shell execution.
    ProcedureSlot {
        slot_id: "WAVE1-EXEC-SHELL",
        procedure_id: "ASMOD-WAVE1-0002",
        procedure_revision: 2,
        title: "synthetic unix-shell command execution",
        techniques: &[CandidateTechnique {
            technique_id: "T1059.004",
            role: CandidateRole::BehavioralCandidate,
        }],
        platforms: &[Platform::Linux, Platform::Macos],
        requirement: Requirement::CanaryFilesystem,
        local_mode: ExecutionMode::Marker,
        stand_mode: ExecutionMode::Marker,
        preconditions: "writable canary directory",
        expected_observables: &[
            "a synthetic shell-command transcript written in canary scope",
        ],
        limitations:
            "records a synthetic shell-command transcript in canary scope and spawns NO real shell \
             process — marker-only in both local and stand modes; representative shell execution \
             is not implemented",
        safety_scope: SCOPE_CANARY_FS,
        benign_control: BenignControl {
            expected_product_behavior:
                "the endpoint sensor records a shell interpreter invocation with the canary command \
                 line",
            verification:
                "match the sensor's process-exec/command-line telemetry to the attempt's transcript; \
                 no telemetry means no coverage",
        },
        budget: ResourceBudget {
            max_duration_ms: 10_000,
            max_bytes: 64 * 1024,
            max_files: 4,
        },
    },
    // 3 — access to a test runtime socket (precondition/signal for T1611).
    ProcedureSlot {
        slot_id: "WAVE1-EXEC-RUNTIME-SOCKET",
        procedure_id: "ASMOD-WAVE1-0003",
        procedure_revision: 1,
        title: "synthetic test runtime-socket reachability signal",
        techniques: &[CandidateTechnique {
            technique_id: "T1611",
            role: CandidateRole::PreconditionSignal,
        }],
        platforms: &[Platform::Containers, Platform::Linux],
        requirement: Requirement::RuntimeTestSocket,
        local_mode: ExecutionMode::Marker,
        stand_mode: ExecutionMode::Marker,
        preconditions:
            "a canary-scoped test runtime socket supplied by a runtime stand; absent on a plain host",
        expected_observables: &[
            "a reachability probe delivered to the canary test runtime socket",
        ],
        limitations:
            "measures reachability of a canary test runtime socket as a PRECONDITION SIGNAL only; \
             performs NO container-to-host escape and gains NO host access — never escape coverage \
             of T1611",
        safety_scope: SCOPE_CANARY_NS,
        benign_control: BenignControl {
            expected_product_behavior:
                "the runtime sensor flags an unexpected connection to a privileged runtime socket \
                 from the canary workload",
            verification:
                "confirm the sensor reports the socket-reachability signal; this validates a \
                 detection precondition, never that an escape was performed or prevented",
        },
        budget: ResourceBudget {
            max_duration_ms: 10_000,
            max_bytes: 16 * 1024,
            max_files: 2,
        },
    },
    // 4 — HTTP beacon (web-protocol C2).
    ProcedureSlot {
        slot_id: "WAVE1-C2-HTTP-BEACON",
        procedure_id: "ASMOD-WAVE1-0004",
        procedure_revision: 1,
        title: "synthetic HTTP beacon to a loopback test receiver",
        techniques: &[CandidateTechnique {
            technique_id: "T1071.001",
            role: CandidateRole::BehavioralCandidate,
        }],
        platforms: &[Platform::Network, Platform::Linux],
        requirement: Requirement::LoopbackTestReceiver,
        local_mode: ExecutionMode::Behavioral,
        stand_mode: ExecutionMode::Behavioral,
        preconditions: "an in-scope loopback/RFC 5737 test receiver (stood up in-process locally)",
        expected_observables: &[
            "a real TCP round-trip to the loopback test receiver carrying a synthetic beacon line",
            "beacon cadence/jitter recorded in the attempt's canary log",
        ],
        limitations:
            "sends a synthetic beacon over a real loopback round-trip to an in-process test receiver \
             within reserved test scope; performs NO egress to any external or routable host and \
             carries no real C2 payload",
        safety_scope: SCOPE_LOOPBACK,
        benign_control: BenignControl {
            expected_product_behavior:
                "the network sensor records an outbound web-protocol beacon to the test receiver and \
                 (if policy applies) sinkholes it",
            verification:
                "match the sensor's connection/beacon telemetry to the attempt's destination, port \
                 and byte count on the reserved test segment",
        },
        budget: ResourceBudget {
            max_duration_ms: 15_000,
            max_bytes: 64 * 1024,
            max_files: 4,
        },
    },
    // 5 — DNS C2 pattern.
    ProcedureSlot {
        slot_id: "WAVE1-C2-DNS",
        procedure_id: "ASMOD-WAVE1-0005",
        procedure_revision: 2,
        title: "synthetic DNS C2 query pattern to a loopback test receiver",
        techniques: &[CandidateTechnique {
            technique_id: "T1071.004",
            role: CandidateRole::BehavioralCandidate,
        }],
        platforms: &[Platform::Network, Platform::Linux],
        requirement: Requirement::LoopbackTestReceiver,
        local_mode: ExecutionMode::Behavioral,
        stand_mode: ExecutionMode::Behavioral,
        preconditions: "an in-scope loopback/RFC 5737 UDP test receiver (stood up in-process locally)",
        expected_observables: &[
            "a real UDP datagram to the loopback test receiver carrying a synthetic DNS query label",
            "the synthetic query label recorded in the attempt's canary log",
        ],
        limitations:
            "emits a valid synthetic DNS TXT question over a real loopback datagram to an in-process test \
             receiver within reserved test scope; performs NO real name resolution and reaches no \
             external resolver",
        safety_scope: SCOPE_LOOPBACK,
        benign_control: BenignControl {
            expected_product_behavior:
                "the DNS/network sensor records a query to the test receiver with the synthetic C2 \
                 label and (if policy applies) RPZ-sinkholes it",
            verification:
                "match the sensor's DNS telemetry to the attempt's query label and destination on \
                 the reserved test segment",
        },
        budget: ResourceBudget {
            max_duration_ms: 15_000,
            max_bytes: 16 * 1024,
            max_files: 4,
        },
    },
    // 6 — synthetic data transfer to a test receiver (exfiltration over C2).
    ProcedureSlot {
        slot_id: "WAVE1-EXFIL-TRANSFER",
        procedure_id: "ASMOD-WAVE1-0006",
        procedure_revision: 1,
        title: "synthetic data transfer to a loopback test receiver",
        techniques: &[CandidateTechnique {
            technique_id: "T1041",
            role: CandidateRole::BehavioralCandidate,
        }],
        platforms: &[Platform::Network, Platform::Linux],
        requirement: Requirement::LoopbackTestReceiver,
        local_mode: ExecutionMode::Behavioral,
        stand_mode: ExecutionMode::Behavioral,
        preconditions: "an in-scope loopback/RFC 5737 test receiver (stood up in-process locally)",
        expected_observables: &[
            "a real TCP transfer of a synthetic canary blob to the loopback test receiver",
            "the transferred byte count recorded in the attempt's canary log",
        ],
        limitations:
            "transfers a synthetic canary blob over a real loopback round-trip to an in-process test \
             receiver within reserved test scope; NO real data leaves the host and no external \
             channel is used",
        safety_scope: SCOPE_LOOPBACK,
        benign_control: BenignControl {
            expected_product_behavior:
                "the DLP/network sensor records an outbound transfer to the test receiver and (if \
                 policy applies) blocks or quarantines it",
            verification:
                "match the sensor's transfer telemetry to the attempt's destination and byte count \
                 on the reserved test segment",
        },
        budget: ResourceBudget {
            max_duration_ms: 15_000,
            max_bytes: 256 * 1024,
            max_files: 4,
        },
    },
];

/// Look up a slot by its stable `slot_id`.
pub fn slot(slot_id: &str) -> Option<&'static ProcedureSlot> {
    PROCEDURE_SLOTS.iter().find(|s| s.slot_id == slot_id)
}

/// The honest coverage denominator: the fixed number of slots in the corpus.
/// `NOT_RUN`/unsupported slots stay in it — they are never removed to lift a
/// coverage percentage.
pub fn corpus_denominator() -> usize {
    PROCEDURE_SLOTS.len()
}

/// The ATT&CK release this corpus is scoped to (echoes the pinned taxonomy).
pub fn corpus_attack_version() -> &'static str {
    ATTACK_VERSION
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mitre::is_known_id;

    #[test]
    fn corpus_has_exactly_six_slots() {
        assert_eq!(PROCEDURE_SLOTS.len(), 6);
        assert_eq!(corpus_denominator(), 6);
    }

    #[test]
    fn slot_ids_and_procedure_ids_are_unique() {
        for field in ["slot", "procedure"] {
            let mut ids: Vec<&str> = PROCEDURE_SLOTS
                .iter()
                .map(|s| {
                    if field == "slot" {
                        s.slot_id
                    } else {
                        s.procedure_id
                    }
                })
                .collect();
            let n = ids.len();
            ids.sort_unstable();
            ids.dedup();
            assert_eq!(ids.len(), n, "duplicate {field} id in corpus");
        }
    }

    #[test]
    fn every_referenced_technique_is_pinned() {
        for s in PROCEDURE_SLOTS {
            assert!(
                !s.techniques.is_empty(),
                "{} references no technique",
                s.slot_id
            );
            for t in s.techniques {
                assert!(
                    is_known_id(t.technique_id),
                    "slot {} references unknown technique {}",
                    s.slot_id,
                    t.technique_id
                );
            }
        }
    }

    #[test]
    fn corpus_covers_the_six_wave_one_candidates() {
        let want = [
            "T1609",
            "T1059.004",
            "T1611",
            "T1071.001",
            "T1071.004",
            "T1041",
        ];
        let got: Vec<&str> = PROCEDURE_SLOTS
            .iter()
            .filter_map(|s| s.primary_technique())
            .collect();
        for w in want {
            assert!(got.contains(&w), "corpus is missing candidate {w}");
        }
        assert_eq!(got.len(), want.len());
    }

    #[test]
    fn t1611_is_precondition_signal_only() {
        let s = slot("WAVE1-EXEC-RUNTIME-SOCKET").unwrap();
        let t = s
            .techniques
            .iter()
            .find(|t| t.technique_id == "T1611")
            .unwrap();
        assert_eq!(t.role, CandidateRole::PreconditionSignal);
        // A precondition-signal slot never reaches behavioural, even on a stand.
        assert_eq!(s.stand_mode, ExecutionMode::Marker);
        assert_eq!(s.stand_mode.fidelity_ceiling(), Fidelity::MarkerOnly);
    }

    #[test]
    fn marker_and_replay_never_claim_behavioral() {
        assert_eq!(
            ExecutionMode::Marker.fidelity_ceiling(),
            Fidelity::MarkerOnly
        );
        assert_eq!(
            ExecutionMode::Replay.fidelity_ceiling(),
            Fidelity::MarkerOnly
        );
        assert_eq!(
            ExecutionMode::Behavioral.fidelity_ceiling(),
            Fidelity::Behavioral
        );
        assert!(!ExecutionMode::Marker.fidelity_ceiling().claims_behavioral());
        assert!(!ExecutionMode::Replay.fidelity_ceiling().claims_behavioral());
        assert!(ExecutionMode::Behavioral
            .fidelity_ceiling()
            .claims_behavioral());
    }

    #[test]
    fn every_slot_has_a_benign_control_and_limitation() {
        for s in PROCEDURE_SLOTS {
            assert!(
                !s.limitations.is_empty(),
                "{} needs a limitation",
                s.slot_id
            );
            assert!(
                !s.benign_control.expected_product_behavior.is_empty()
                    && !s.benign_control.verification.is_empty(),
                "{} needs a benign paired control",
                s.slot_id
            );
            assert!(
                !s.expected_observables.is_empty(),
                "{} needs expected observables",
                s.slot_id
            );
        }
    }

    #[test]
    fn default_local_env_leaves_runtime_stand_slots_not_run() {
        let caps = Capabilities::LOCAL_CANARY;
        // Container-exec and runtime-socket need a stand socket: NOT_RUN locally.
        assert!(!slot("WAVE1-EXEC-CONTAINER").unwrap().supported_in(caps));
        assert!(!slot("WAVE1-EXEC-RUNTIME-SOCKET")
            .unwrap()
            .supported_in(caps));
        // Shell + the three network slots run locally.
        assert!(slot("WAVE1-EXEC-SHELL").unwrap().supported_in(caps));
        assert!(slot("WAVE1-C2-HTTP-BEACON").unwrap().supported_in(caps));
        assert!(slot("WAVE1-C2-DNS").unwrap().supported_in(caps));
        assert!(slot("WAVE1-EXFIL-TRANSFER").unwrap().supported_in(caps));
        // Denominator is unaffected by support.
        let supported = PROCEDURE_SLOTS
            .iter()
            .filter(|s| s.supported_in(caps))
            .count();
        assert_eq!(supported, 4);
        assert_eq!(corpus_denominator(), 6);
    }

    #[test]
    fn full_stand_supports_all_slots() {
        let caps = Capabilities::FULL_STAND;
        assert!(PROCEDURE_SLOTS.iter().all(|s| s.supported_in(caps)));
    }

    #[test]
    fn planned_mode_tracks_support() {
        let caps = Capabilities::LOCAL_CANARY;
        assert_eq!(
            slot("WAVE1-C2-HTTP-BEACON").unwrap().planned_mode_in(caps),
            Some(ExecutionMode::Behavioral)
        );
        assert_eq!(
            slot("WAVE1-EXEC-SHELL").unwrap().planned_mode_in(caps),
            Some(ExecutionMode::Marker)
        );
        assert_eq!(
            slot("WAVE1-EXEC-CONTAINER").unwrap().planned_mode_in(caps),
            None
        );
    }

    #[test]
    fn corpus_serializes_to_json() {
        // The whole static corpus is report-ready without hand-rolling JSON.
        let v = serde_json::to_value(PROCEDURE_SLOTS).unwrap();
        assert_eq!(v.as_array().unwrap().len(), 6);
        assert_eq!(v[0]["slot_id"], "WAVE1-EXEC-CONTAINER");
        assert_eq!(v[0]["techniques"][0]["role"], "behavioral_candidate");
    }
}
