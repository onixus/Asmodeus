//! asmodeus-common — the core domain of Asmodeus: roles and the RBAC matrix,
//! the run lifecycle state machine, ids, exercise tags and the root INV-0 gate.
//! No async, no I/O — pure logic that every other crate builds on.

pub mod rbac;
pub mod state;

pub use rbac::{Capability, Role};
pub use state::{RunEvent, RunState, StateError};

use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

/// Category of a scenario. Decides which RBAC capability the caller needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Category {
    /// Adversary emulation / BAS — requires `Capability::RunRedTeam`.
    RedTeam,
    /// Infrastructure chaos — requires `Capability::InjectChaos`.
    Chaos,
}

impl Category {
    pub fn required_capability(self) -> Capability {
        match self {
            Category::RedTeam => Capability::RunRedTeam,
            Category::Chaos => Capability::InjectChaos,
        }
    }

    pub fn tag(self) -> &'static str {
        match self {
            Category::RedTeam => EXERCISE_TAG_RED_TEAM,
            Category::Chaos => EXERCISE_TAG_CHAOS,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Category::RedTeam => "red_team",
            Category::Chaos => "chaos",
        }
    }
}

impl FromStr for Category {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "red_team" | "redteam" => Ok(Category::RedTeam),
            "chaos" => Ok(Category::Chaos),
            _ => Err("unknown category"),
        }
    }
}

/// Opaque run identifier, e.g. `run_98f41e2a`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RunId(pub String);

impl RunId {
    pub fn new(raw: impl Into<String>) -> Self {
        RunId(raw.into())
    }
}

impl fmt::Display for RunId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

pub const EXERCISE_TAG_RED_TEAM: &str = "🔴 [RED TEAM EXERCISE]";
pub const EXERCISE_TAG_CHAOS: &str = "⚡ [CHAOS TEST]";

// ---------------------------------------------------------------------------
// INV-0 — Synthetic-Only, the root safety invariant (see ARCHITECTURE.md §0).
// ---------------------------------------------------------------------------

/// Human-readable statement of INV-0, referenced by the DSL validator.
pub const INV_0_SYNTHETIC_ONLY: &str =
    "Asmodeus is synthetic-only: imitate techniques, never carry operational capability";

/// Whether a runner action is a synthetic marker or an operational capability.
/// Operational actions are OUT OF PROJECT SCOPE and rejected before `Injecting`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionNature {
    /// Synthetic marker or benign probe — permitted.
    Synthetic,
    /// Operational / weaponizable capability — forbidden.
    Operational,
}

impl ActionNature {
    /// INV-0 gate: only synthetic actions may execute.
    pub fn is_permitted(self) -> bool {
        matches!(self, ActionNature::Synthetic)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            ActionNature::Synthetic => "synthetic",
            ActionNature::Operational => "operational",
        }
    }
}

impl FromStr for ActionNature {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "synthetic" => Ok(ActionNature::Synthetic),
            "operational" => Ok(ActionNature::Operational),
            _ => Err("unknown action nature"),
        }
    }
}
