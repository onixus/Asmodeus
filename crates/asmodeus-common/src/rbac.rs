//! RBAC engine — the access matrix from FTT §3, enforced in the control-plane
//! (never delegated to the upstream APEX gateway). The CISO/SecOps/Auditor
//! invariant: no launch or injection, ever, even with a valid JWT.

use std::str::FromStr;

use serde::{Deserialize, Serialize};

/// Roles recognised by the system, carried in the `X-Apex-Role` header.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    Admin,
    RedTeam,
    #[serde(rename = "devsecops")]
    DevSecOps,
    Ciso,
    SecOps,
    Auditor,
}

impl FromStr for Role {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "admin" => Ok(Role::Admin),
            "red_team" | "redteam" => Ok(Role::RedTeam),
            "devsecops" => Ok(Role::DevSecOps),
            "ciso" => Ok(Role::Ciso),
            "secops" | "soc" | "blue_team" => Ok(Role::SecOps),
            "auditor" => Ok(Role::Auditor),
            _ => Err(()),
        }
    }
}

impl Role {
    /// Canonical wire spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            Role::Admin => "admin",
            Role::RedTeam => "red_team",
            Role::DevSecOps => "devsecops",
            Role::Ciso => "ciso",
            Role::SecOps => "secops",
            Role::Auditor => "auditor",
        }
    }
}

/// Actions guarded by RBAC.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Capability {
    /// Launch adversary-emulation (Red Team) scenarios.
    RunRedTeam,
    /// Inject infrastructure chaos (DevSecOps).
    InjectChaos,
    /// View telemetry, reports and MTTD/MTTR.
    ViewReports,
    /// Create / edit scenarios in the catalog.
    ManageScenarios,
}

impl Role {
    /// The RBAC matrix (FTT §3). This is the single source of truth; the HTTP
    /// layer maps a `false` here to `403 Forbidden`.
    pub fn can(self, cap: Capability) -> bool {
        use Capability::*;
        use Role::*;
        match (self, cap) {
            // Superadmin: everything.
            (Admin, _) => true,

            // Red Team operator.
            (RedTeam, RunRedTeam) => true,
            (RedTeam, ViewReports) => true,
            (RedTeam, ManageScenarios) => true,
            (RedTeam, InjectChaos) => false,

            // DevSecOps engineer.
            (DevSecOps, InjectChaos) => true,
            (DevSecOps, ViewReports) => true,
            (DevSecOps, ManageScenarios) => true,
            (DevSecOps, RunRedTeam) => false,

            // CISO / SecOps / Auditor: read-only. INV of FTT §3.
            (Ciso, ViewReports) => true,
            (SecOps, ViewReports) => true,
            (Auditor, ViewReports) => true,
            (Ciso, _) => false,
            (SecOps, _) => false,
            (Auditor, _) => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_roles() {
        assert_eq!("red_team".parse(), Ok(Role::RedTeam));
        assert_eq!("CISO".parse(), Ok(Role::Ciso));
        assert!("nobody".parse::<Role>().is_err());
    }

    #[test]
    fn admin_can_do_everything() {
        for cap in [
            Capability::RunRedTeam,
            Capability::InjectChaos,
            Capability::ViewReports,
            Capability::ManageScenarios,
        ] {
            assert!(Role::Admin.can(cap));
        }
    }

    #[test]
    fn separation_of_duties() {
        assert!(Role::RedTeam.can(Capability::RunRedTeam));
        assert!(!Role::RedTeam.can(Capability::InjectChaos));
        assert!(Role::DevSecOps.can(Capability::InjectChaos));
        assert!(!Role::DevSecOps.can(Capability::RunRedTeam));
    }

    #[test]
    fn ciso_secops_auditor_are_read_only() {
        for role in [Role::Ciso, Role::SecOps, Role::Auditor] {
            assert!(role.can(Capability::ViewReports));
            assert!(!role.can(Capability::RunRedTeam));
            assert!(!role.can(Capability::InjectChaos));
            assert!(!role.can(Capability::ManageScenarios));
        }
    }
}
