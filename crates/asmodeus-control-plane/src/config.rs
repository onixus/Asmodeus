//! Runtime configuration for the control plane.
//!
//! Environment parsing lives here instead of in `main`, so startup policy is
//! deterministic and unit-testable.

use std::net::SocketAddr;

const DEFAULT_LISTEN: &str = "127.0.0.1:8842";
const DEFAULT_WATCHDOG_INTERVAL_SEC: u64 = 30;
const DEFAULT_SCHEDULER_INTERVAL_SEC: u64 = 30;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControlPlaneConfig {
    pub listen_addr: SocketAddr,
    pub watchdog_interval_sec: u64,
    pub scheduler_interval_sec: u64,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ConfigError {
    #[error("invalid ASMODEUS_LISTEN address: {0}")]
    InvalidListen(String),
    #[error("{name} must be an integer number of seconds, got: {value}")]
    InvalidInterval { name: &'static str, value: String },
    #[error("{name} must be greater than zero")]
    ZeroInterval { name: &'static str },
}

impl ControlPlaneConfig {
    pub fn from_env() -> Result<Self, ConfigError> {
        Self::from_lookup(|name| std::env::var(name).ok())
    }

    fn from_lookup<F>(lookup: F) -> Result<Self, ConfigError>
    where
        F: Fn(&str) -> Option<String>,
    {
        let listen_raw = lookup("ASMODEUS_LISTEN").unwrap_or_else(|| DEFAULT_LISTEN.to_string());
        let listen_addr = listen_raw
            .parse()
            .map_err(|_| ConfigError::InvalidListen(listen_raw.clone()))?;

        let watchdog_interval_sec = parse_interval(
            "ASMODEUS_WATCHDOG_INTERVAL_SEC",
            lookup("ASMODEUS_WATCHDOG_INTERVAL_SEC"),
            DEFAULT_WATCHDOG_INTERVAL_SEC,
        )?;
        let scheduler_interval_sec = parse_interval(
            "ASMODEUS_SCHEDULER_INTERVAL_SEC",
            lookup("ASMODEUS_SCHEDULER_INTERVAL_SEC"),
            DEFAULT_SCHEDULER_INTERVAL_SEC,
        )?;

        Ok(Self {
            listen_addr,
            watchdog_interval_sec,
            scheduler_interval_sec,
        })
    }
}

fn parse_interval(
    name: &'static str,
    raw: Option<String>,
    default: u64,
) -> Result<u64, ConfigError> {
    let Some(value) = raw else {
        return Ok(default);
    };
    let parsed = value
        .parse::<u64>()
        .map_err(|_| ConfigError::InvalidInterval {
            name,
            value: value.clone(),
        })?;
    if parsed == 0 {
        return Err(ConfigError::ZeroInterval { name });
    }
    Ok(parsed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_stable() {
        let cfg = ControlPlaneConfig::from_lookup(|_| None).unwrap();
        assert_eq!(cfg.listen_addr, "127.0.0.1:8842".parse().unwrap());
        assert_eq!(cfg.watchdog_interval_sec, 30);
        assert_eq!(cfg.scheduler_interval_sec, 30);
    }

    #[test]
    fn accepts_explicit_runtime_settings() {
        let cfg = ControlPlaneConfig::from_lookup(|name| match name {
            "ASMODEUS_LISTEN" => Some("0.0.0.0:9000".into()),
            "ASMODEUS_WATCHDOG_INTERVAL_SEC" => Some("5".into()),
            "ASMODEUS_SCHEDULER_INTERVAL_SEC" => Some("7".into()),
            _ => None,
        })
        .unwrap();

        assert_eq!(cfg.listen_addr, "0.0.0.0:9000".parse().unwrap());
        assert_eq!(cfg.watchdog_interval_sec, 5);
        assert_eq!(cfg.scheduler_interval_sec, 7);
    }

    #[test]
    fn rejects_zero_and_malformed_intervals() {
        let zero = ControlPlaneConfig::from_lookup(|name| {
            (name == "ASMODEUS_WATCHDOG_INTERVAL_SEC").then(|| "0".into())
        })
        .unwrap_err();
        assert_eq!(
            zero,
            ConfigError::ZeroInterval {
                name: "ASMODEUS_WATCHDOG_INTERVAL_SEC"
            }
        );

        let malformed = ControlPlaneConfig::from_lookup(|name| {
            (name == "ASMODEUS_SCHEDULER_INTERVAL_SEC").then(|| "fast".into())
        })
        .unwrap_err();
        assert_eq!(
            malformed,
            ConfigError::InvalidInterval {
                name: "ASMODEUS_SCHEDULER_INTERVAL_SEC",
                value: "fast".into()
            }
        );
    }

    #[test]
    fn rejects_invalid_listen_address() {
        let err = ControlPlaneConfig::from_lookup(|name| {
            (name == "ASMODEUS_LISTEN").then(|| "not-an-address".into())
        })
        .unwrap_err();
        assert_eq!(err, ConfigError::InvalidListen("not-an-address".into()));
    }
}
