//! asmodeus-testkit — reusable polygon fixtures: synthetic canary files,
//! fake targets and an e2e harness for scenario lifecycle assertions.
pub fn canary_fixture_dir() -> &'static str {
    asmodeus_dsl::CANARY_PREFIXES[1]
}
