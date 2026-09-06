//! asmodeus-cli — operator entrypoint: sign scenarios, dry-run on the polygon
//! and emit ready-to-paste cURL/CLI snippets for DevSecOps CI/CD pipelines.
fn main() {
    println!(
        "asmodeus {} — usage: asmodeus <sign|run|validate|status> (skeleton)",
        env!("CARGO_PKG_VERSION")
    );
}
