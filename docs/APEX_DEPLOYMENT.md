# APEX deployment contract 1.0 — asmodeus

The root `apex-deploy.json` declares the installation method and required parameter names.
The common schema is `apex-contract/deployment/apex-deploy.schema.json`.
APEX reserves one dedicated server for one product, archives the selected Git SHA,
and only reports Docker readiness after the declared service's real healthcheck.

Mode: **docker**. Required parameters: STAND_JWT_SECRET.
Also provide `APEX_GATEWAY_URL` and `APEX_SERVICE_URL`. They declare the integration
addresses; domain-specific adapters and credentials still require operator configuration.
Secrets must never be committed. The platform's `deployment/install.py` asks for SSH
key paths and lets OpenSSH request passwords/passphrases in the terminal.
Environment values are entered with hidden input and written to a protected
`/etc/apex/asmodeus.env` on the target only on explicit first-time setup.

Recipe: `stand/compose.apex.yml`; readiness service: `asmodeus-control-plane`.
Run `docker compose --env-file /etc/apex/asmodeus.env -p apex-asmodeus -f stand/compose.apex.yml config --quiet` before installation.
Published images should be verified and selected by digest. Build/healthcheck validation
is not physical-server acceptance. Root or prepared `/opt/apex` and Docker permissions
are required. A host reverse proxy with trusted TLS must expose loopback-bound APIs
to APEX; do not publish unauthenticated management ports.

This recipe contains only Asmodeus key initialization, runner and control plane. It does not deploy a second APEX console, Gateway or ClickHouse. STAND_JWT_SECRET must match the authenticated APEX adapter configuration.
