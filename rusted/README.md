# SubBoost RS — native Rust + SQLite

A standalone, router-local implementation of the essential SubBoost workflow.
It is **not yet feature-equivalent** to the old Next.js/Prisma application.

## Features
- Axum HTTP server with embedded mobile WebUI and per-install admin token
- Local SQLite (WAL) profiles; tokens and data survive reboot
- Multiple HTTP(S) sources, manual refresh and bounded fetch size
- Clash YAML and common Shadowsocks, Trojan, VLESS, VMess URI sources
- Custom rules and YAML proxy/rule providers
- YAML: /api/subscriptions/{TOKEN}/config.yaml?target=clash-rs or ?target=mihomo
- Nikki RS rule-provider path isolation, name rewriting, GEO database path handling

## Run
Use Rust stable:
  cargo run --release --manifest-path rusted/Cargo.toml
Open http://127.0.0.1:3000; to obtain the admin token run:
  cargo run --manifest-path rusted/Cargo.toml -- token

Environment variables:
- SUBBOOST_BIND (default 0.0.0.0:3000)
- SUBBOOST_DB (default ./data/subboost.sqlite)
- SUBBOOST_TOKEN_FILE (default ./data/admin.token)

For OpenWrt, override data and token paths to persistent storage.
Never expose port 3000 directly on the WAN.

## Feature parity and remaining gaps
This branch adds persistent SQLite templates, scheduled refresh with bounded
backoff, per-source last-good caches, safe regex filters and more URI protocols.
The original SubBoost's full template modules, intelligent node matching,
advanced group/rule graph and rule catalog are not yet feature-equivalent.
See [PARITY.md](PARITY.md) for an auditable per-feature ledger.

Unsupported proxy types for clash-rs-minimal are rejected rather than
silently producing broken configurations. Runtime requires no Node.js or
PostgreSQL.

The native musl APK is being integrated with Nikki RS Nightly.

## OpenWrt procd runtime

Native OpenWrt APK packaging uses openwrt/subboost-rs.init, subboost-rs.config and subboost-rsctl. SQLite data and token live under /etc/subboost-rs (persistent overlay, chmod 0700, owned by nobody). The procd daemon runs as nobody on port 3000 (configurable). Run subboost-rsctl token from SSH to obtain the WebUI admin token. Do not open port 3000 on WAN. Removing the APK preserves the SQLite database.


## Compact ARM64 release profile

Release builds now use size-focused Rust code generation (`opt-level=s`, ThinLTO, one codegen unit, symbols stripped, abort on panic). Test builds retain unwind behavior. The A53 footprint job measures the exact architecture's static ELF size and native ARM64 RSS before reporting resource claims. ARM64 CI runners are not physical Cortex-A53 devices.


## Fetch-side SSRF protection

Remote HTTP(S) source refresh resolves every hostname first and pins the allowed addresses into the HTTP client. DNS changes cannot redirect a validated hostname to the router itself. Redirects and environment HTTP proxies are disabled. Requests to private, loopback and link-local destinations are rejected by default. To deliberately import from a trusted private server, set `uci set subboost-rs.main.allow_private_sources='1'; uci commit subboost-rs; /etc/init.d/subboost-rs restart`. Do not use this opt-in for untrusted subscriptions.


## Subscription metadata compatibility

The native backend now stores per-source Subscription-Userinfo traffic and expiry metadata in SQLite. Partial-source outages retain each source's last known quota values. Generated YAML responses include Subscription-Userinfo, a safe UTF-8 Content-Disposition filename and Profile-Update-Interval where an automatic refresh schedule is configured. Metadata is also exposed to the authenticated WebUI under GET /api/subscriptions/{id}/info.


## Upstream policy module catalog

The Rust engine embeds all 36 group definitions and 94 linked rule sets from the current original SubBoost registry, with deterministic source-to-Rust sync via `node rusted/scripts/sync-modules.cjs --check`. OpenWrt does not require Node.js. Groups are optional and saved per profile; this avoids unexpectedly downloading all remote MRS rule providers on an existing router after upgrade. The UI offers minimal (7), standard (14) and full presets. User-defined proxy groups in manual YAML retain priority over auto-generated group names. This ports the catalog, not the entire upstream advanced group editing workflow.
