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

## Limits
Advanced templates, multi-hop chain editing, smart node matching, scheduled
refresh, and other cloud features are not ported in the first native release.
Unsupported URI schemes are rejected rather than silently converted.
Runtime requires no Node.js or PostgreSQL.

The native musl APK is being integrated with Nikki RS Nightly.

## OpenWrt procd runtime

Native OpenWrt APK packaging uses openwrt/subboost-rs.init, subboost-rs.config and subboost-rsctl. SQLite data and token live under /etc/subboost-rs (persistent overlay, chmod 0700, owned by nobody). The procd daemon runs as nobody on port 3000 (configurable). Run subboost-rsctl token from SSH to obtain the WebUI admin token. Do not open port 3000 on WAN. Removing the APK preserves the SQLite database.


## Compact ARM64 release profile

Release builds now use size-focused Rust code generation (`opt-level=s`, ThinLTO, one codegen unit, symbols stripped, abort on panic). Test builds retain unwind behavior. The A53 footprint job measures the exact architecture's static ELF size and native ARM64 RSS before reporting resource claims. ARM64 CI runners are not physical Cortex-A53 devices.
