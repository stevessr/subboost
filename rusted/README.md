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