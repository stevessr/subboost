# SubBoost RS parity ledger (2026-11-10)

Goal: full user-visible equivalence to upstream SubBoost, with local SQLite
and a small native daemon suitable for Cortex-A53 OpenWrt routers.

"Implemented" is not the same as "equivalent". Each row must gain equivalent
configuration output and automated black-box coverage before marking parity.

| Domain | Upstream location | Rust RS state | Proof / next work |
| --- | --- | --- | --- |
| Profiles create/edit/list/delete | local/src/lib/subscription-service.ts | Core implemented | Rust store/WebUI tests, API smoke |
| Subscription bearer tokens/rotation | local/src/lib/subscription-service.ts | Core implemented | Old URL invalidation test |
| Last-good subscription cache | packages/server-core/src/subscription/refresh-node-snapshot.ts | Partial | Per-source HTTP fallback, atomic revisions; upstream source metadata not fully migrated |
| Scheduled updates | local/src/lib/auto-update-service.ts | Partial | Persistent 360s+ schedule, serialized worker, exponential backoff; upstream failure-state and quotas more sophisticated |
| Templates | local/src/lib/template-service.ts | Partial | Three native presets + custom YAML saved in SQLite; upstream template schema/modules/built-ins not fully migrated |
| Node name regex include/exclude | packages/core/src/subscription/node-name-filter.ts | Implemented core | Bounded linear-time Rust regex, persisted settings; origin-name semantics differ for renamed nodes |
| Protocol URI parsing | packages/core/src/parser/protocols/* | Partial | SS/VMess/VLESS/Trojan/Hysteria2/TUIC/AnyTLS/SSR/WireGuard; SS SIP002 plugins, VMess JSON/URI transport options, Shadowrocket VLESS, TLS/Reality defaults and WS Early Data improved in PR #9; advanced formats and full upstream transport semantics remain incomplete |
| Clash YAML proxy import | packages/core/src/parser/clash-yaml.ts | Partial | Preserves proxy entries, strips remote dialer control; alternate Clash field formats incomplete |
| Built-in region and services groups | packages/core/src/generator/proxy-group-modules.ts | Partial | 36 upstream modules and 94 MRS rules now embedded and opt-in; advanced per-module settings, rule edits and semantics still need cross-output fixtures |
| Custom proxy group graph | packages/core/src/generator/proxy-groups.ts | Partial | Manual YAML custom groups preserved; automatic region filter, module, health-check and reference validation not equivalent |
| Dialer chain and relays | packages/core/src/generator/chain.ts | Missing native UI/generator | Advanced manual YAML may work, not full editing semantics |
| Rule order and builtin rule edits | packages/core/src/generator/rules.ts | Partial | Manual ordered rule lines; full rule module editing and rule-source support pending |
| Remote MRS rule providers | packages/core/src/generator/clash-rs.ts | Partial | Namespace, path, DNS refs and collision handling; need semantic fixtures with upstream output |
| DNS2, GeoIP and GeoSite | packages/core/src/generator/dns.ts | Partial | Basic DB path, provider reference rewrites, not full defaults |
| Node smart matching/rename | packages/core/src/node-identity.ts | Missing | Need persistent stable identity and rename/share matching |
| Subscription-info headers, expiry, quota | packages/server-core/src/subscription/response-headers.ts | Partial | Per-source traffic/expiry metadata + outbound Subscription-Userinfo and update interval; needs profile page URL/plan name and full upstream merge rules |
| Rule catalog lookup/detection | local/app/api/rules/* | Partial | Authenticated search across embedded 94 MRS rules + WebUI module selection; no complete upstream rule-index, remote discovery/detection, or index auto-update |
| Shared template import/export | local/app/api/templates/* | Partial | Versioned native JSON import/export (v1) and WebUI upload/download added; original Next.js share schema still not fully compatible |
| Admin login/session/device management | local/app/api/auth/* | Different design | Router-local bearer token instead of upstream username/password sessions |
| SSRF / URL pinning | packages/server-core/src/subscription/ssrf-ip.ts | Core implemented | Public IP checks + pinned DNS, no redirects, explicit private source opt-in |
| Reproducible ARM64 size/RSS tests | N/A | Implemented in integration PR | GitHub-hosted ARM64, not physical Cortex-A53 |
| OpenWrt native APK / procd | Nikki RS packaging | Released v0.1; parity branch pending | APK only on x86_64 and supported ARM64 targets |

## Compatibility requirements

1. Compare serialized YAML semantics for each fixture against the upstream
   generateClashYaml implementation in packages/core/src/generator/index.ts.
   Compare both Mihomo and clash-rs targets, ignoring cosmetic YAML differences.
2. Test all supported URI protocols with realistic edge cases and actual
   clash-rs-minimal -t smoke checks, not only YAML syntax.
3. Run source refresh race, partial outage, token rotation, filter, database
   migration and schedule-failure tests.
4. Repeat RSS/peak RSS for 1k, 3k and 10k nodes on native ARM64, and run
   final confirmation on physical Cortex-A53 hardware before making CPU claims.
5. Keep native APK format and the previously shipped database backwards
   compatible. Never delete persistent /etc/subboost-rs data on uninstall.

## Resource test baseline (not the same as router measurements)

The published nightly SubBoost Rust v0.1 aarch64_cortex-a53 APK was
2,888,609 bytes; the full Nikki RS archive is larger. Initial native
ARM64 runner testing showed 5,068 KiB idle RSS and 24,704 KiB RSS with
1000 nodes. Size-optimized branch builds differ and must be remeasured
after each feature batch. Run the paired Nikki RS PR's
SubBoost Cortex-A53 footprint Action for exact data.

**Do not label this port feature-complete while critical rows are Partial
or Missing.** The Rust backend and Next.js/Prisma app remain separate
products until their behavior converges.

## Incremental parser parity gate (PR #9)

- Canonical shared fixtures live at `rusted/data/uri-parity-fixtures.json`.
- Original TypeScript parser assertion: `packages/core/src/parser/protocols/rs-parity.test.ts`.
- Native Rust assertion: `rusted/src/parser.rs::tests::shared_upstream_uri_contract`.
- `SubBoost RS (Rust + SQLite)` CI now gates MUSL artifacts on both parsers.
- **As of this change, no workflow runs are associated with the PR head**. These checks are pending execution; parity is not certified and this PR must remain unmerged.
- This fixture subset is a compatibility seed, not a claim of full parity. Broaden the corpus to all protocols, provider outputs, DNS/rule semantics, templates, node identity, profile lifecycle and UI/API before a 1:1 release.

## SS/Trojan compatibility regression additions

The shared fixture contract now includes SS plaintext URL credentials with
embedded colons, percent-encoded SIP002 base64 padding and UTF-8 labels.
It compares UDP defaults and Trojan SNI in addition to transport options.
This is intentionally a partial projection, not an assertion that all
generated YAML is byte-identical or semantically equivalent.

The shared URI fixture corpus is expanded in subsequent commits. Passing any
fixture subset must not be treated as full protocol or product equivalence.

## SIP002 plugin compatibility batch

The shared fixture corpus includes SIP002 test cases, including
SIP002 obfs-local normalization with host/mode and UDP-over-TCP/TFO flags.
The Rust URI parser additionally accepts empty boolean query values and bare
plugin keys like the original TypeScript parser. These changes are committed,
but CI verification is still pending; do not mark protocol parity complete.

## Current parity test expansion (PR #9)

- 17 canonical URI fixtures shared by the Rust and original TypeScript parsers.
- 1 canonical module-rule ordering fixture shared by both implementations.
- VLESS: ordinary, Shadowrocket base64 authority, implicit TLS, Reality, WS, gRPC, HTTP, H2 and HTTPUpgrade paths (subset of upstream options).
- VMess: JSON base64 + URI style, WS Early Data, gRPC, HTTP transport and TLS metadata (other upstream formats remain).
- SS: plaintext/base64 credential variants, obfs-local, UDP-over-TCP and TCP fast-open.
- Trojan: TCP/WS/gRPC/HTTPUpgrade options, SNI and default-credential handling.
- Config: enabled final module now owns exactly one terminal MATCH, with a separate Mihomo canonical ordering test; clash-rs provider namespace adaptation has its own tests.
- Rule catalog: local authenticated search of the embedded 94-rule MRS subset and one-click module selection in the WebUI. This is **not** a replacement for the original remote rule index or detection API.
- CI includes a JavaScript syntax check for the native WebUI and JSON fixture structure checks before installing npm dependencies. Rust tests, original TypeScript tests, x86_64/aarch64 MUSL builds and runtime core smoke tests still require actual CI execution.

**Verification gate:** This branch has not produced any GitHub Actions workflow runs.
All added tests are authored but not yet green. Keep PR #9 unmerged and out of
Nightly until the checks and native clash-rs tests have run successfully.

## Portable native templates (PR #9)

The native template API now supports `GET /api/templates/{id}/export` and
`POST /api/templates/import` with a versioned JSON envelope:

```json
{"format":"subboost-rs-template","version":1,"name":"Example","description":"","manual_yaml":"","rules_text":"MATCH,Proxy"}
```

Imports validate the version and existing template limits before inserting a
new SQLite record; exports exclude the internal ID and timestamps. WebUI
upload/download buttons handle the same format. The native portability format
is not a claim of equivalence to the original Next.js shared-template schema.
Unit and API regression tests were added but have not executed through CI.
