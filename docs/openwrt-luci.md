# OpenWrt / LuCI and Nikki RS integration

SubBoost's self-hosted server needs Node.js 24+ and PostgreSQL. The
architecture-independent LuCI adapter uses an existing hosted or self-hosted
SubBoost deployment instead of attempting to run Next.js/Prisma on the router.

## Installation

Use GitHub Actions > OpenWrt LuCI packages > Run workflow. Download a package
for the OpenWrt release family in use:

- OpenWrt 24.10.x: IPK (opkg install /tmp/luci-app-subboost_*.ipk).
- OpenWrt 25.12.x: APK (apk add --allow-untrusted /tmp/luci-app-subboost-*.apk).

The workflow builds against the OpenWrt SDK for both x86_64 and
aarch64_cortex-a53 and uploads build artifacts. The package itself contains
only architecture-independent LuCI resources.

Open **Services > SubBoost**, enter your hosted or self-hosted SubBoost
web interface URL, and paste each **generated** subscription's final YAML
URL, for example:

    https://your-subboost.example/api/subscriptions/YOUR_TOKEN/config.yaml

Save & Apply, then click **Sync to Nikki RS**. When Nikki RS is installed,
the LuCI adapter creates or updates a tagged Nikki RS subscription with
User-Agent set to clash-rs and preference set to remote. It **does not**
change the active profile or start/restart the proxy core intentionally.
Choose the profile in **Nikki RS > App Config** and update through Nikki's
existing subscription update mechanism.

Recent versions of Nikki RS also provide a **Nikki RS > SubBoost** page for
direct URL import without installing this package.

## Security and compatibility

Generated URLs are bearer-style secrets. They are stored in UCI, just like
ordinary Nikki RS subscription URLs. Use HTTPS unless targeting a trusted
local server. The backend generates Mihomo YAML; some options may not be
implemented by clash-rs, so review the effective configuration before enabling
advanced features.

## OpenWrt buildroot

Add the repository as a custom feed:

    echo 'src-git subboost https://github.com/stevessr/subboost.git;main' >> feeds.conf.default
    ./scripts/feeds update subboost
    ./scripts/feeds install -p subboost luci-app-subboost
    make package/luci-app-subboost/compile V=s

## Removal

Remove luci-app-subboost with opkg/apk. There is no running SubBoost daemon
or added firewall/DNS rule to clean up. Nikki RS subscriptions deliberately
synced earlier remain in Nikki RS so the router's active proxy profile is not
silently removed. Remove these entries in Nikki RS if no longer needed.

## Clash-rs / Nikki RS target-aware export

A SubBoost generated subscription normally emits Mihomo YAML. Nikki RS must
use the explicit target flag (the LuCI integration adds it automatically):

```text
https://your-subboost.example/api/subscriptions/YOUR_TOKEN/config.yaml?target=clash-rs
```

`target=nikki-rs` is an alias. Without the query flag (or with
`target=mihomo`), output remains unchanged.

The clash-rs profile uses namespaced rule providers (`subboost-*`) with
rewritten `RULE-SET` references to avoid collisions with Nikki RS UCI
providers. Remote rule caches use
`/etc/nikki-rs/providers/rule/subboost-*.mrs`; remote proxy provider caches
use `/etc/nikki-rs/providers/proxy/subboost-*.yaml`. Local file providers
keep their configured paths. The adapter emits explicit `geosite`, `mmdb`,
`asn-mmdb` and matching download URLs **when legacy GEO rules or DNS
settings require those databases**, and removes Mihomo-only `geox-url` and
geodata-update fields. MRS-only rules do not download full GEO databases.

Nikki RS continues owning interception ports, firewall, TUN/eBPF and its
own UCI-backed DNS/listener settings. Check clash-rs support for protocols,
DNS2 and advanced node settings separately; the target adapter does not
silently convert unsupported protocols to a different protocol.

### Isolated provider caches

For exported subscriptions, cache filenames include a stable 16-digit hexadecimal
prefix derived from SHA-256 of the bearer token. For example,
`/etc/nikki-rs/providers/rule/subboost-0123456789abcdef-cn.mrs`.
This prevents two different SubBoost subscriptions with the same provider
names but different provider URLs from overwriting or reusing each other's
cached rule/proxy provider files. The raw token is **never** written to provider
cache paths; the namespace does not alter `RULE-SET` references.

The LuCI synchronizer also recognizes SubBoost API paths deployed below a
reverse-proxy prefix (for example `/subboost/api/subscriptions/TOKEN/config.yaml`)
and avoids duplicate imports when old links lack the `target` query.
