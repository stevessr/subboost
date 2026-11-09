import type { ClashConfig } from "@subboost/core/types/config";

/**
 * Nikki RS invokes clash-rs with -d /etc/nikki-rs/run and overlays its own
 * UCI providers and transparent-proxy settings. This adapter is intentionally
 * opt-in and never changes the ordinary Mihomo export.
 */
const NIKKI_ROOT = "/etc/nikki-rs";
const RULE_CACHE = `${NIKKI_ROOT}/providers/rule`;
const PROXY_CACHE = `${NIKKI_ROOT}/providers/proxy`;

const GEO_DEFAULTS = {
  geosite: {
    path: "geosite.dat",
    url: "https://cdn.jsdelivr.net/gh/DustinWin/ruleset_geodata@mihomo-geodata/geosite-lite.dat",
  },
  mmdb: {
    path: "Country.mmdb",
    url: "https://cdn.jsdelivr.net/gh/DustinWin/ruleset_geodata@mihomo-geodata/Country.mmdb",
  },
  asn: {
    path: "Country-ASN.mmdb",
    url: "https://cdn.jsdelivr.net/gh/DustinWin/ruleset_geodata@mihomo-geodata/Country-ASN.mmdb",
  },
} as const;

type Mapping = Record<string, unknown>;

function isRecord(value: unknown): value is Mapping {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function safeId(id: string): string {
  return id.replace(/[^a-zA-Z0-9_-]/g, "_").replace(/_+/g, "_").slice(0, 48) || "unnamed";
}

/** Deterministic, bounded filename: collisions are resolved within each map. */
function reserveName(id: string, used: Set<string>): string {
  const stem = `subboost-${safeId(id)}`;
  let name = stem;
  let suffix = 2;
  while (used.has(name)) name = `${stem}-${suffix++}`;
  used.add(name);
  return name;
}

function safeExtension(value: unknown, defaultExtension: string): string {
  const extension = typeof value === "string" ? value.toLowerCase() : "";
  if (extension === "mrs") return "mrs";
  if (extension === "yaml" || extension === "yml") return "yaml";
  if (extension === "text" || extension === "txt") return "txt";
  return defaultExtension;
}

function rewriteProviders(
  original: unknown,
  baseDirectory: string,
  isRuleProvider: boolean
): { providers: unknown; renamed: Map<string, string> } {
  if (!isRecord(original)) return { providers: original, renamed: new Map() };

  const usedNames = new Set<string>();
  const names = new Map<string, string>();
  const result: Mapping = {};
  // Sorting makes the mapping stable regardless of object insertion order.
  for (const name of Object.keys(original).sort()) {
    const entry = original[name];
    if (!isRecord(entry)) {
      result[name] = entry;
      continue;
    }

    const newName = isRuleProvider ? reserveName(name, usedNames) : name;
    if (isRuleProvider) names.set(name, newName);
    const type = entry.type;
    if (type !== "http") {
      // A user-owned local file must never be silently redirected to a
      // generated, possibly nonexistent, cache location.
      result[newName] = { ...entry };
      continue;
    }

    const ext = isRuleProvider
      ? safeExtension(entry.format, "yaml")
      : "yaml";
    const basename = isRuleProvider ? newName : reserveName(name, usedNames);
    result[newName] = {
      ...entry,
      path: `${baseDirectory}/${basename}.${ext}`,
    };
  }
  return { providers: result, renamed: names };
}

function rewriteRuleSetReferences(rules: unknown, names: Map<string, string>): unknown {
  if (!Array.isArray(rules) || names.size === 0) return rules;
  return rules.map((value) => {
    if (typeof value !== "string") return value;
    const parts = value.split(",");
    if (parts[0]?.trim().toUpperCase() !== "RULE-SET" || parts.length < 3) return value;
    const oldName = parts[1].trim();
    const next = names.get(oldName);
    if (!next) return value;
    parts[1] = next;
    return parts.join(",");
  });
}

function fixDnsPolicyReferences(dns: unknown, names: Map<string, string>): unknown {
  if (!isRecord(dns) || !isRecord(dns["nameserver-policy"])) return dns;
  const policy: Mapping = {};
  for (const [key, value] of Object.entries(dns["nameserver-policy"])) {
    const match = /^rule-set:(.+)$/i.exec(key);
    const updatedName = match && names.get(match[1]);
    policy[updatedName ? `rule-set:${updatedName}` : key] = value;
  }
  return { ...dns, "nameserver-policy": policy };
}

function hasGeoRule(rules: unknown, ruleType: string): boolean {
  return Array.isArray(rules) && rules.some((r) =>
    typeof r === "string" && r.toUpperCase().startsWith(`${ruleType},`)
  );
}

function policyNeedsGeosite(dns: unknown): boolean {
  if (!isRecord(dns)) return false;
  const policy = dns["nameserver-policy"];
  const fallback = dns["fallback-filter"];
  return (
    (isRecord(policy) && Object.keys(policy).some((key) => /^geosite:/i.test(key))) ||
    (isRecord(fallback) && Array.isArray(fallback.geosite) && fallback.geosite.length > 0)
  );
}

function validHttpUrl(url: unknown): url is string {
  if (typeof url !== "string") return false;
  try {
    const parsed = new URL(url);
    return parsed.protocol === "https:" || parsed.protocol === "http:";
  } catch {
    return false;
  }
}

function geoUrl(candidate: unknown, fallback: string): string {
  return validHttpUrl(candidate) ? candidate : fallback;
}

function setGeoFile(
  config: Mapping,
  pathField: string,
  urlField: string,
  url: string,
  fallbackPath: string
): void {
  // Preserve an explicitly set local path or custom download URL.
  if (typeof config[pathField] !== "string" || !config[pathField]) config[pathField] = fallbackPath;
  if (!validHttpUrl(config[urlField])) config[urlField] = url;
}

export function adaptConfigForNikkiRs(config: ClashConfig): ClashConfig {
  const copy: Mapping = { ...config };
  const geoUrls = isRecord(config["geox-url"]) ? config["geox-url"] : {};
  const originalDns = config.dns;
  const rules = config.rules;

  // The Mihomo geodata updater is not the clash-rs GEO database interface.
  for (const key of [
    "geodata-mode", "geo-auto-update", "geodata-loader", "geo-update-interval", "geox-url",
  ]) delete copy[key];

  // Nikki's UCI configuration owns transparent interception, firewall, DNS
  // listeners and eBPF/TUN exclusivity. Do not let subscription settings
  // overwrite these runtime decisions.
  for (const key of [
    "mixed-port", "port", "socks-port", "redir-port", "tproxy-port",
    "allow-lan", "bind-address", "external-controller", "secret",
    "external-ui", "external-ui-url", "ebpf", "tun",
  ]) delete copy[key];

  const ruleProviders = rewriteProviders(config["rule-providers"], RULE_CACHE, true);
  copy["rule-providers"] = ruleProviders.providers;
  copy.rules = rewriteRuleSetReferences(rules, ruleProviders.renamed);
  copy["proxy-providers"] = rewriteProviders(config["proxy-providers"], PROXY_CACHE, false).providers;
  copy.dns = fixDnsPolicyReferences(originalDns, ruleProviders.renamed);

  // Rule-provider MRS files are preferred. Load large GEO databases only
  // when a legacy GEO rule or a DNS policy actually depends on one.
  if (hasGeoRule(rules, "GEOSITE") || policyNeedsGeosite(originalDns)) {
    setGeoFile(copy, "geosite", "geosite-download-url",
      geoUrl(geoUrls.geosite, GEO_DEFAULTS.geosite.url), GEO_DEFAULTS.geosite.path);
  }
  if (hasGeoRule(rules, "GEOIP") ||
      (isRecord(originalDns?.["fallback-filter"]) &&
       originalDns["fallback-filter"].geoip === true)) {
    setGeoFile(copy, "mmdb", "mmdb-download-url",
      geoUrl(geoUrls.mmdb, GEO_DEFAULTS.mmdb.url), GEO_DEFAULTS.mmdb.path);
  }
  if (hasGeoRule(rules, "IP-ASN")) {
    setGeoFile(copy, "asn-mmdb", "asn-mmdb-download-url",
      geoUrl(geoUrls.asn, GEO_DEFAULTS.asn.url), GEO_DEFAULTS.asn.path);
  }

  return copy as ClashConfig;
}
