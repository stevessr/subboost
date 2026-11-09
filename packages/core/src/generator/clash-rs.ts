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
  return id.replace(/[^a-zA-Z0-9_-]/g, "_").replace(/_+/g, "_")
    .replace(/^[_-]+|[_-]+$/g, "").slice(0, 48) || "unnamed";
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
  isRuleProvider: boolean,
  cacheNamespace?: string
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
    // An individual subscription must not share cache files with another
    // subscription that happens to use the same rule/provider name.
    const scopedBasename = cacheNamespace
      ? `subboost-${cacheNamespace}-${basename.slice("subboost-".length)}`
      : basename;
    result[newName] = {
      ...entry,
      path: `${baseDirectory}/${scopedBasename}.${ext}`,
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

function rewriteRuleSetLabel(value: string, names: Map<string, string>): string {
  const match = /^(rule-set:)(.+)$/i.exec(value);
  const replacement = match && names.get(match[2]);
  return replacement ? `${match![1]}${replacement}` : value;
}

function fixDnsPolicyReferences(dns: unknown, names: Map<string, string>): unknown {
  if (!isRecord(dns)) return dns;
  const next: Mapping = { ...dns };
  if (isRecord(dns["nameserver-policy"])) {
    next["nameserver-policy"] = Object.fromEntries(
      Object.entries(dns["nameserver-policy"]).map(([key, value]) => [
        rewriteRuleSetLabel(key, names), value,
      ])
    );
  }
  // Legacy DNS fake-IP filters may name a RULE-SET as a matcher.
  if (Array.isArray(dns["fake-ip-filter"])) {
    next["fake-ip-filter"] = dns["fake-ip-filter"].map((matcher) =>
      typeof matcher === "string" ? rewriteRuleSetLabel(matcher, names) : matcher
    );
  }
  return next;
}

function fixDns2RuleSetReferences(dns2: unknown, names: Map<string, string>): unknown {
  if (!isRecord(dns2) || !Array.isArray(dns2.rules)) return dns2;
  return {
    ...dns2,
    rules: dns2.rules.map((rule) => {
      if (!isRecord(rule) || !Array.isArray(rule["rule-set"])) return rule;
      return {
        ...rule,
        "rule-set": rule["rule-set"].map((name) =>
          typeof name === "string" ? (names.get(name) ?? name) : name
        ),
      };
    }),
  };
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

export interface NikkiRsAdapterOptions {
  /** Stable, non-secret hex namespace; hash the subscription token server-side. */
  cacheNamespace?: string;
}

export function adaptConfigForNikkiRs(
  config: ClashConfig,
  options: NikkiRsAdapterOptions = {}
): ClashConfig {
  const cacheNamespace = typeof options.cacheNamespace === "string" &&
    /^[a-f0-9]{12,32}$/.test(options.cacheNamespace)
    ? options.cacheNamespace : undefined;
  const copy: Mapping = { ...config };
  const geoUrls: Mapping = isRecord(config["geox-url"]) ? config["geox-url"] : {};
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

  const ruleProviders = rewriteProviders(config["rule-providers"], RULE_CACHE, true, cacheNamespace);
  copy["rule-providers"] = ruleProviders.providers;
  copy.rules = rewriteRuleSetReferences(rules, ruleProviders.renamed);
  copy["proxy-providers"] = rewriteProviders(config["proxy-providers"], PROXY_CACHE, false, cacheNamespace).providers;
  copy.dns = fixDnsPolicyReferences(originalDns, ruleProviders.renamed);
  copy.dns2 = fixDns2RuleSetReferences(config.dns2, ruleProviders.renamed);

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
