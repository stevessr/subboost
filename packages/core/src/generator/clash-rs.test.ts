import { describe, expect, it } from "vitest";
import { adaptConfigForNikkiRs } from "./clash-rs";
import type { ClashConfig } from "@subboost/core/types/config";

describe("Nikki RS / clash-rs config compatibility", () => {
  const original = (): ClashConfig => ({
    "mixed-port": 7897,
    "allow-lan": true,
    ebpf: { enabled: true },
    tun: { enable: true },
    "geodata-mode": true,
    "geo-auto-update": true,
    "geox-url": {
      mmdb: "https://example.org/country.mmdb",
      geosite: "https://example.org/geosite.dat",
      asn: "https://example.org/asn.mmdb",
    },
    dns: {
      "fallback-filter": { geoip: true },
      "nameserver-policy": {
        "rule-set:cn": "223.5.5.5",
        "geosite:private": "127.0.0.1",
      },
    },
    "rule-providers": {
      ai: { type: "http", behavior: "domain", format: "mrs", path: "./ruleset/ai.mrs", url: "https://example.org/ai.mrs" },
      cn: { type: "http", behavior: "domain", format: "mrs", path: "./ruleset/cn.mrs", url: "https://example.org/cn.mrs" },
      "my/../custom": { type: "http", behavior: "classical", format: "yaml", path: "../../oops", url: "https://example.org/custom.yaml" },
      file_rule: { type: "file", behavior: "domain", path: "/etc/nikki-rs/custom.mrs", format: "mrs" },
    },
    "proxy-providers": {
      airport: { type: "http", path: "../airport.yaml", url: "https://example.org/airport.yaml" },
    },
    rules: [
      "RULE-SET,ai,AI",
      "RULE-SET,cn,DIRECT,no-resolve",
      "RULE-SET,my/../custom,PROXY",
      "RULE-SET,file_rule,DIRECT",
      "GEOIP,CN,DIRECT,no-resolve",
      "GEOSITE,private,DIRECT",
      "IP-ASN,15169,PROXY",
      "MATCH,PROXY",
    ],
  });

  it("namespaces UCI-colliding rule providers and rewrites their references", () => {
    const config = adaptConfigForNikkiRs(original());
    const providers = config["rule-providers"]!;
    expect(providers).not.toHaveProperty("ai");
    expect(providers).not.toHaveProperty("cn");
    expect(providers["subboost-ai"].path).toBe("/etc/nikki-rs/providers/rule/subboost-ai.mrs");
    expect(providers["subboost-cn"].url).toBe("https://example.org/cn.mrs");
    expect(providers["subboost-my_custom"].path).not.toContain("../");
    expect(providers["subboost-file_rule"].path).toBe("/etc/nikki-rs/custom.mrs");
    expect(config.rules).toEqual([
      "RULE-SET,subboost-ai,AI",
      "RULE-SET,subboost-cn,DIRECT,no-resolve",
      "RULE-SET,subboost-my_custom,PROXY",
      "RULE-SET,subboost-file_rule,DIRECT",
      "GEOIP,CN,DIRECT,no-resolve",
      "GEOSITE,private,DIRECT",
      "IP-ASN,15169,PROXY",
      "MATCH,PROXY",
    ]);
    expect(config.dns?.["nameserver-policy"]).toHaveProperty("rule-set:subboost-cn", "223.5.5.5");
  });

  it("uses Nikki provider paths, preserving remote type and URL", () => {
    const config = adaptConfigForNikkiRs(original());
    expect((config["proxy-providers"] as any).airport.path).toBe("/etc/nikki-rs/providers/proxy/subboost-airport.yaml");
    expect(config["rule-providers"]!["subboost-ai"]).toMatchObject({
      type: "http", format: "mrs", behavior: "domain",
    });
    expect(config["rule-providers"]!["subboost-my_custom"].path).toMatch(/^\/etc\/nikki-rs\/providers\/rule\/[^/]+\.yaml$/);
  });

  it("replaces Mihomo Geo fields with explicit clash-rs database paths and download URLs", () => {
    const config = adaptConfigForNikkiRs(original());
    expect(config).not.toHaveProperty("geox-url");
    expect(config).not.toHaveProperty("geodata-mode");
    expect(config).not.toHaveProperty("geo-auto-update");
    expect(config).toMatchObject({
      mmdb: "Country.mmdb",
      "mmdb-download-url": "https://example.org/country.mmdb",
      geosite: "geosite.dat",
      "geosite-download-url": "https://example.org/geosite.dat",
      "asn-mmdb": "Country-ASN.mmdb",
      "asn-mmdb-download-url": "https://example.org/asn.mmdb",
    });
    for (const key of ["mixed-port", "allow-lan", "ebpf", "tun", "external-controller"]) {
      expect(config).not.toHaveProperty(key);
    }
  });

  it("avoids heavyweight databases when only RULE-SET MRS is used", () => {
    const source: ClashConfig = {
      "rule-providers": {
        cn: { type: "http", format: "mrs", behavior: "domain", url: "https://example.org/cn.mrs" },
      },
      rules: ["RULE-SET,cn,DIRECT", "MATCH,DIRECT"],
    };
    const config = adaptConfigForNikkiRs(source);
    expect(config).not.toHaveProperty("mmdb");
    expect(config).not.toHaveProperty("geosite");
    expect(config.rules).toEqual(["RULE-SET,subboost-cn,DIRECT", "MATCH,DIRECT"]);
  });

  it("does not mutate Mihomo source objects or introduce unsafe paths for user rule names", () => {
    const input = original();
    const snapshot = JSON.parse(JSON.stringify(input));
    const config = adaptConfigForNikkiRs(input);
    expect(input).toEqual(snapshot);
    expect(config["rule-providers"]!["subboost-my_custom"].path).not.toContain("..");
    const second = adaptConfigForNikkiRs(input);
    expect(second).toEqual(config);
  });
});
