import { describe, expect, it } from "vitest";
import { adaptConfigForNikkiRs } from "./clash-rs";
import { generateClashConfig, generateClashYaml } from "./index";
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
  it("rewrites all DNS rule-set references without changing direct domains", () => {
    const source = original();
    source.dns!["fake-ip-filter"] = ["rule-set:cn", "*.lan"];
    source.dns2 = { rules: [{ "rule-set": ["cn", "local"], upstream: "direct-dns" }] };
    const config = adaptConfigForNikkiRs(source);
    expect(config.dns?.["fake-ip-filter"]).toEqual(["rule-set:subboost-cn", "*.lan"]);
    expect((config.dns2 as any).rules[0]["rule-set"]).toEqual(["subboost-cn", "local"]);
  });

  it("generates an end-to-end target profile while retaining default Mihomo behavior", () => {
    const options = {
      nodes: [{
        name: "Node", type: "ss" as const, server: "example.org", port: 8388,
        cipher: "aes-128-gcm", password: "secret",
      }],
      template: "minimal" as const,
    };
    const mihomo = generateClashConfig(options);
    const nikki = generateClashConfig({ ...options, target: "clash-rs" });
    expect(mihomo["rule-providers"]).toHaveProperty("cn");
    expect(mihomo["rule-providers"]?.cn.path).toBe("./ruleset/cn.mrs");
    expect(nikki["rule-providers"]).toHaveProperty("subboost-cn");
    expect(nikki["rule-providers"]?.["subboost-cn"].path).toBe(
      "/etc/nikki-rs/providers/rule/subboost-cn.mrs"
    );
    expect(nikki.rules?.some((r) => r.includes("RULE-SET,subboost-cn,"))).toBe(true);
    const yaml = generateClashYaml({ ...options, target: "clash-rs" });
    expect(yaml).toContain("/etc/nikki-rs/providers/rule/subboost-cn.mrs");
    expect(yaml).toContain("RULE-SET,subboost-cn,");
    expect(generateClashYaml(options)).not.toContain("subboost-cn.mrs");
  });

  it("uses documented GEO download fallback URLs when Mihomo URLs are missing or invalid", () => {
    const config = adaptConfigForNikkiRs({
      "geox-url": { mmdb: "file:///private.mmdb", geosite: "javascript:bad", asn: "" },
      rules: ["GEOIP,JP,DIRECT", "GEOSITE,cn,DIRECT", "IP-ASN,64512,PROXY"],
      mmdb: "/custom/geo.mmdb",
      "geosite-download-url": "https://example.org/current.dat",
    });
    expect(config.mmdb).toBe("/custom/geo.mmdb");
    expect(config["mmdb-download-url"]).toContain("DustinWin/ruleset_geodata");
    expect(config.geosite).toBe("geosite.dat");
    expect(config["geosite-download-url"]).toBe("https://example.org/current.dat");
    expect(config["asn-mmdb-download-url"]).toContain("Country-ASN.mmdb");
  });

  it("keeps local proxy provider paths and leaves unrelated RULE-SET references unchanged", () => {
    const output = adaptConfigForNikkiRs({
      "rule-providers": {
        local: { type: "file", behavior: "domain", path: "./local.yaml" },
        remote: { type: "http", behavior: "domain", format: "text", url: "https://example.org/remote.txt" },
      },
      "proxy-providers": {
        disk: { type: "file", path: "/etc/nikki-rs/node.yaml" },
      },
      rules: ["RULE-SET,remote,DIRECT", "RULE-SET,missing,REJECT", "MATCH,DIRECT", "BAD", 22 as any],
      dns: { "nameserver-policy": { "geosite:cn": ["223.5.5.5"] } },
    });
    expect(output["rule-providers"]?.["subboost-local"].path).toBe("./local.yaml");
    expect(output["rule-providers"]?.["subboost-remote"].path).toBe(
      "/etc/nikki-rs/providers/rule/subboost-remote.txt"
    );
    expect((output["proxy-providers"] as any).disk.path).toBe("/etc/nikki-rs/node.yaml");
    expect(output.rules).toContain("RULE-SET,missing,REJECT");
    expect(output.rules).toContain("BAD");
    expect(output.rules).toContain(22);
  });

  it("resolves collisions after safe filename normalization", () => {
    const output = adaptConfigForNikkiRs({
      "rule-providers": {
        "id/path": { type: "http", format: "yaml", url: "https://example.org/a.yaml" },
        "id.path": { type: "http", format: "yaml", url: "https://example.org/b.yaml" },
        "!": { type: "http", format: "mrs", url: "https://example.org/c.mrs" },
      },
      rules: ["RULE-SET,id/path,DIRECT", "RULE-SET,id.path,PROXY", "RULE-SET,!,REJECT"],
    });
    const names = Object.keys(output["rule-providers"]!);
    expect(new Set(names).size).toBe(3);
    expect(names).toContain("subboost-id_path");
    expect(names).toContain("subboost-id_path-2");
    expect(output.rules).toContain("RULE-SET,subboost-id_path-2,DIRECT");
    expect(output.rules).toContain("RULE-SET,subboost-id_path,PROXY");
    expect(names.some((name) => name.startsWith("subboost-unnamed"))).toBe(true);
  });

  it("handles absent and non-object providers without inventing new downloads", () => {
    const original = { rules: [], "rule-providers": "unrecognized", "proxy-providers": null };
    const output = adaptConfigForNikkiRs(original as any);
    expect(output["rule-providers"]).toBe("unrecognized");
    expect(output["proxy-providers"]).toBeNull();
    expect(output).not.toHaveProperty("geosite");
    expect(output).not.toHaveProperty("mmdb");
  });

  it("isolates providers of different subscriptions without changing their RULE-SET names", () => {
    const input = original();
    const one = adaptConfigForNikkiRs(input, { cacheNamespace: "0123456789abcdef" });
    const two = adaptConfigForNikkiRs(input, { cacheNamespace: "fedcba9876543210" });
    expect(one.rules).toEqual(two.rules);
    expect(one["rule-providers"]?.["subboost-cn"].path)
      .toBe("/etc/nikki-rs/providers/rule/subboost-0123456789abcdef-cn.mrs");
    expect(two["rule-providers"]?.["subboost-cn"].path)
      .toBe("/etc/nikki-rs/providers/rule/subboost-fedcba9876543210-cn.mrs");
    expect((one["proxy-providers"] as any).airport.path)
      .toBe("/etc/nikki-rs/providers/proxy/subboost-0123456789abcdef-airport.yaml");
    expect((two["proxy-providers"] as any).airport.path)
      .not.toBe((one["proxy-providers"] as any).airport.path);
    expect(adaptConfigForNikkiRs(input, { cacheNamespace: "0123456789abcdef" })).toEqual(one);
    expect(input["rule-providers"]?.cn.path).toBe("./ruleset/cn.mrs");
  });

  it("never interpolates untrusted or token-like cache namespace values into paths", () => {
    for (const name of ["../other", "ABCD123456789abc", "", "secret", "0123456789abcde/", "a".repeat(70)]) {
      const config = adaptConfigForNikkiRs(original(), { cacheNamespace: name });
      expect(config["rule-providers"]?.["subboost-cn"].path)
        .toBe("/etc/nikki-rs/providers/rule/subboost-cn.mrs");
    }
  });

  it("applies scoped cache namespaces via the full generator target", () => {
    const config = generateClashConfig({
      target: "clash-rs",
      cacheNamespace: "1234567890abcdef",
      nodes: [{
        name: "Node", type: "ss", server: "example.org", port: 8388,
        cipher: "aes-128-gcm", password: "secret",
      }],
      template: "minimal",
    });
    expect(config["rule-providers"]?.["subboost-cn"].path).toBe(
      "/etc/nikki-rs/providers/rule/subboost-1234567890abcdef-cn.mrs"
    );
  });

  it("uses clash-rs sticky-session strategy spelling without mutating Mihomo groups", () => {
    const source: ClashConfig = {
      "proxy-groups": [
        { name: "sticky", type: "load-balance", strategy: "sticky-sessions", proxies: ["DIRECT"] },
        { name: "round", type: "load-balance", strategy: "round-robin", proxies: ["DIRECT"] },
        { name: "selector", type: "select", proxies: ["DIRECT"] },
      ],
    };
    const output = adaptConfigForNikkiRs(source);
    expect(output["proxy-groups"]?.[0].strategy).toBe("sticky-session");
    expect(output["proxy-groups"]?.[1].strategy).toBe("round-robin");
    expect(output["proxy-groups"]?.[2].type).toBe("select");
    expect(source["proxy-groups"]?.[0].strategy).toBe("sticky-sessions");
    expect(adaptConfigForNikkiRs({})["proxy-groups"]).toBeUndefined();
  });

});
