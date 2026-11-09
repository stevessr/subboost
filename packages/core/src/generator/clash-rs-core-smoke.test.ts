import { spawnSync } from "node:child_process";
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { adaptConfigForNikkiRs } from "./clash-rs";
import { configToYaml } from "./yaml";

/**
 * Optional real-core smoke test. The ordinary unit suite skips when
 * CLASH_RS_BINARY is absent. GitHub Actions uses the same pinned core release
 * packaged by OpenWrt-nikki-rs to exercise the actual config parser.
 */
describe("Nikki RS pinned clash-rs binary smoke", () => {
  const run = process.env.CLASH_RS_BINARY ? it : it.skip;

  run("accepts adapted sticky-session groups and local RULE-SET file paths", () => {
    const temp = mkdtempSync(join(tmpdir(), "subboost-clash-rs-"));
    try {
      const rulesPath = join(temp, "rule.yaml");
      mkdirSync(join(temp, "cache"), { recursive: true });
      writeFileSync(rulesPath, "payload:\n  - +.example.com\n");
      const config = adaptConfigForNikkiRs({
        mode: "rule",
        proxies: [{
          name: "SmokeSS", type: "ss", server: "127.0.0.1", port: 8388,
          cipher: "aes-128-gcm", password: "test-secret",
        }],
        "proxy-groups": [{
          name: "SmokeLB", type: "load-balance", proxies: ["SmokeSS"],
          url: "https://www.gstatic.com/generate_204", interval: 300,
          strategy: "sticky-sessions",
        }],
        "rule-providers": {
          sample: { type: "file", behavior: "domain", format: "yaml", path: rulesPath },
        },
        rules: ["RULE-SET,sample,SmokeLB", "MATCH,SmokeLB"],
      }, { cacheNamespace: "0123456789abcdef" });
      expect(config["proxy-groups"]?.[0].strategy).toBe("sticky-session");
      expect(config["rule-providers"]?.["subboost-sample"].path).toBe(rulesPath);
      expect(config.rules?.[0]).toBe("RULE-SET,subboost-sample,SmokeLB");
      writeFileSync(join(temp, "config.yaml"), configToYaml(config));

      const result = spawnSync(process.env.CLASH_RS_BINARY!, ["-d", temp, "-t"], {
        encoding: "utf8",
        timeout: 60_000,
      });
      expect(result.error?.message).toBeUndefined();
      expect(result.status, result.stdout + "\n" + result.stderr).toBe(0);
    } finally {
      rmSync(temp, { recursive: true, force: true });
    }
  });
});
