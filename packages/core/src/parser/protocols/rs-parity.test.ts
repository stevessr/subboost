import { describe, expect, it } from "vitest";
import fixtures from "../../../../../rusted/data/uri-parity-fixtures.json";
import ruleFixtures from "../../../../../rusted/data/rule-parity-fixtures.json";
import { generateRules } from "../../generator/rules";
import { parseTrojan } from "./trojan";
import { parseSS } from "./ss";
import { parseVMess } from "./vmess";
import { parseVLESS } from "./vless";

type Node = Record<string, unknown>;
function projection(node: Node): Record<string, unknown> {
  const result: Record<string, unknown> = {};
  for (const name of ["name", "type", "server", "port", "network", "cipher", "password", "udp", "sni", "client-fingerprint", "plugin", "tfo", "tls", "uuid", "alterId", "servername", "skip-cert-verify"]) {
    if (node[name] !== undefined) result[name] = node[name];
  }
  const opts = node["plugin-opts"] as Record<string, unknown> | undefined;
  if (opts?.mode !== undefined) result.plugin_mode = opts.mode;
  if (opts?.host !== undefined) result.plugin_host = opts.host;
  if (node["udp-over-tcp"] !== undefined) result.udp_over_tcp = node["udp-over-tcp"];
  const ws = node["ws-opts"] as Record<string, unknown> | undefined;
  if (ws) {
    result.ws_path = ws.path;
    if (ws["max-early-data"] !== undefined) result.ws_early_data = ws["max-early-data"];
    if (ws["early-data-header-name"] !== undefined) result.ws_header = ws["early-data-header-name"];
    const headers = ws.headers as Record<string, unknown> | undefined;
    if (headers?.Host !== undefined) result.ws_host = headers.Host;
  }
  const http = node["http-opts"] as Record<string, unknown> | undefined;
  if (http) {
    if (http.method !== undefined) result.http_method = http.method;
    if (http.path !== undefined) result.http_paths = http.path;
    const headers = http.headers as Record<string, unknown> | undefined;
    if (headers?.Host !== undefined) result.http_hosts = headers.Host;
  }
  const grpc = node["grpc-opts"] as Record<string, unknown> | undefined;
  if (grpc?.["grpc-service-name"] !== undefined) result.grpc_service = grpc["grpc-service-name"];
  return result;
}

describe("upstream URI parity contract shared with Rust", () => {
  for (const fixture of fixtures) {
    it(fixture.id, () => {
      const node = fixture.uri.startsWith("vless://")
        ? parseVLESS(fixture.uri)
        : fixture.uri.startsWith("ss://")
          ? parseSS(fixture.uri)
          : fixture.uri.startsWith("vmess://")
            ? parseVMess(fixture.uri)
            : parseTrojan(fixture.uri);
      const actual = projection(node as unknown as Node);
      const expected = fixture.expected as Record<string, unknown>;
      const selected = Object.fromEntries(
        Object.keys(expected).map((key) => [key, actual[key]])
      );
      expect(selected).toEqual(expected);
    });
  }
});

describe("upstream rule-order contract shared with Rust", () => {
  for (const fixture of ruleFixtures) {
    it(fixture.id, () => {
      const actual = generateRules({
        enabledModules: fixture.enabled_modules,
        customRules: [],
      });
      expect(actual).toEqual(fixture.expected_rules);
    });
  }
});
