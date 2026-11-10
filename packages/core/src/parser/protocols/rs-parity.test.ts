import { describe, expect, it } from "vitest";
import fixtures from "../../../../../rusted/data/uri-parity-fixtures.json";
import { parseTrojan } from "./trojan";
import { parseVLESS } from "./vless";

type Node = Record<string, unknown>;
function projection(node: Node): Record<string, unknown> {
  const result: Record<string, unknown> = {};
  for (const name of ["name", "type", "server", "port", "network"]) {
    if (node[name] !== undefined) result[name] = node[name];
  }
  const ws = node["ws-opts"] as Record<string, unknown> | undefined;
  if (ws) {
    result.ws_path = ws.path;
    if (ws["max-early-data"] !== undefined) result.ws_early_data = ws["max-early-data"];
    if (ws["early-data-header-name"] !== undefined) result.ws_header = ws["early-data-header-name"];
    const headers = ws.headers as Record<string, unknown> | undefined;
    if (headers?.Host !== undefined) result.ws_host = headers.Host;
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
        : parseTrojan(fixture.uri);
      expect(projection(node as unknown as Node)).toEqual(fixture.expected);
    });
  }
});
