import assert from "node:assert/strict";
import test from "node:test";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import type { DnsServerSettingsDocument } from "@/types/api";
import { dnsSettingsFilename, exportDnsSettings } from "./exportDnsSettings";
import { DNS_SETTINGS_DRAFT_NOTE, DNS_SETTINGS_EXPORT_NOTE, DnsSettingsExportButton, DnsSettingsExportNote } from "./DnsSettingsExport";

const snapshot: DnsServerSettingsDocument = {
  format: "nfqws2-strategy-dnsserver", version: 1, exported_at: "2026-10-02T14:04:05Z",
  config: {
    enabled: false, listen_host: "192.168.3.1", dns_port: 5355, logging_enabled: false, fast_dns: false,
    default_upstream: { address: "https://cloudflare-dns.com/dns-query", bootstrap_ips: ["1.1.1.1"] },
    default_pool: [{ address: "https://dns.quad9.net/dns-query", bootstrap_ips: ["9.9.9.9"] }],
    timeout_seconds: 5, cache_size: 0, cache_ttl_seconds: 3600, awg_fallback: "saved-warp", route_mode: "vpn_only",
    rules: [{ id: "group-one", enabled: true, domain: "example.com", include_subdomains: true, upstream: { address: "https://1.1.1.1/dns-query", bootstrap_ips: [] }, pool: [] }],
    disabled_methods: [{ route: "nfqws", upstream: "https://dns.quad9.net/dns-query" }],
    filtering: { enabled: true, lists: ["adguard"], custom_rules: [{ domain: "ads.example", category: "ads" }], allowlist: ["allowed.example"] },
    shadow_dns: { enabled: true, servers: ["192.0.2.53:53"], domains: [{ domain: "ru", include_subdomains: true }, { domain: "vk.com", include_subdomains: false }] },
  },
};

test("DNS export clearly names saved settings and warns only about an existing local draft", () => {
  const button = renderToStaticMarkup(createElement(DnsSettingsExportButton));
  assert.ok(button.includes("Экспорт сохранённых настроек"));
  const saved = renderToStaticMarkup(createElement(DnsSettingsExportNote, { dirty: false }));
  assert.ok(saved.includes(DNS_SETTINGS_EXPORT_NOTE));
  assert.equal(saved.includes(DNS_SETTINGS_DRAFT_NOTE), false);
  const draft = renderToStaticMarkup(createElement(DnsSettingsExportNote, { dirty: true }));
  assert.ok(draft.includes(DNS_SETTINGS_DRAFT_NOTE));
});

test("DNS filenames use the exported UTC snapshot date and reject an unknown document format", () => {
  assert.equal(dnsSettingsFilename(snapshot), "dns-server-settings-20261002-140405.json");
  assert.equal(dnsSettingsFilename({ ...snapshot, exported_at: "2026-10-02T17:04:05+03:00" }), "dns-server-settings-20261002-140405.json");
  assert.throws(() => dnsSettingsFilename({ ...snapshot, exported_at: "not-a-date" }), /некорректный/);
  assert.throws(() => dnsSettingsFilename({ ...snapshot, version: 2 } as unknown as DnsServerSettingsDocument), /некорректный/);
});

test("DNS export downloads the full saved response via GET and never sends or changes a local form", async (t) => {
  let downloaded: Blob | undefined;
  let request: RequestInit | undefined;
  let endpoint: string | undefined;
  let clicks = 0;
  let removes = 0;
  let revoked = "";
  const link = { href: "", download: "", click() { clicks++; }, remove() { removes++; } };
  t.mock.method(globalThis, "fetch", async (url: string, init: RequestInit) => {
    endpoint = url; request = init;
    return new Response(JSON.stringify(snapshot), { status: 200 });
  });
  t.mock.method(URL, "createObjectURL", (blob: Blob) => { downloaded = blob; return "blob:dns-export"; });
  t.mock.method(URL, "revokeObjectURL", (url: string) => { revoked = url; });
  const realDocument = Object.getOwnPropertyDescriptor(globalThis, "document");
  Object.defineProperty(globalThis, "document", { configurable: true, value: { createElement: () => link, body: { appendChild: () => {} } } });
  t.after(() => realDocument ? Object.defineProperty(globalThis, "document", realDocument) : Reflect.deleteProperty(globalThis, "document"));
  t.mock.timers.enable({ apis: ["setTimeout"] });
  const before = JSON.stringify(snapshot);
  await exportDnsSettings();
  assert.equal(endpoint, "/api/dnsserver/export");
  assert.equal(request?.method, "GET");
  assert.equal(request?.body, undefined);
  assert.equal(link.download, "dns-server-settings-20261002-140405.json");
  assert.equal(downloaded?.type, "application/json");
  assert.deepEqual(JSON.parse(await downloaded!.text()), snapshot);
  assert.equal(JSON.stringify(snapshot), before);
  assert.equal(clicks, 1);
  assert.equal(removes, 1);
  assert.equal(revoked, "");
  t.mock.timers.tick(2000);
  assert.equal(revoked, "blob:dns-export");
});

test("a rejected DNS export does not create a download or try a settings mutation", async (t) => {
  const calls: RequestInit[] = [];
  t.mock.method(globalThis, "fetch", async (_url: string, init: RequestInit) => {
    calls.push(init);
    return new Response(JSON.stringify({ error: "read failed" }), { status: 500 });
  });
  t.mock.method(URL, "createObjectURL", () => { throw new Error("unexpected download"); });
  await assert.rejects(exportDnsSettings(), /read failed/);
  assert.equal(calls.length, 1);
  assert.equal(calls[0].method, "GET");
  assert.equal(calls[0].body, undefined);
});
