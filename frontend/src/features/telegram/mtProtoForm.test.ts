import assert from "node:assert/strict";
import test from "node:test";
import type { TgwsConfig } from "@/types/api";
import { collect, toForm } from "./MtProto";

test("MTProto settings preserve the explicit H2 choice and enable legacy configurations", () => {
  const legacy = { port: 1433, secret: "0123456789abcdef0123456789abcdef", pool_size: 0, cfproxy: true, dc_redirects: { "4": "192.0.2.4" } } as unknown as TgwsConfig;
  for (const option of [undefined, false, true]) {
    const form = toForm({ ...legacy, cfproxy_h2_media: option });
    assert.equal(form.cfproxy_h2_media, option ?? true);
    const value = collect(form);
    assert.equal(value.cfproxy_h2_media, option ?? true);
    assert.equal(value.pool_size, 0);
    assert.equal(value.secret, legacy.secret);
    assert.deepEqual(value.dc_redirects, legacy.dc_redirects);
    form.cfproxy_h2_media = false;
    form.disable_secure = true;
    assert.equal(collect(form).cfproxy_h2_media, false);
  }
});
