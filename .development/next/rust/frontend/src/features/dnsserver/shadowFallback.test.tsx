import assert from "node:assert/strict";
import test from "node:test";
import { renderToStaticMarkup } from "react-dom/server";
import type { DnsShadowStatus } from "@/types/api";
import { ShadowDns } from "./ShadowDns";
import { DomainGroups } from "./DomainGroups";
import { dnsSchedulerState } from "./dnsSchedulerState";
import type { DnsServerSchedulerSnapshot } from "@/types/api";

const healthy: DnsShadowStatus = { enabled: true, automatic: true, servers: ["192.0.2.53:53"] };
const render = (status?: DnsShadowStatus) => renderToStaticMarkup(<ShadowDns value={{ enabled: true, patterns: "*.ru" }} status={status} onChange={() => {}} />);

test("Shadow fallback displays provider failure and on-demand recovery without claiming the reserve succeeded", (t) => {
  const request = t.mock.method(globalThis, "fetch", () => { throw new Error("render must not probe DNS or renew DHCP"); });
  const html = render({ ...healthy, fallback_active: true, error: "Shadow DNS: context deadline exceeded", next_probe_at: "2026-10-05T12:30:00Z" });
  assert.match(html, /Резерв: DNS Server/);
  assert.match(html, /context deadline exceeded/);
  assert.match(html, /192\.0\.2\.53:53/);
  assert.match(html, /Если доступных маршрутов нет, запрос вернёт ошибку/);
  assert.match(html, /при следующем запросе без ответа в кеше/);
  assert.match(html, /dateTime="2026-10-05T12:30:00Z"/);
  assert.match(html, /После успешного ответа снова используется провайдер/);
  assert.equal(request.mock.callCount(), 0);
});

test("Healthy, disabled and older Shadow statuses do not advertise an active reserve", () => {
  for (const status of [undefined, healthy, { ...healthy, fallback_active: false }, { ...healthy, enabled: false, fallback_active: true }]) {
    const html = render(status);
    assert.equal(html.includes("Резерв: DNS Server"), false);
    assert.equal(html.includes("Повторная проверка провайдера"), false);
    assert.match(html, /с учётом групп DoH, режима VPN и отключённых методов/);
    assert.equal(html.includes("автоматического перехода к DoH или VPN нет"), false);
  }
});

test("Fallback works without discovered servers and treats an invalid retry date as unavailable", () => {
  for (const next_probe_at of [undefined, "invalid", "<script>untrusted</script>"]) {
    const html = render({ ...healthy, servers: [], fallback_active: true, error: "<script>provider error</script>", next_probe_at });
    assert.match(html, /Резерв: DNS Server/);
    assert.match(html, /не чаще одного раза в 30 секунд/);
    assert.equal(html.includes("Invalid Date"), false);
    assert.equal(html.includes("<script>"), false);
    assert.equal(html.includes("untrusted"), false);
    assert.match(html, /&lt;script&gt;provider error&lt;\/script&gt;/);
  }
});

test("Domain groups and the provider scheduler state explain DoH as a reserve", () => {
  const html = renderToStaticMarkup(<DomainGroups value={[]} onChange={() => {}} disabled={false} />);
  assert.match(html, /при его недоступности используется выбранный здесь пул/);
  assert.match(html, /для доменов из Shadow DNS он служит резервом/);
  const state = dnsSchedulerState({ reason: "shadow" } as DnsServerSchedulerSnapshot);
  assert.equal(state.active, false);
  assert.match(state.message, /Пул DoH используется как резерв/);
  assert.match(state.message, /Фоновые пробы этого домена не выполняются/);
});
