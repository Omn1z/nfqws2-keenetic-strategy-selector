import { useEffect, useState } from "react";
import { api } from "@/lib/api";
import { awgVersionLabel, vpnEngineIssue, vpnProfileLabel } from "@/lib/awg";
import { toast } from "@/components/ui/Toast";
import { confirmDialog } from "@/components/ui/Confirm";
import { Card } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { Badge } from "@/components/ui/Badge";
import { Switch } from "@/components/ui/Switch";
import { Field, Input, Select, Textarea } from "@/components/ui/form";
import type { Awg2Status, AwgServerConfig } from "@/types/api";

interface Form {
  enabled: boolean; protocol: string;
  protocol_version: string; traffic_obfuscation: boolean;
  host: string; port: string; user: string; auth_kind: string;
  password: string; key_pem: string; key_pass: string; known_key: string;
  install: string;
  listen_port: string; address: string; subnet: string; mtu: string; dns: string; wan_iface: string; endpoint: string;
  jc: string; jmin: string; jmax: string; s1: string; s2: string; s3: string; s4: string;
  h1: string; h2: string; h3: string; h4: string;
  i1: string; i2: string; i3: string; i4: string; i5: string;
  header_protection_key: string;
  content_padding_addition: string; rekey_after_time: string; rekey_timeout: string;
  reject_after_time: string; keepalive_timeout: string; max_handshake_attempts: string;
  random_trailers: boolean; disable_cookies: boolean;
}

const AWG3_FIELDS = [
  ["content_padding_addition", "ContentPaddingAddition"],
  ["rekey_after_time", "RekeyAfterTime"],
  ["rekey_timeout", "RekeyTimeout"],
  ["reject_after_time", "RejectAfterTime"],
  ["keepalive_timeout", "KeepaliveTimeout"],
  ["max_handshake_attempts", "MaxHandshakeAttempts"],
] as const;

const S = (n: number | undefined) => String(n ?? "");
const toForm = (c: AwgServerConfig): Form => ({
  enabled: c.enabled !== false, protocol: c.protocol || "awg",
  protocol_version: c.protocol_version || "", traffic_obfuscation: c.traffic_obfuscation ?? c.protocol !== "wireguard",
  host: c.conn.host || "", port: S(c.conn.port || 22), user: c.conn.user || "root", auth_kind: c.conn.auth_kind || "password",
  password: "", key_pem: "", key_pass: "", known_key: c.conn.known_key || "",
  install: c.install || "apt",
  listen_port: S(c.listen_port || 51820), address: c.address || "", subnet: c.subnet || "", mtu: S(c.mtu || 1420),
  dns: c.dns || "", wan_iface: c.wan_iface || "", endpoint: c.endpoint || "",
  jc: S(c.obf.jc), jmin: S(c.obf.jmin), jmax: S(c.obf.jmax), s1: S(c.obf.s1), s2: S(c.obf.s2), s3: S(c.obf.s3), s4: S(c.obf.s4),
  h1: c.obf.h1 || "1", h2: c.obf.h2 || "2", h3: c.obf.h3 || "3", h4: c.obf.h4 || "4",
  i1: c.obf.i1 || "", i2: c.obf.i2 || "", i3: c.obf.i3 || "", i4: c.obf.i4 || "", i5: c.obf.i5 || "",
  header_protection_key: "",
  content_padding_addition: c.obf.content_padding_addition || "", rekey_after_time: c.obf.rekey_after_time || "", rekey_timeout: c.obf.rekey_timeout || "",
  reject_after_time: c.obf.reject_after_time || "", keepalive_timeout: c.obf.keepalive_timeout || "", max_handshake_attempts: c.obf.max_handshake_attempts || "",
  random_trailers: !!c.obf.random_trailers, disable_cookies: !!c.obf.disable_cookies,
});
const int = (s: string) => parseInt(s, 10) || 0;
const collect = (f: Form) => ({
  enabled: f.enabled,
  protocol: f.protocol || "awg",
  protocol_version: f.protocol_version || undefined,
  traffic_obfuscation: f.traffic_obfuscation,
  install: f.install,
  conn: { host: f.host.trim(), port: int(f.port) || 22, user: f.user.trim() || "root", auth_kind: f.auth_kind, password: f.password, key_pem: f.key_pem, key_pass: f.key_pass, known_key: f.known_key },
  listen_port: int(f.listen_port) || 51820, address: f.address.trim(), subnet: f.subnet.trim(), mtu: int(f.mtu) || 1420,
  dns: f.dns.trim(), wan_iface: f.wan_iface.trim(), endpoint: f.endpoint.trim(),
  obf: {
    jc: int(f.jc), jmin: int(f.jmin), jmax: int(f.jmax), s1: int(f.s1), s2: int(f.s2), s3: int(f.s3), s4: int(f.s4), h1: f.h1.trim() || "1", h2: f.h2.trim() || "2", h3: f.h3.trim() || "3", h4: f.h4.trim() || "4", i1: f.i1.trim(), i2: f.i2.trim(), i3: f.i3.trim(), i4: f.i4.trim(), i5: f.i5.trim(),
    header_protection_key: f.header_protection_key.trim(),
    content_padding_addition: f.content_padding_addition.trim(), rekey_after_time: f.rekey_after_time.trim(), rekey_timeout: f.rekey_timeout.trim(),
    reject_after_time: f.reject_after_time.trim(), keepalive_timeout: f.keepalive_timeout.trim(), max_handshake_attempts: f.max_handshake_attempts.trim(),
    random_trailers: f.random_trailers, disable_cookies: f.disable_cookies,
  },
});

const formatKey = (f: Form) => JSON.stringify({ version: f.protocol_version, enabled: f.traffic_obfuscation, obf: collect(f).obf });

export default function ServerPane({ st, reload, deployActive, deploying, onFormatBusyChange, onOpenEngineSettings }: { st: Awg2Status; reload: () => void; deployActive: () => Promise<boolean>; deploying: boolean; onFormatBusyChange: (busy: boolean) => void; onOpenEngineSettings: () => void }) {
  const [form, setForm] = useState<Form>(() => toForm(st.config));
  const [saving, setSaving] = useState(false);
  const [dirty, setDirty] = useState(false);
  const [applyingFormat, setApplyingFormat] = useState(false);
  const [advanced, setAdvanced] = useState(false);
  const [passwordOpen, setPasswordOpen] = useState(false);
  useEffect(() => {
    setForm(toForm(st.config));
    setDirty(false);
  }, [st.active_server_id]);
  const set = <K extends keyof Form>(k: K, v: Form[K]) => { setDirty(true); setForm((f) => ({ ...f, [k]: v })); };
  const imported = st.config.install === "imported";
  const activeServer = st.servers.find((s) => s.id === st.active_server_id);
  const deploymentNeeded = !!st.deployment_pending;
  const awg3 = form.protocol_version === "3.1";
  const engineIssue = imported ? "" : vpnEngineIssue(st.engine, form.traffic_obfuscation && awg3);
  const formatChanged = !imported && formatKey(form) !== formatKey(toForm(st.config));
  const working = saving || deploying || applyingFormat;
  const configKey = JSON.stringify(st.config);
  useEffect(() => {
    if (!dirty && !working) setForm(toForm(st.config));
  }, [configKey, dirty, working]);

  const saveConfig = async (): Promise<Awg2Status | null> => {
    setSaving(true);
    try {
      const next = await api<Awg2Status>("POST", "/api/awg2/config", collect(form));
      setForm(toForm(next.config));
      setDirty(false);
      await reload();
      return next;
    } catch (e) {
      toast((e as Error).message, "err");
      return null;
    } finally {
      setSaving(false);
    }
  };
  const save = async () => {
    if (working || formatChanged) return;
    const next = await saveConfig();
    if (next) toast(next.deployment_pending ? "Настройки сохранены; для применения разверните сервер" : "Настройки VPN сохранены", "ok");
  };
  const saveAndDeploy = async () => {
    if (working || imported) return;
    if (engineIssue) { toast(engineIssue, "err"); return; }
    if (st.deployed && formatChanged && !(await confirmDialog({
      title: "Изменить формат VPN и развернуть сервер?",
      body: "VPN-соединение прервётся на время развёртывания. На роутере применятся новые параметры; на остальных устройствах нужно заново импортировать клиентские конфиги.",
      confirmLabel: "Сохранить и развернуть",
    }))) return;
    setApplyingFormat(true);
    onFormatBusyChange(true);
    try {
      if (!(await saveConfig())) return;
      if (!(await deployActive())) return;
      await reload();
      toast(st.config.client.enabled ? "Сервер развёрнут, подключение роутера восстанавливается автоматически" : "Сервер развёрнут, туннель на роутере остаётся выключенным", "ok");
    } catch (e) {
      toast("Настройки сохранены, но развёртывание не завершено: " + (e as Error).message, "err");
    } finally {
      setApplyingFormat(false);
      onFormatBusyChange(false);
    }
  };

  return (
    <>
      {!imported && (
        <Card
          title="Развертывание VPS"
          sub="обычно достаточно адреса и пароля"
          head={<Button mini variant="primary" onClick={() => { void deployActive(); }} disabled={working || formatChanged || !st.config.enabled || !st.config.conn.host}>{deploying ? "Деплой..." : st.deployed ? "Переразвернуть этот сервер" : "Развернуть этот сервер"}</Button>}
        >
          <div className="grid gap-3 lg:grid-cols-[minmax(180px,1fr)_110px_140px_auto] lg:items-end">
            <Field label="Адрес VPS">
              <Input value={form.host} placeholder="1.2.3.4 или vpn.example.com" onChange={(e) => set("host", e.target.value)} />
            </Field>
            <Field label="SSH">
              <Input type="number" min={1} max={65535} value={form.port} onChange={(e) => set("port", e.target.value)} />
            </Field>
            <Field label="Пользователь">
              <Input value={form.user} onChange={(e) => set("user", e.target.value)} />
            </Field>
            <Button onClick={save} disabled={working || formatChanged}>{saving ? "..." : "Сохранить доступ"}</Button>
          </div>
          <div className="mt-3 flex flex-wrap items-center gap-2">
            <Badge kind={st.has_password || st.has_key ? "ok" : "warn"}>{st.has_password || st.has_key ? "доступ сохранён" : "нужен доступ SSH"}</Badge>
            {st.has_password && !passwordOpen ? <Button mini onClick={() => setPasswordOpen(true)}>Обновить пароль</Button> : null}
            <Button mini variant="ghost" onClick={() => setAdvanced((v) => !v)}>{advanced ? "Скрыть тонкие настройки" : "Тонкие настройки"}</Button>
          </div>
          {(!st.has_password || passwordOpen) && form.auth_kind === "password" && (
            <div className="mt-3 grid gap-3 sm:grid-cols-[minmax(180px,1fr)_auto] sm:items-end">
              <Field label="Пароль SSH" hint={st.has_password ? "новый пароль, если старый устарел" : ""}>
                <Input type="password" value={form.password} placeholder={st.has_password ? "новый пароль" : ""} onChange={(e) => set("password", e.target.value)} />
              </Field>
              <Button onClick={async () => { await save(); setPasswordOpen(false); }} disabled={working || formatChanged || !form.password}>{saving ? "..." : "Сохранить пароль"}</Button>
            </div>
          )}
        </Card>
      )}

      <Card title="Формат VPN" head={<Badge kind={deploymentNeeded ? "warn" : "neutral"}>{deploymentNeeded ? "Последний успешный: " : ""}{vpnProfileLabel(activeServer || st.config)}</Badge>}>
        {imported ? (
          <p className="text-xs text-muted">{activeServer?.is_warp
            ? "Параметры WARP задаёт провайдер подключения."
            : "Версия и параметры обфускации получены из импортированного профиля. Для их изменения импортируйте обновлённый профиль сервера."}</p>
        ) : (
          <>
            <Switch checked={form.traffic_obfuscation} onChange={(v) => set("traffic_obfuscation", v)} disabled={working} label="Обфускация трафика" />
            <p className="mt-2 text-xs text-muted">{form.traffic_obfuscation
              ? `${awgVersionLabel(form.protocol_version)}: параметры маскировки должны совпадать у сервера и клиентов.`
              : "Обычный формат WireGuard. Шифрование VPN остаётся включённым, параметры обфускации сохраняются для повторного включения."}</p>
            <div className="mt-3 flex flex-wrap items-center gap-2">
              <span className="text-xs text-ink-soft">{deploymentNeeded ? "Сохранённый профиль обфускации" : "Профиль обфускации"}: <b>{awgVersionLabel(form.protocol_version)}</b></span>
              {!awg3 && <Button mini onClick={() => set("protocol_version", "3.1")} disabled={working}>Перейти на AWG 3.1</Button>}
              {form.protocol_version !== (st.config.protocol_version || "") && <Button mini variant="ghost" onClick={() => set("protocol_version", st.config.protocol_version || "")} disabled={working}>Отменить переход</Button>}
            </div>
            {(formatChanged || deploymentNeeded) && <p className="mt-3 rounded-lg bg-warn-bg px-3 py-2 text-xs text-warn">{deploymentNeeded ? "Настройки сохранены, но успешное развёртывание не подтверждено. Роутер и экспорт используют последнюю успешно развёрнутую конфигурацию. Повторите развёртывание." : "Изменения формата применятся после сохранения и развёртывания сервера."} После успешного развёртывания обновите клиентские конфиги на остальных устройствах.</p>}
            {engineIssue && <div className="mt-3 rounded-lg bg-warn-bg px-3 py-2 text-xs text-warn"><p>{engineIssue}</p><Button mini className="mt-2" onClick={onOpenEngineSettings} disabled={working}>Настройки движка</Button></div>}
            <div className="mt-3 flex flex-wrap items-center gap-2">
              <Button variant="primary" onClick={saveAndDeploy} disabled={working || !!engineIssue || !form.host.trim() || !st.config.enabled || (!formatChanged && !deploymentNeeded)}>{applyingFormat ? "Развёртывание…" : "Сохранить и развернуть"}</Button>
              <Button mini variant="ghost" onClick={() => setAdvanced((v) => !v)}>{advanced ? "Скрыть параметры" : "Тонкие настройки"}</Button>
            </div>
          </>
        )}
      </Card>

      <Card
        title="Параметры интерфейса"
        sub={st.deployment_pending || formatChanged ? "изменения применятся после развёртывания сервера" : "локальные параметры клиента на роутере"}
        head={imported ? <Badge kind="neutral">nossh</Badge> : undefined}
      >
        <div className="grid gap-3 sm:grid-cols-[120px_auto] sm:items-end">
          <Field label="MTU">
            <Input type="number" min={1280} max={1500} value={form.mtu} onChange={(e) => set("mtu", e.target.value)} />
          </Field>
          <Button variant="primary" onClick={save} disabled={working || formatChanged}>{saving ? "Сохранение…" : "Сохранить MTU"}</Button>
        </div>
      </Card>

      {advanced && !imported && (
      <Card
        title="Сервер (VPS) и SSH"
        sub="куда и как разворачивать"
      >
        <div className="flex flex-wrap gap-4">
          <Field label="Адрес VPS" className="min-w-[200px] flex-1"><Input value={form.host} placeholder="1.2.3.4 или vpn.example.com" onChange={(e) => set("host", e.target.value)} /></Field>
          <Field label="SSH-порт" className="w-28 shrink-0"><Input type="number" min={1} max={65535} value={form.port} onChange={(e) => set("port", e.target.value)} /></Field>
          <Field label="Пользователь" className="w-36 shrink-0"><Input value={form.user} onChange={(e) => set("user", e.target.value)} /></Field>
        </div>
        <div className="flex flex-wrap gap-4">
          <Field label="Авторизация" className="w-44 shrink-0"><Select value={form.auth_kind} onChange={(e) => set("auth_kind", e.target.value)}><option value="password">Пароль</option><option value="key">SSH-ключ</option></Select></Field>
          {form.auth_kind === "password" ? (
            <Field label="Пароль SSH" hint={st.has_password ? "(сохранён — пусто = не менять)" : ""} className="min-w-[200px] flex-1"><Input type="password" value={form.password} placeholder={st.has_password ? "••••••" : ""} onChange={(e) => set("password", e.target.value)} /></Field>
          ) : (
            <Field label="Пароль ключа" hint="если зашифрован" className="w-48 shrink-0"><Input type="password" value={form.key_pass} placeholder={st.has_key ? "(сохранён)" : ""} onChange={(e) => set("key_pass", e.target.value)} /></Field>
          )}
        </div>
        {form.auth_kind === "key" && (
          <Field label="Приватный SSH-ключ (PEM)" hint={st.has_key ? "(сохранён — пусто = не менять)" : ""}><Textarea rows={4} value={form.key_pem} placeholder={st.has_key ? "(сохранён)" : "-----BEGIN OPENSSH PRIVATE KEY-----"} onChange={(e) => set("key_pem", e.target.value)} /></Field>
        )}
        {form.known_key && <p className="text-[11px] text-muted [overflow-wrap:anywhere]">Ключ хоста закреплён (TOFU): <code>{form.known_key.slice(0, 48)}…</code> <Button mini variant="ghost" onClick={() => set("known_key", "")}>Сбросить</Button></p>}
        <div className="mt-1 flex flex-wrap gap-4">
          <Field label="Метод установки" className="w-64 shrink-0"><Select value={form.install} onChange={(e) => set("install", e.target.value)}><option value="apt">apt (модуль ядра) + fallback</option><option value="userspace">userspace amneziawg-go</option><option value="imported">imported (без SSH-деплоя)</option></Select></Field>
        </div>
      </Card>
      )}

      {advanced && !imported && (
      <Card title="Сеть туннеля">
        <div className="flex flex-wrap gap-4">
          <Field label="UDP-порт" className="w-32 shrink-0"><Input type="number" min={1} max={65535} value={form.listen_port} onChange={(e) => set("listen_port", e.target.value)} /></Field>
          <Field label="WAN-интерфейс" hint="пусто = авто" className="w-40 shrink-0"><Input value={form.wan_iface} placeholder="eth0" onChange={(e) => set("wan_iface", e.target.value)} /></Field>
        </div>
        <div className="flex flex-wrap gap-4">
          <Field label="Адрес сервера" className="w-44 shrink-0"><Input value={form.address} placeholder="10.13.13.1/24" onChange={(e) => set("address", e.target.value)} /></Field>
          <Field label="Подсеть (NAT)" className="w-44 shrink-0"><Input value={form.subnet} placeholder="10.13.13.0/24" onChange={(e) => set("subnet", e.target.value)} /></Field>
          <Field label="DNS для клиентов" className="min-w-[160px] flex-1"><Input value={form.dns} placeholder="1.1.1.1, 1.0.0.1" onChange={(e) => set("dns", e.target.value)} /></Field>
        </div>
        <Field label="Endpoint для клиентов" hint="пусто = адрес VPS : UDP-порт"><Input value={form.endpoint} placeholder="vpn.example.com:51820" onChange={(e) => set("endpoint", e.target.value)} /></Field>
      </Card>
      )}

      {advanced && !imported && form.traffic_obfuscation ? (
      <Card title={`Параметры ${awgVersionLabel(form.protocol_version)}`} sub="создаются автоматически при развёртывании">
        <div className="flex flex-wrap gap-3">
          <Field label="Jc" className="w-20 shrink-0"><Input type="number" value={form.jc} onChange={(e) => set("jc", e.target.value)} /></Field>
          <Field label="Jmin" className="w-20 shrink-0"><Input type="number" value={form.jmin} onChange={(e) => set("jmin", e.target.value)} /></Field>
          <Field label="Jmax" className="w-20 shrink-0"><Input type="number" value={form.jmax} onChange={(e) => set("jmax", e.target.value)} /></Field>
          <Field label="S1" className="w-20 shrink-0"><Input type="number" value={form.s1} onChange={(e) => set("s1", e.target.value)} /></Field>
          <Field label="S2" className="w-20 shrink-0"><Input type="number" value={form.s2} onChange={(e) => set("s2", e.target.value)} /></Field>
          <Field label="S3" className="w-20 shrink-0"><Input type="number" value={form.s3} onChange={(e) => set("s3", e.target.value)} /></Field>
          <Field label="S4" className="w-20 shrink-0"><Input type="number" value={form.s4} onChange={(e) => set("s4", e.target.value)} /></Field>
        </div>
        <div className="flex flex-wrap gap-3">
          <Field label="H1" hint="число или x-y" className="w-32 shrink-0"><Input value={form.h1} onChange={(e) => set("h1", e.target.value)} /></Field>
          <Field label="H2" className="w-32 shrink-0"><Input value={form.h2} onChange={(e) => set("h2", e.target.value)} /></Field>
          <Field label="H3" className="w-32 shrink-0"><Input value={form.h3} onChange={(e) => set("h3", e.target.value)} /></Field>
          <Field label="H4" className="w-32 shrink-0"><Input value={form.h4} onChange={(e) => set("h4", e.target.value)} /></Field>
        </div>
        <Field label="Сигнатурные пакеты I1–I5" hint="необязательно (CPS), напр. <b 0x..><r 12><t>">
          <div className="space-y-1.5">
            {(["i1", "i2", "i3", "i4", "i5"] as const).map((k) => (
              <Input key={k} value={form[k]} placeholder={k.toUpperCase()} className="font-mono text-xs" onChange={(e) => set(k, e.target.value)} />
            ))}
          </div>
        </Field>
        {awg3 && (
          <div className="mt-4 space-y-3 border-t border-line-soft pt-3">
            <Field label="HeaderProtectionKey" hint={st.config.obf.has_header_protection_key ? "сохранён — пусто = не менять" : "создаётся автоматически"}>
              <Input type="password" autoComplete="new-password" value={form.header_protection_key} onChange={(e) => set("header_protection_key", e.target.value)} placeholder={st.config.obf.has_header_protection_key ? "••••••" : "автоматически"} className="font-mono text-xs" />
            </Field>
            <div className="grid gap-3 sm:grid-cols-2">
              {AWG3_FIELDS.map(([key, label]) => <Field key={key} label={label} hint="число или диапазон"><Input value={form[key]} onChange={(e) => set(key, e.target.value)} placeholder="автоматически" className="font-mono text-xs" /></Field>)}
            </div>
            <div className="flex flex-wrap gap-4">
              <Switch checked={form.random_trailers} onChange={(v) => set("random_trailers", v)} disabled={working} label="RandomTrailers" />
              <Switch checked={form.disable_cookies} onChange={(v) => set("disable_cookies", v)} disabled={working} label="DisableCookies" />
            </div>
          </div>
        )}
        <div className="mt-3 flex flex-wrap items-center gap-2.5"><Button variant="primary" onClick={saveAndDeploy} disabled={working || !!engineIssue || !form.host.trim() || !st.config.enabled || (!formatChanged && !deploymentNeeded)}>{applyingFormat ? "Развёртывание…" : "Сохранить и развернуть"}</Button></div>
      </Card>
      ) : null}
    </>
  );
}
