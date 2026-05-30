import { useState } from "react";
import { api } from "@/lib/api";
import { toast } from "@/components/ui/Toast";
import { Card } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { Field, Input, Select, Textarea } from "@/components/ui/form";
import type { Awg2Status, AwgServerConfig } from "@/types/api";

interface Form {
  host: string; port: string; user: string; auth_kind: string;
  password: string; key_pem: string; key_pass: string;
  install: string;
  listen_port: string; address: string; subnet: string; mtu: string; dns: string; wan_iface: string; endpoint: string;
  jc: string; jmin: string; jmax: string; s1: string; s2: string; s3: string; s4: string;
  h1: string; h2: string; h3: string; h4: string;
  i1: string; i2: string; i3: string; i4: string; i5: string;
}

const S = (n: number | undefined) => String(n ?? "");
const toForm = (c: AwgServerConfig): Form => ({
  host: c.conn.host || "", port: S(c.conn.port || 22), user: c.conn.user || "root", auth_kind: c.conn.auth_kind || "password",
  password: "", key_pem: "", key_pass: "",
  install: c.install || "apt",
  listen_port: S(c.listen_port || 51820), address: c.address || "", subnet: c.subnet || "", mtu: S(c.mtu || 1420),
  dns: c.dns || "", wan_iface: c.wan_iface || "", endpoint: c.endpoint || "",
  jc: S(c.obf.jc), jmin: S(c.obf.jmin), jmax: S(c.obf.jmax), s1: S(c.obf.s1), s2: S(c.obf.s2), s3: S(c.obf.s3), s4: S(c.obf.s4),
  h1: c.obf.h1 || "1", h2: c.obf.h2 || "2", h3: c.obf.h3 || "3", h4: c.obf.h4 || "4",
  i1: c.obf.i1 || "", i2: c.obf.i2 || "", i3: c.obf.i3 || "", i4: c.obf.i4 || "", i5: c.obf.i5 || "",
});
const int = (s: string) => parseInt(s, 10) || 0;
const collect = (f: Form) => ({
  install: f.install,
  conn: { host: f.host.trim(), port: int(f.port) || 22, user: f.user.trim() || "root", auth_kind: f.auth_kind, password: f.password, key_pem: f.key_pem, key_pass: f.key_pass, known_key: "" },
  listen_port: int(f.listen_port) || 51820, address: f.address.trim(), subnet: f.subnet.trim(), mtu: int(f.mtu) || 1420,
  dns: f.dns.trim(), wan_iface: f.wan_iface.trim(), endpoint: f.endpoint.trim(),
  obf: { jc: int(f.jc), jmin: int(f.jmin), jmax: int(f.jmax), s1: int(f.s1), s2: int(f.s2), s3: int(f.s3), s4: int(f.s4), h1: f.h1.trim() || "1", h2: f.h2.trim() || "2", h3: f.h3.trim() || "3", h4: f.h4.trim() || "4", i1: f.i1.trim(), i2: f.i2.trim(), i3: f.i3.trim(), i4: f.i4.trim(), i5: f.i5.trim() },
});

export default function ServerPane({ st, reload }: { st: Awg2Status; reload: () => void }) {
  const [form, setForm] = useState<Form>(() => toForm(st.config));
  const [saving, setSaving] = useState(false);
  const set = <K extends keyof Form>(k: K, v: Form[K]) => setForm((f) => ({ ...f, [k]: v }));

  const save = async () => {
    setSaving(true);
    try {
      await api("POST", "/api/awg2/config", collect(form));
      await reload();
      toast("Настройки AWG2 сохранены", "ok");
    } catch (e) {
      toast((e as Error).message, "err");
    } finally {
      setSaving(false);
    }
  };

  return (
    <>
      <Card title="Сервер (VPS) и SSH" sub="куда и как разворачивать">
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
        {st.config.conn.known_key && <p className="text-[11px] text-muted [overflow-wrap:anywhere]">Ключ хоста закреплён (TOFU): <code>{st.config.conn.known_key.slice(0, 48)}…</code></p>}
        <div className="mt-1 flex flex-wrap gap-4">
          <Field label="Метод установки" className="w-64 shrink-0"><Select value={form.install} onChange={(e) => set("install", e.target.value)}><option value="apt">apt (модуль ядра) + fallback</option><option value="userspace">userspace amneziawg-go</option></Select></Field>
        </div>
      </Card>

      <Card title="Сеть туннеля">
        <div className="flex flex-wrap gap-4">
          <Field label="UDP-порт" className="w-32 shrink-0"><Input type="number" min={1} max={65535} value={form.listen_port} onChange={(e) => set("listen_port", e.target.value)} /></Field>
          <Field label="MTU" className="w-28 shrink-0"><Input type="number" min={1280} max={1500} value={form.mtu} onChange={(e) => set("mtu", e.target.value)} /></Field>
          <Field label="WAN-интерфейс" hint="пусто = авто" className="w-40 shrink-0"><Input value={form.wan_iface} placeholder="eth0" onChange={(e) => set("wan_iface", e.target.value)} /></Field>
        </div>
        <div className="flex flex-wrap gap-4">
          <Field label="Адрес сервера" className="w-44 shrink-0"><Input value={form.address} placeholder="10.13.13.1/24" onChange={(e) => set("address", e.target.value)} /></Field>
          <Field label="Подсеть (NAT)" className="w-44 shrink-0"><Input value={form.subnet} placeholder="10.13.13.0/24" onChange={(e) => set("subnet", e.target.value)} /></Field>
          <Field label="DNS для клиентов" className="min-w-[160px] flex-1"><Input value={form.dns} placeholder="1.1.1.1, 1.0.0.1" onChange={(e) => set("dns", e.target.value)} /></Field>
        </div>
        <Field label="Endpoint для клиентов" hint="пусто = адрес VPS : UDP-порт"><Input value={form.endpoint} placeholder="vpn.example.com:51820" onChange={(e) => set("endpoint", e.target.value)} /></Field>
      </Card>

      <Card title="Обфускация AmneziaWG 2.0" sub="случайная при первом деплое; должна совпадать у сервера и клиента">
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
        <Field label="Сигнатурные пакеты I1–I5" hint="2.0, необязательно (CPS), напр. <b 0x..><r 12><t>">
          <div className="space-y-1.5">
            {(["i1", "i2", "i3", "i4", "i5"] as const).map((k) => (
              <Input key={k} value={form[k]} placeholder={k.toUpperCase()} className="font-mono text-xs" onChange={(e) => set(k, e.target.value)} />
            ))}
          </div>
        </Field>
        <div className="mt-2 flex flex-wrap items-center gap-2.5"><Button variant="primary" onClick={save} disabled={saving}>{saving ? "Сохранение…" : "Сохранить настройки"}</Button><span className="text-xs text-muted">деплой — кнопкой «Развернуть сервер» вверху</span></div>
      </Card>
    </>
  );
}
