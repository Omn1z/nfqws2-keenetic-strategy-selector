import { useState } from "react";
import type { FormEvent } from "react";
import { api } from "@/lib/api";
import { Button } from "@/components/ui/Button";
import { Field, Input } from "@/components/ui/form";

export function Login({ onSuccess }: { onSuccess: () => void }) {
  const [user, setUser] = useState("root");
  const [pass, setPass] = useState("");
  const [err, setErr] = useState("");

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setErr("");
    try {
      await api("POST", "/api/auth/login", { user, password: pass });
      onSuccess();
    } catch (ex) {
      setErr((ex as Error).message);
    }
  };

  return (
    <div className="fixed inset-0 z-[60] grid place-items-center bg-[rgba(20,30,45,.55)] backdrop-blur-sm">
      <form onSubmit={submit} className="w-[340px] rounded-2xl border border-line bg-panel p-9 text-center shadow-2xl">
        <span className="mx-auto mb-1 grid h-12 w-12 place-items-center rounded-[14px] bg-gradient-to-br from-[#36a3ff] to-accent-d text-white">
          <svg viewBox="0 0 24 24" width="26" height="26"><path d="M13 2 4 14h6l-1 8 9-12h-6z" fill="currentColor" /></svg>
        </span>
        <h3 className="mb-0.5 mt-3 text-lg font-semibold">Вход</h3>
        <p className="mb-3 text-xs text-muted">Логин и пароль роутера (как в веб-интерфейсе nfqws).</p>
        <div className="space-y-3 text-left">
          <Field label="Логин"><Input autoComplete="username" value={user} onChange={(e) => setUser(e.target.value)} /></Field>
          <Field label="Пароль"><Input type="password" autoComplete="current-password" value={pass} onChange={(e) => setPass(e.target.value)} /></Field>
        </div>
        <Button variant="primary" type="submit" className="mt-4 w-full">Войти</Button>
        <div className="mt-2 min-h-[18px] text-[13px] text-bad">{err}</div>
      </form>
    </div>
  );
}
