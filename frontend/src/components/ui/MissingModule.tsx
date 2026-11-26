import { useEffect, useState } from "react";
import { api } from "@/lib/api";

export function MissingModule({ name }: { name: string }) {
  const pkg = `nfqws2-strategy-${name}`;
  const [available, setAvailable] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  useEffect(() => {
    const controller = new AbortController();
    api<{ packages: string[] }>("GET", "/api/modules", undefined, { signal: controller.signal })
      .then(data => setAvailable(data.packages.includes(pkg))).catch(() => {});
    return () => controller.abort();
  }, [pkg]);
  const install = async () => {
    setBusy(true);
    setError("");
    try {
      const result = await api<{ ok: boolean; error?: string }>("POST", "/api/system/install", { package: pkg });
      if (!result.ok) throw new Error(result.error || "Ошибка установки");
      location.reload();
    } catch (e) {
      setError((e as Error).message);
      setBusy(false);
    }
  };
  return <section role="alert" className="space-y-3">
    <h2 className="text-lg font-medium">Не удалось загрузить раздел</h2>
    <p>Для этого раздела нужен пакет из репозитория вашей версии панели.</p>
    <code>opkg install {pkg}</code>
    <div className="flex gap-4">
      {available && <button className="underline" disabled={busy} onClick={install}>{busy ? "Установка…" : "Установить пакет"}</button>}
      <button className="underline" disabled={busy} onClick={() => location.reload()}>Обновить страницу</button>
    </div>
    {error && <p className="text-bad">{error}</p>}
  </section>;
}
