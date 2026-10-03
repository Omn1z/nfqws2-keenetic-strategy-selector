import { useCallback, useEffect, useRef, useState } from "react";
import { api } from "@/lib/api";
import { Badge } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import { Card } from "@/components/ui/Card";
import { Field, Select } from "@/components/ui/form";
import { Modal } from "@/components/ui/Modal";
import { Switch } from "@/components/ui/Switch";
import { EmptyRow, TableWrap, tableCls, tdCls, thBase } from "@/components/ui/Table";
import { toast } from "@/components/ui/Toast";
import { canApplyARPBlockIsolation, editARPBlockIsolation, emptyARPBlockEditor, receiveARPBlockView } from "./state";
import type { ARPBlockView } from "./types";

const checkedTime = (unix: number) => unix ? new Date(unix * 1000).toLocaleString("ru-RU", { hour12: false }) : "—";
const errorMessage = (error: unknown) => error instanceof Error ? error.message : "Не удалось получить ответ роутера";

export default function ARPBlock() {
  const [editor, setEditor] = useState(emptyARPBlockEditor);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [confirming, setConfirming] = useState(false);
  const [error, setError] = useState("");
  const [needsRefresh, setNeedsRefresh] = useState(false);
  const reading = useRef<AbortController | null>(null);
  const writing = useRef<AbortController | null>(null);

  const refresh = useCallback(async () => {
    reading.current?.abort();
    const controller = new AbortController();
    reading.current = controller;
    setLoading(true);
    setError("");
    try {
      const view = await api<ARPBlockView>("GET", "/api/arp-block", undefined, { signal: controller.signal, timeoutMs: 25_000 });
      if (reading.current !== controller || controller.signal.aborted) return;
      setEditor(previous => receiveARPBlockView(previous, view));
      setNeedsRefresh(false);
    } catch (err) {
      if (reading.current === controller && !controller.signal.aborted) setError(errorMessage(err));
    } finally {
      if (reading.current === controller) {
        reading.current = null;
        setLoading(false);
      }
    }
  }, []);

  useEffect(() => {
    void refresh();
    return () => {
      reading.current?.abort();
      writing.current?.abort();
      reading.current = null;
      writing.current = null;
    };
  }, [refresh]);

  const { view, selected, draft } = editor;
  const segment = view?.segments.find(item => item.id === selected);
  const clients = view?.clients.filter(client => client.segment === selected) ?? [];
  const stale = !!(draft && view && draft.revision !== view.revision);
  const canApply = canApplyARPBlockIsolation(editor) && !saving && !loading && !needsRefresh;

  const resetDraft = () => setEditor(previous => previous.view
    ? receiveARPBlockView({ ...previous, draft: null }, previous.view)
    : previous);

  const apply = async () => {
    if (!canApply || !draft || writing.current) return;
    reading.current?.abort();
    reading.current = null;
    const controller = new AbortController();
    writing.current = controller;
    setSaving(true);
    setError("");
    try {
      const next = await api<ARPBlockView>("POST", "/api/arp-block/isolation", draft, { signal: controller.signal, timeoutMs: 65_000 });
      if (writing.current !== controller || controller.signal.aborted) return;
      setEditor(previous => receiveARPBlockView({ ...previous, draft: null }, next));
      setNeedsRefresh(false);
      toast("Настройка изоляции применена", "ok");
    } catch (err) {
      if (writing.current === controller && !controller.signal.aborted) {
        setError(errorMessage(err));
        setNeedsRefresh(true);
      }
    } finally {
      if (writing.current === controller) {
        writing.current = null;
        setSaving(false);
        setConfirming(false);
      }
    }
  };

  return (
    <>
      <Card title="ARP Block" sub="Встроенная изоляция Wi-Fi клиентов Keenetic" head={
        <Button onClick={() => void refresh()} disabled={saving || confirming} aria-busy={loading}>
          {loading ? "Обновление…" : "Обновить"}
        </Button>
      }>
        <p className="text-sm text-muted-foreground">
          Управляет настройкой peer-isolation выбранного сегмента. Она применяется ко всем его Wi-Fi клиентам.
        </p>
        {view && <div className="mt-3 flex flex-wrap items-center gap-2 text-xs text-muted-foreground">
          <Badge kind={view.supported ? "neutral" : "bad"}>{view.platform || "Платформа не определена"}</Badge>
          <span>Проверено: {checkedTime(view.checked_at)}</span>
        </div>}
        {error && <div role="alert" className="mt-3 rounded-md border border-bad/30 bg-bad-bg p-3 text-sm text-bad [overflow-wrap:anywhere]">{error}</div>}
        {needsRefresh && <p role="status" className="mt-3 text-sm text-muted-foreground">Сначала обновите состояние: настройка могла примениться, даже если ответ не получен.</p>}
        {!view && <p role="status" className="mt-3 text-sm text-muted-foreground">{loading ? "Читаем сегменты и состояние изоляции…" : "Данные не загружены. Повторите обновление."}</p>}
        {view && (view.reason || !view.supported) && <p role="status" className="mt-3 text-sm text-muted-foreground">{view.reason || "Встроенная изоляция Wi-Fi на этой платформе недоступна."}</p>}
      </Card>

      {view && <Card title="Изоляция сегмента" head={segment && <Badge kind={segment.enabled ? "ok" : "neutral"}>{segment.enabled ? "Включена на роутере" : "Выключена на роутере"}</Badge>}>
        <div className="grid min-w-0 gap-4 md:grid-cols-2">
          <Field label="Сегмент" hint={draft ? "сначала примените или отмените изменения" : undefined}>
            <Select value={selected} onChange={event => setEditor(previous => ({ ...previous, selected: event.target.value }))} disabled={saving || !!draft || !view.segments.length}>
              {!view.segments.length && <option value="">Сегменты не найдены</option>}
              {selected && !segment && <option value={selected}>{selected} — больше не найден</option>}
              {view.segments.map(item => <option key={item.id} value={item.id}>{item.name || item.id}{item.name && item.name !== item.id ? ` · ${item.id}` : ""}{item.home ? " · домашний" : ""}</option>)}
            </Select>
          </Field>
          <div className="flex min-w-0 items-center md:pt-6">
            <Switch checked={draft?.enabled ?? segment?.enabled ?? false}
              onChange={enabled => setEditor(previous => editARPBlockIsolation(previous, enabled))}
              disabled={saving || !view.supported || !view.revision || !segment?.eligible || stale || needsRefresh}
              label="Изолировать всех Wi-Fi клиентов" />
          </div>
        </div>
        {segment && <dl className="mt-4 grid gap-3 rounded-md bg-line-soft p-3 text-sm sm:grid-cols-2 lg:grid-cols-4">
          <div><dt className="text-xs text-muted-foreground">SSID</dt><dd className="mt-1 [overflow-wrap:anywhere]">{segment.ssids.join(", ") || "Не указан"}</dd></div>
          <div><dt className="text-xs text-muted-foreground">Адрес сегмента</dt><dd className="mt-1 font-mono text-xs">{segment.address || "—"}</dd></div>
          <div><dt className="text-xs text-muted-foreground">Интерфейсы</dt><dd className="mt-1 font-mono text-xs [overflow-wrap:anywhere]">{segment.members.join(", ") || "—"}</dd></div>
          <div><dt className="text-xs text-muted-foreground">Состояние сегмента</dt><dd className="mt-1">{segment.up ? "Активен" : "Неактивен"}</dd></div>
        </dl>}
        {segment && !segment.eligible && <p role="status" className="mt-3 text-sm text-muted-foreground">{segment.reason || "Изоляция для этого сегмента недоступна."}</p>}
        <div className="mt-4 space-y-2 text-sm text-muted-foreground">
          <p>Настройка затрагивает все Wi-Fi устройства сегмента, а не только выбранную колонку или телефон. Локальное управление устройствами, трансляция и обнаружение принтеров могут перестать работать.</p>
          <p>Связь проводных устройств между собой не изолируется. Локальные DNS-имена и доступ к сервисам самого роутера настраиваются отдельно; для отдельной политики IoT нужен свой сегмент.</p>
        </div>
        {stale && <p role="alert" className="mt-3 text-sm text-bad">Состояние роутера изменилось. Черновик сохранён: отмените изменения, проверьте новое состояние и выберите настройку снова.</p>}
        <div className="mt-4 flex flex-wrap items-center gap-2">
          <Button variant="primary" disabled={!canApply} onClick={() => setConfirming(true)}>{saving ? "Применение…" : "Применить"}</Button>
          {draft && <Button disabled={saving} onClick={resetDraft}>Отменить изменения</Button>}
          {draft && <span className="text-xs text-muted-foreground">Есть неприменённые изменения</span>}
        </div>
      </Card>}

      <Card title="Какие режимы доступны">
        <dl className="grid gap-4 text-sm md:grid-cols-3">
          <div><dt className="font-medium">Все Wi-Fi клиенты сегмента</dt><dd className="mt-1 text-muted-foreground">Поддерживается встроенной изоляцией Keenetic. Это режим переключателя выше.</dd></div>
          <div><dt className="font-medium">Только выбранные устройства</dt><dd className="mt-1 text-muted-foreground">Выборочная изоляция по MAC этим механизмом не поддерживается. Нужен отдельный SSID/VLAN и перенос устройств в него.</dd></div>
          <div><dt className="font-medium">Все, кроме разрешённых</dt><dd className="mt-1 text-muted-foreground">Исключений по MAC здесь нет. Разрешённые связи задаются отдельно между сегментами.</dd></div>
        </dl>
      </Card>

      {view && <Card title="Известные устройства" sub={segment ? `${segment.name || segment.id} · ${clients.length}` : "Сегмент не выбран"}>
        <p className="mb-3 text-xs text-muted-foreground">Сведения роутера на момент обновления. Это список для просмотра; выбор отдельных устройств для изоляции здесь недоступен.</p>
        <TableWrap scrollable>
          <table className={tableCls}>
            <thead><tr><th className={thBase}>Устройство</th><th className={thBase}>IP</th><th className={thBase}>MAC</th><th className={thBase}>Точка доступа</th></tr></thead>
            <tbody>
              {!clients.length && <EmptyRow colSpan={4}>Известных устройств в выбранном сегменте нет</EmptyRow>}
              {clients.map((client, index) => <tr key={`${client.mac}-${client.ip}-${index}`}>
                <td className={tdCls}>{client.hostname || "Без имени"}</td>
                <td className={`${tdCls} font-mono text-xs`}>{client.ip || "—"}</td>
                <td className={`${tdCls} whitespace-nowrap font-mono text-xs`}>{client.mac || "—"}</td>
                <td className={tdCls}>{client.ap || "Не определена"}</td>
              </tr>)}
            </tbody>
          </table>
        </TableWrap>
      </Card>}

      {confirming && draft && segment && <Modal title={draft.enabled ? "Включить изоляцию сегмента?" : "Отключить изоляцию сегмента?"}
        onClose={() => { if (!saving) setConfirming(false); }} actions={<>
          <Button disabled={saving} onClick={() => setConfirming(false)}>Отмена</Button>
          <Button variant="primary" disabled={!canApply} onClick={() => void apply()}>{saving ? "Применение…" : draft.enabled ? "Включить изоляцию" : "Отключить изоляцию"}</Button>
        </>}>
        <p><strong>{segment.name || segment.id}</strong> ({segment.id}){segment.address ? ` · ${segment.address}` : ""}</p>
        <p className="mt-2">Wi-Fi: {segment.ssids.join(", ") || "SSID не указан"}.</p>
        <p className="mt-3">{draft.enabled
          ? "Изоляция будет включена для всех Wi-Fi клиентов этого сегмента. Она затронет и ваши телефоны, компьютеры и другие беспроводные устройства. Локальное управление, трансляция и обнаружение устройств могут перестать работать."
          : "Встроенная изоляция будет снята для всех Wi-Fi клиентов этого сегмента. Локальные соединения, которые она ограничивала, снова будут разрешены этим механизмом."}</p>
        <p className="mt-3">Связь проводных устройств между собой, локальные DNS-имена и доступ к сервисам роутера эта настройка не изолирует. Для отдельной политики колонки или других IoT устройств нужен отдельный сегмент.</p>
        {segment.home && <p className="mt-3 font-medium">Вы меняете изоляцию домашнего сегмента.</p>}
        {saving && <p role="status" className="mt-3 text-muted-foreground">Ожидаем подтверждение роутера. Не применяйте настройку повторно.</p>}
      </Modal>}
    </>
  );
}
