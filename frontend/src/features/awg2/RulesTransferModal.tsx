import { useEffect, useRef, useState } from "react";
import { api } from "@/lib/api";
import { Modal } from "@/components/ui/Modal";
import { Button } from "@/components/ui/Button";
import { Badge } from "@/components/ui/Badge";
import { Field, Select } from "@/components/ui/form";
import { confirmDialog } from "@/components/ui/Confirm";
import type { Awg2ServerSummary, AwgRoutingConfig, AwgRulesImportMode, AwgRulesImportPlan, AwgRulesImportRequest, AwgRulesMappings } from "@/types/api";
import { buildRuleImportRequest, captureRoutingDraft, initialRuleMappings, parseRulesDocument, refreshedRuleMappings, RULES_FILE_LIMIT } from "./routingRules";

export type RoutingReadTask = <T>(work: () => Promise<T>) => Promise<T>;
export type ImportRoutingRules = (request: AwgRulesImportRequest) => Promise<boolean>;

interface Props {
  tunnels: Awg2ServerSummary[];
  currentRuleCount: number;
  baseRouting: AwgRoutingConfig;
  hasDraft: boolean;
  saving: boolean;
  runRead: RoutingReadTask;
  importRules: ImportRoutingRules;
  onClose: () => void;
}

const UNCHOSEN = "\u0000choose";
const titleFor = (s: { label?: string; id?: string; ref?: string; endpoint?: string; client_iface?: string; protocol?: string }) =>
  [s.label || s.id || s.ref, s.endpoint, s.client_iface, s.protocol].filter(Boolean).join(" · ");

export default function RulesTransferModal({ tunnels, currentRuleCount, baseRouting, hasDraft, saving, runRead, importRules, onClose }: Props) {
  const [document, setDocument] = useState<string | null>(null);
  const [plan, setPlan] = useState<AwgRulesImportPlan | null>(null);
  const [filename, setFilename] = useState("");
  const [mappings, setMappings] = useState<AwgRulesMappings>({});
  const [mode, setMode] = useState<AwgRulesImportMode>("append");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [capturedBase, setCapturedBase] = useState<AwgRoutingConfig | null>(null);
  const [originalPolicyHash, setOriginalPolicyHash] = useState("");
  const working = useRef(false);
  const mounted = useRef(true);
  const previewController = useRef<AbortController | null>(null);
  useEffect(() => {
    mounted.current = true;
    return () => { mounted.current = false; previewController.current?.abort(); };
  }, []);
  const availableTunnels = tunnels.filter((s) => s.imported || s.deployed || s.endpoint);
  const targetIDs = new Set(availableTunnels.map((s) => s.id));

  const chooseFile = async (file?: File) => {
    if (!file || working.current || saving) return;
    working.current = true;
    setBusy(true);
    setError("");
    // A failed replacement preview cannot leave an earlier file importable.
    setDocument(null);
    setPlan(null);
    setMappings({});
    setCapturedBase(null);
    setOriginalPolicyHash("");
    setFilename(file.name);
    const controller = new AbortController();
    previewController.current = controller;
    try {
      if (file.size > RULES_FILE_LIMIT) throw new Error("Файл правил превышает 2 МиБ.");
      const doc = await file.text();
      parseRulesDocument(doc);
      const base = captureRoutingDraft(baseRouting, new Set(tunnels.map((tunnel) => tunnel.id)));
      if (!mounted.current) return;
      const preview = await runRead(() => api<AwgRulesImportPlan>("POST", "/api/awg2/routing/rules/import/preview", { document: doc }, { signal: controller.signal, readOnly: true }));
      if (!mounted.current || controller.signal.aborted) return;
      setDocument(doc);
      setPlan(preview);
      setMappings(initialRuleMappings(preview));
      setCapturedBase(base);
      setOriginalPolicyHash(preview.policy_hash);
    } catch (e) {
      if (mounted.current && !controller.signal.aborted) setError((e as Error).message);
    } finally {
      working.current = false;
      if (mounted.current) setBusy(false);
    }
  };

  const refreshPreview = async () => {
    if (!document || !plan || working.current || saving) return;
    working.current = true;
    setBusy(true);
    setError("");
    const controller = new AbortController();
    previewController.current = controller;
    try {
      const next = await runRead(() => api<AwgRulesImportPlan>("POST", "/api/awg2/routing/rules/import/preview", { document }, { signal: controller.signal, readOnly: true }));
      if (!mounted.current || controller.signal.aborted) return;
      setMappings(refreshedRuleMappings(plan, mappings, next));
      setPlan(next);
    } catch (e) {
      if (mounted.current && !controller.signal.aborted) setError((e as Error).message);
    } finally { working.current = false; if (mounted.current) setBusy(false); }
  };

  const apply = async () => {
    if (!document || !plan || !capturedBase || working.current || saving) return;
    let request: AwgRulesImportRequest;
    try { request = buildRuleImportRequest(document, plan, mappings, targetIDs, mode, capturedBase); }
    catch (e) { setError((e as Error).message); return; }
    working.current = true;
    setBusy(true);
    setError("");
    try {
      if (mode === "replace" && !(await confirmDialog({
        title: "Заменить все правила маршрутизации?",
        body: `${currentRuleCount} текущих правил будут заменены ${plan.rule_count} правилами из файла. Общие настройки маршрутизации будут взяты из файла.${hasDraft ? " Несохранённые изменения на этой вкладке будут заменены." : ""}`,
        confirmLabel: "Заменить правила", danger: true,
      }))) return;
      if (mode === "append" && originalPolicyHash !== plan.policy_hash && !(await confirmDialog({
        title: "Применить сохранённый снимок правил?",
        body: "С момента первой проверки правила на роутере изменились. Добавление применит снимок списка и настроек с этой вкладки на момент выбора файла, включая несохранённые правки. Более поздние изменения могут быть заменены.",
        confirmLabel: "Применить снимок", danger: true,
      }))) return;
      const saved = await importRules(request);
      if (saved && mounted.current) onClose();
      else if (mounted.current) setError("Импорт не подтверждён. Файл, сопоставления и снимок вкладки сохранены для повторной попытки. При конфликте обновите проверку.");
    } catch (e) {
      if (mounted.current) setError((e as Error).message);
    } finally {
      working.current = false;
      if (mounted.current) setBusy(false);
    }
  };

  const unresolved = plan?.connections.filter((item) => !Object.hasOwn(mappings, item.source.ref) ||
    (mappings[item.source.ref] !== "" && !targetIDs.has(mappings[item.source.ref]))).length || 0;
  return (
    <Modal title="Импорт правил маршрутизации" size="lg" onClose={() => { if (!working.current) onClose(); }} actions={
      <>
        <Button variant="ghost" onClick={onClose} disabled={busy}>Отмена</Button>
        <Button variant="primary" onClick={() => { void apply(); }} disabled={busy || saving || !plan || !capturedBase || !plan.policy_hash || unresolved > 0}>
          {busy ? "Обрабатываем…" : mode === "replace" ? "Заменить правила" : "Добавить правила"}
        </Button>
      </>
    }>
      <div className="space-y-4">
        <Field label="Файл экспорта JSON" hint="до 2 МиБ">
          <input type="file" accept="application/json,.json" disabled={busy || saving} className="block w-full text-xs"
            onChange={(e) => { const file = e.target.files?.[0]; e.target.value = ""; void chooseFile(file); }} />
        </Field>
        {busy && <p className="text-xs text-muted" role="status">Обрабатываем правила и подключения…</p>}
        {error && <p className="text-xs text-bad" role="alert">{error}</p>}
        {plan && <>
          <div className="flex flex-wrap items-center justify-between gap-2"><p className="text-xs">{filename}: <b>{plan.rule_count}</b> правил.</p>
            <Button mini onClick={() => { void refreshPreview(); }} disabled={busy || saving}>Обновить проверку</Button>
          </div>
          <p className="text-xs text-muted">Порядок, домены, IP и резервные подключения сохраняются. Адреса источников LAN переносятся без изменений — проверьте их на новом роутере.</p>
          <Field label="Как импортировать">
            <Select value={mode} disabled={busy || saving} onChange={(e) => setMode(e.target.value as AwgRulesImportMode)}>
              <option value="append">Добавить в конец текущего списка</option>
              <option value="replace">Заменить все правила и настройки маршрутизации</option>
            </Select>
          </Field>
          {mode === "append" && <p className="text-xs text-muted">Используется снимок правил и настроек на этой вкладке на момент выбора файла, включая несохранённые изменения. Импортированные правила добавляются после них; повторная попытка использует тот же снимок.</p>}
          <div className="space-y-3">
            {plan.connections.map((item) => {
              const matched = item.state === "matched" && !item.reason;
              const choices = item.candidates.filter((candidate) => candidate.fingerprint && targetIDs.has(candidate.id));
              return <div key={item.source.ref} className="rounded-lg border border-line bg-panel-soft/40 p-3">
                <div className="mb-2 flex flex-wrap items-center gap-2">
                  <span className="text-xs font-medium [overflow-wrap:anywhere]">{titleFor(item.source)}</span>
                  <Badge kind={matched ? "ok" : "warn"}>{matched ? "Совпадение подтверждено" : item.reason === "identity_changed" ? "Подключение изменилось" : item.state === "ambiguous" ? "Несколько совпадений" : "Подключение не найдено"}</Badge>
                </div>
                <Select value={Object.hasOwn(mappings, item.source.ref) ? mappings[item.source.ref] : UNCHOSEN}
                  disabled={busy || saving} aria-label={`Подключение для ${item.source.label || item.source.ref}`}
                  onChange={(e) => { if (e.target.value !== UNCHOSEN) setMappings((old) => ({ ...old, [item.source.ref]: e.target.value })); }}>
                  <option value={UNCHOSEN} disabled>Выберите подключение или ожидание…</option>
                  <option value="">Оставить в ожидании подключения</option>
                  {choices.map((s) => <option key={s.id} value={s.id}>{titleFor(s)}</option>)}
                  {Object.hasOwn(mappings, item.source.ref) && mappings[item.source.ref] && !targetIDs.has(mappings[item.source.ref]) &&
                    <option value={mappings[item.source.ref]} disabled>Выбранное подключение больше недоступно</option>}
                </Select>
              </div>;
            })}
          </div>
          {unresolved > 0 && <p className="text-xs text-warn">Осталось выбрать {unresolved} сопоставлений. Совпадение имени или локального ID само по себе не выбирает VPN.</p>}
          {(plan.warnings || []).map((warning, i) => <p key={i} className="text-xs text-warn">{warning}</p>)}
          <p className="text-xs text-muted">Ожидающие правила остаются в списке и не перенаправляются через другое подключение. Файл не переносит приватные VPN-ключи и пароли; подключения выбираются из уже настроенных на этом роутере.</p>
        </>}
      </div>
    </Modal>
  );
}
