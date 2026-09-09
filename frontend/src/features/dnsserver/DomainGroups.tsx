import { Button } from "@/components/ui/Button";
import { Card } from "@/components/ui/Card";
import { Field, Textarea } from "@/components/ui/form";
import { Switch } from "@/components/ui/Switch";
import { UpstreamPool } from "./UpstreamPool";
import { newRuleGroup, type RuleGroupForm } from "./ruleGroups";

const domainCount = (domains: string) => new Set(domains.split(/[\s,;]+/).map((domain) => domain.trim().toLowerCase().replace(/\.$/, "")).filter(Boolean)).size;

export function DomainGroups({ value, onChange, disabled }: {
  value: RuleGroupForm[];
  onChange: (groups: RuleGroupForm[]) => void;
  disabled: boolean;
}) {
  const change = (index: number, patch: Partial<RuleGroupForm>) => onChange(value.map((group, i) => i === index ? { ...group, ...patch } : group));
  const totalDomains = value.reduce((total, group) => total + domainCount(group.domains), 0);

  return <Card title="Специальные DoH и домены" sub={`Групп: ${value.length} · Доменов: ${totalDomains}`} head={<Button mini disabled={disabled} onClick={() => onChange([...value, newRuleGroup()])}>Добавить группу</Button>}>
    <p className="mb-3 text-xs text-muted">Сначала выберите DoH или пул серверов, затем добавьте один домен или целый список. Все домены группы используют только этот пул; пул по умолчанию к нему не добавляется.</p>
    <div className="space-y-4">
      {value.length === 0 && <p className="py-3 text-xs text-muted">Специальных групп нет. Все запросы используют пул DoH по умолчанию.</p>}
      {value.map((group, index) => <div key={group.id} className="rounded-lg border border-line p-3 sm:p-4">
        <div className="mb-3 flex flex-wrap items-center gap-3">
          <h3 className="mr-auto text-sm font-semibold">Группа {index + 1}</h3>
          <Switch checked={group.enabled} disabled={disabled} onChange={(enabled) => change(index, { enabled })} label={`Группа ${index + 1} включена`} />
          <Button mini variant="danger" disabled={disabled} onClick={() => onChange(value.filter((_, i) => i !== index))} aria-label={`Удалить группу ${index + 1}`}>Удалить группу</Button>
        </div>
        <p className="mb-2 text-xs font-semibold text-ink-soft">DoH для группы</p>
        <UpstreamPool value={group.pool} onChange={(pool) => change(index, { pool })} />
        <Field label="Домены" hint={`в группе: ${domainCount(group.domains)}`} className="mt-4">
          <Textarea value={group.domains} disabled={disabled} rows={5} placeholder={"claude.com\ngrok.com\nclaude.ai"} onChange={(event) => change(index, { domains: event.target.value })} autoCapitalize="none" spellCheck={false} />
        </Field>
        <p className="mt-2 text-xs text-muted">По одному домену на строку или через запятую, без https:// и пути.</p>
        <div className="mt-3"><Switch checked={group.include_subdomains} disabled={disabled} onChange={(include_subdomains) => change(index, { include_subdomains })} label="Включая поддомены для всей группы" /></div>
        {!group.enabled && <p className="mt-2 text-xs text-muted">Группа выключена. Её домены используют другие подходящие группы или пул по умолчанию.</p>}
      </div>)}
    </div>
    {value.length > 0 && <p className="mt-3 text-xs text-muted">Если подходят несколько групп, применяется наиболее конкретный домен. Например, api.example.com имеет приоритет над example.com.</p>}
  </Card>;
}
