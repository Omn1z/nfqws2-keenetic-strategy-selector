import { Button } from "@/components/ui/Button";
import { DnsBadge } from "@/components/ui/Badge";
import { StatsStrip } from "@/components/ui/FeaturePage";
import { EmptyRow, TableWrap, tableCls, tdCls, thBase } from "@/components/ui/Table";
import { cn } from "@/lib/cn";
import type { DnsServer, DnsType } from "@/types/api";

export function visibleDnsServers(servers: DnsServer[], query: string, type: "" | DnsType): DnsServer[] {
  const text = query.trim().toLowerCase();
  return servers.filter(server => (!type || server.type === type) && (!text || [server.id, server.name, server.addr, server.type].some(value => (value || "").toLowerCase().includes(text))));
}

export function DnsSummary({ servers }: { servers: DnsServer[] }) {
  return <StatsStrip label="Состав каталога DNS" items={[
    { label: "DNS-серверов", value: servers.length, hint: "настроено для прогонов" },
    { label: "DNS over HTTPS", value: servers.filter(server => server.type === "doh").length, hint: "DoH" },
    { label: "DNS over TLS", value: servers.filter(server => server.type === "dot").length, hint: "DoT" },
  ]} />;
}

export function DnsCatalog({ servers, busy, filtered, onDelete }: {
  servers: DnsServer[]; busy: string | null; filtered: boolean;
  onDelete: (id: string, name: string) => void;
}) {
  return <TableWrap>
    <table className={cn(tableCls, "min-w-[580px]")}>
      <thead><tr>{["Название / ID", "Протокол", "Адрес / URL", "Действия"].map(label => <th key={label} scope="col" className={thBase}>{label}</th>)}</tr></thead>
      <tbody>
        {!servers.length && <EmptyRow colSpan={4}>{filtered ? "DNS-серверы под выбранный фильтр не найдены." : "Список пуст — добавьте DNS выше или сбросьте к стандартным."}</EmptyRow>}
        {servers.map(server => <tr key={server.id} className="hover:bg-line-soft">
          <th scope="row" className={cn(tdCls, "min-w-[150px] max-w-[260px] text-left font-normal [overflow-wrap:anywhere]")}><span className="font-medium">{server.name || server.id}</span><span className="mt-1 block font-mono text-[11px] text-muted">{server.id}</span></th>
          <td className={tdCls}><DnsBadge name={server.type.toUpperCase()} id={server.id} /></td>
          <td className={cn(tdCls, "min-w-[220px] max-w-[560px]")}><code className="whitespace-pre-wrap font-mono text-xs [overflow-wrap:anywhere]">{server.addr}</code></td>
          <td className={tdCls}><Button mini variant="danger" aria-label={`Удалить DNS ${server.name || server.id}`} disabled={busy !== null} onClick={() => onDelete(server.id, server.name)}>{busy === `delete:${server.id}` ? "Удаление…" : "Удалить"}</Button></td>
        </tr>)}
      </tbody>
    </table>
  </TableWrap>;
}
