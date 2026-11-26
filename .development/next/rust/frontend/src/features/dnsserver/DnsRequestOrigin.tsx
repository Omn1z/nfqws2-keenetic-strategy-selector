import { DNS_FORWARDER_NOTE, dnsRequestSourceLabel, dnsRequestTransportLabel } from "./dnsRequestSource";

type Origin = { source?: string; clientIP?: string; transport?: string };

export function DnsRequestOrigin({ source, clientIP, transport }: Origin) {
  const parts = [dnsRequestSourceLabel(source), clientIP ? `Отправитель: ${clientIP}` : "", dnsRequestTransportLabel(transport)].filter(Boolean);
  if (!parts.length) return null;
  return <span className="rounded bg-line-soft px-1.5 text-muted" title={source === "local" ? DNS_FORWARDER_NOTE : "Источник DNS-запроса и наблюдаемый IP отправителя"}>{parts.join(" · ")}</span>;
}

export function DnsRequestOriginDetails({ source, clientIP, transport }: Origin) {
  if (!source && !clientIP && !transport) return null;
  return <>
    {source && <span>Источник DNS-запроса: {dnsRequestSourceLabel(source)}</span>}
    {clientIP && <span>Наблюдаемый IP отправителя: {clientIP}</span>}
    {transport && <span>Входящий транспорт: {dnsRequestTransportLabel(transport)}</span>}
    {source === "local" && <span>{DNS_FORWARDER_NOTE}</span>}
  </>;
}
