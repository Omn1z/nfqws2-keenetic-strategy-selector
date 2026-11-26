export const DNS_FORWARDER_NOTE = "IP отправителя — адрес, видимый DNS-серверу. Если Keenetic пересылает запросы от своего имени, исходное устройство определить нельзя.";

export function dnsRequestSourceLabel(source?: string): string {
  const labels: Record<string, string> = {
    client: "Устройство", local: "Роутер / DNS-посредник", diagnostic: "Проверка в панели",
    internal: "Сервис", probe: "Фоновая проверка",
  };
  return source ? labels[source] || source : "";
}

export const dnsRequestTransportLabel = (transport?: string) => transport ? transport.toUpperCase() : "";
