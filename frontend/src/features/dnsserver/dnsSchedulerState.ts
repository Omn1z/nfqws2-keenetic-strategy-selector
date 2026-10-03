import type { DnsServerSchedulerSnapshot } from "@/types/api";

export function dnsSchedulerState(snapshot: DnsServerSchedulerSnapshot): { active: boolean; message: string } {
  if (snapshot.reason === "shadow") return { active: false, message: "Домен относится к Shadow DNS: запросы идут напрямую к DNS провайдера. Пул DoH и его планировщик для этого домена не используются; кэш и фильтрация остаются включены согласно настройкам." };
  if (snapshot.enabled === false || snapshot.reason === "disabled") return { active: false, message: "Планировщик выключен. DNS работает в порядке настройки пула, без обучения и фоновых замеров. Кэш и fast-dns работают независимо." };
  if (snapshot.reason === "single_candidate") return { active: false, message: "В этом пуле доступно одно сочетание DoH и маршрута. Ранжирование и фоновые замеры автоматически пропущены." };
  if (snapshot.reason === "no_candidates") return { active: false, message: "В этом пуле нет доступных включённых сочетаний DoH и маршрута. Фоновые замеры не выполняются." };
  return { active: snapshot.effective !== false, message: snapshot.effective === false ? "Фоновые замеры этого пула приостановлены." : "" };
}
