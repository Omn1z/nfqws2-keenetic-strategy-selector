import { api } from "@/lib/api";
import { toast } from "@/components/ui/Toast";

/** Apply a strategy to the live nfqws2 config (with a backup), optionally
 *  restarting the service. Guarded by explicit confirmations since it affects
 *  the whole network. */
export async function applyStrategyToConfig(args: string): Promise<void> {
  if (!confirm(`Применить стратегию в основной конфиг nfqws2?\n\n${args}`)) return;
  const restart = confirm("Перезапустить сервис nfqws2 сейчас? (затронет всю сеть)\n\nOK — перезапустить, Отмена — только записать конфиг.");
  try {
    await api("POST", "/api/apply", { args, restart });
    toast(restart ? "Применено и перезапущено" : "Записано в конфиг", "ok");
  } catch (e) {
    toast((e as Error).message, "err");
  }
}
