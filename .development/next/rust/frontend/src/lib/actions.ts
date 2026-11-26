import { api } from "@/lib/api";
import { toast } from "@/components/ui/Toast";
import { confirmDialog } from "@/components/ui/Confirm";

/** Apply a strategy to the live nfqws2 config (with a backup), optionally
 *  restarting the service. Guarded by explicit confirmations since it affects
 *  the whole network. */
export async function applyStrategyToConfig(args: string): Promise<void> {
  if (!(await confirmDialog({ title: "Применить стратегию в основной конфиг nfqws2?", body: args, confirmLabel: "Применить" }))) return;
  const restart = await confirmDialog({
    title: "Перезапустить сервис nfqws2 сейчас?",
    body: "Затронет всю сеть. «Перезапустить» — применить немедленно; «Только записать» — лишь обновить конфиг.",
    confirmLabel: "Перезапустить",
    cancelLabel: "Только записать",
  });
  try {
    await api("POST", "/api/apply", { args, restart });
    toast(restart ? "Применено и перезапущено" : "Записано в конфиг", "ok");
  } catch (e) {
    toast((e as Error).message, "err");
  }
}
