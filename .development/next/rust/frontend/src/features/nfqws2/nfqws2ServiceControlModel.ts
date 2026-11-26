import { api } from "@/lib/api";
import type { Nfqws2ServiceStatus } from "@/types/api";

export type Nfqws2ServiceAction = "start" | "stop" | "restart";
export interface Nfqws2ServiceResult { name: string; ok: boolean; detail: string }

/** One service mutation at a time; a pre-mutation status read cannot undo it. */
export class Nfqws2ServiceController {
  status: Nfqws2ServiceStatus | null = null;
  error = "";
  pending: Nfqws2ServiceAction | null = null;
  private generation = 0;
  private reading: AbortController | null = null;
  private active = true;

  activate() { this.active = true; }
  dispose() { this.active = false; this.invalidateRead(); }

  private invalidateRead() {
    this.generation++;
    this.reading?.abort(); this.reading = null;
  }

  async refresh(signal?: AbortSignal, afterAction = false): Promise<Nfqws2ServiceStatus | null> {
    if (!this.active || signal?.aborted || (this.pending && !afterAction)) return null;
    this.invalidateRead();
    const generation = this.generation;
    const controller = new AbortController();
    this.reading = controller;
    const abort = () => controller.abort();
    signal?.addEventListener("abort", abort, { once: true });
    try {
      const status = await api<Nfqws2ServiceStatus>("GET", "/api/nfqws2/status", undefined, { signal: controller.signal });
      if (controller.signal.aborted || generation !== this.generation || !this.active) return null;
      if (typeof status?.running !== "boolean" || typeof status?.manual_off !== "boolean") throw new Error("Роутер вернул неизвестное состояние службы NFQWS2");
      this.status = status; this.error = "";
      return status;
    } catch (cause) {
      if (!controller.signal.aborted && generation === this.generation && this.active) this.error = (cause as Error).message;
      return null;
    } finally {
      signal?.removeEventListener("abort", abort);
      if (this.reading === controller) this.reading = null;
    }
  }

  async perform(action: Nfqws2ServiceAction): Promise<Nfqws2ServiceResult | null> {
    if (this.pending || !this.active) return null;
    if (!this.status || this.error) throw new Error("Дождитесь подтверждения состояния службы NFQWS2");
    if (action === "restart" && (!this.status.running || this.status.manual_off)) throw new Error("Служба NFQWS2 остановлена. Сначала включите её переключателем.");
    if ((action === "start" && this.status.running) || (action === "stop" && !this.status.running)) return null;
    this.pending = action;
    this.invalidateRead();
    try {
      const result = action === "restart"
        ? (await api<{ results: Nfqws2ServiceResult[] }>("POST", "/api/services/restart", { services: ["nfqws2"] }, { timeoutMs: 45000 })).results?.find(item => item.name === "nfqws2")
        : await api<Nfqws2ServiceResult>("POST", `/api/nfqws2/${action}`, {}, { timeoutMs: 45000 });
      if (!result || result.name !== "nfqws2" || typeof result.ok !== "boolean") throw new Error("Роутер не подтвердил результат управления NFQWS2");
      return result;
    } finally {
      // Commands can partly succeed even when their response is lost. Read the
      // actual process state before enabling the next switch/button action.
      await this.refresh(undefined, true);
      this.pending = null;
    }
  }
}
