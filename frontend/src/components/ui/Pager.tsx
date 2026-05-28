export function pageSlice<T>(arr: T[], page: number, pageSize: string): T[] {
  const total = arr.length;
  const size = pageSize === "all" ? Math.max(total, 1) : parseInt(pageSize, 10);
  const pages = Math.max(1, Math.ceil(total / size));
  const p = Math.min(Math.max(page, 1), pages);
  return arr.slice((p - 1) * size, (p - 1) * size + size);
}

interface PagerProps {
  total: number;
  page: number;
  setPage: (p: number) => void;
  pageSize: string;
  setPageSize: (s: string) => void;
}

const btn = "rounded-md border border-line bg-panel px-2.5 py-1 text-xs font-semibold text-ink transition hover:border-track disabled:pointer-events-none disabled:opacity-40";

/** Page-size select + prev/next, rendered BELOW the table. */
export function Pager({ total, page, setPage, pageSize, setPageSize }: PagerProps) {
  if (total === 0) return null;
  const size = pageSize === "all" ? Math.max(total, 1) : parseInt(pageSize, 10);
  const pages = Math.max(1, Math.ceil(total / size));
  const p = Math.min(Math.max(page, 1), pages);
  return (
    <div className="mt-3.5 flex flex-wrap items-center justify-center gap-3">
      <label className="flex items-center gap-1.5 text-xs text-ink-soft">
        Показывать
        <select
          value={pageSize}
          onChange={(e) => { setPageSize(e.target.value); setPage(1); }}
          className="rounded-md border border-line bg-input px-2 py-1 text-xs text-ink"
        >
          <option value="20">20</option>
          <option value="50">50</option>
          <option value="100">100</option>
          <option value="all">Все</option>
        </select>
      </label>
      <button className={btn} disabled={p <= 1} onClick={() => setPage(p - 1)}>‹ Назад</button>
      <span className="min-w-[170px] text-center text-xs text-muted">стр. {p} из {pages} · {total} записей</span>
      <button className={btn} disabled={p >= pages} onClick={() => setPage(p + 1)}>Вперёд ›</button>
    </div>
  );
}
