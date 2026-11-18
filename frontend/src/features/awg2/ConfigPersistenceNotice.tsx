export default function ConfigPersistenceNotice({ error, recovered }: { error?: string; recovered?: boolean }) {
  if (error) return <div role="alert" className="mt-3 rounded-lg border border-warn/30 bg-warn-bg p-3 text-xs text-warn [overflow-wrap:anywhere]">
    <p>Сохранённые настройки Amnezia не загружены. Запись остановлена для защиты данных; восстановите настройки из резервной копии.</p>
    <p className="mt-1">{error}</p>
  </div>;
  if (recovered) return <p role="status" className="mt-3 rounded-lg bg-warn-bg p-3 text-xs text-warn">Настройки Amnezia восстановлены из проверенной резервной копии.</p>;
  return null;
}
