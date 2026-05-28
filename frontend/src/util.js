// Human-readable bytes (RU units), throughput KB, grouped numbers.
export const human = (b) => {
  b = Number(b) || 0;
  const u = ["Б", "КБ", "МБ", "ГБ", "ТБ"];
  let i = 0;
  while (b >= 1024 && i < u.length - 1) { b /= 1024; i++; }
  return (i === 0 ? b : b.toFixed(b < 10 ? 1 : 0)) + " " + u[i];
};
export const kb = (bps) => (Number(bps) / 1024).toFixed(0);
export const fmtNum = (n) => (Number(n) || 0).toLocaleString("ru-RU");

// hostOf strips the port from an "ip:port" / "[ipv6]:port" destination.
export const hostOf = (hp) => {
  if (!hp) return "";
  if (hp.startsWith("[")) { const i = hp.indexOf("]"); return i > 0 ? hp.slice(1, i) : hp; }
  const i = hp.lastIndexOf(":");
  return i > 0 ? hp.slice(0, i) : hp;
};

// Verdict labels shared by baseline (auto run) and BlockCheck.
export const VERDICT = {
  ok: ["доступен", "ok"], cap16k: ["обрыв 16КБ", "bad"], reset: ["RST", "bad"],
  timeout: ["таймаут", "bad"], refused: ["отказ", "warn"], dns: ["DNS", "warn"], error: ["ошибка", "bad"],
};

// connFailing mirrors the Go Conn.Failing(): no reply, or TCP stuck in SYN_SENT.
export const connFailing = (c) => c.unreplied || (c.proto === "tcp" && c.state === "SYN_SENT");
