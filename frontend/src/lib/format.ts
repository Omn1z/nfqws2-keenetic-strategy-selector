import type { Conn } from "@/types/api";

/** Human-readable bytes in RU units. */
export const human = (b?: number): string => {
  let n = Number(b) || 0;
  const u = ["Б", "КБ", "МБ", "ГБ", "ТБ"];
  let i = 0;
  while (n >= 1024 && i < u.length - 1) {
    n /= 1024;
    i++;
  }
  return `${i === 0 ? n : n.toFixed(n < 10 ? 1 : 0)} ${u[i]}`;
};

export const kb = (bps?: number): string => (Number(bps) / 1024).toFixed(0);
export const fmtNum = (n?: number): string => (Number(n) || 0).toLocaleString("ru-RU");

/** Strip the port from "ip:port" / "[ipv6]:port". */
export const hostOf = (hp: string): string => {
  if (!hp) return "";
  if (hp.startsWith("[")) {
    const i = hp.indexOf("]");
    return i > 0 ? hp.slice(1, i) : hp;
  }
  const i = hp.lastIndexOf(":");
  return i > 0 ? hp.slice(0, i) : hp;
};

/** Mirrors Go Conn.Failing(): no reply, or TCP stuck in SYN_SENT. */
export const connFailing = (c: Conn): boolean => c.unreplied || (c.proto === "tcp" && c.state === "SYN_SENT");
