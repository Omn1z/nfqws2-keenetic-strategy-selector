// TypeScript mirrors of the Go JSON API (field names match the `json:"..."` tags).

export type RunStatus = "running" | "done" | "cancelled" | "error";
export type Verdict = "ok" | "timeout" | "reset" | "refused" | "cap16k" | "dns" | "error";
export type DnsType = "doh" | "dot";

export interface AuthStatus {
  enabled: boolean;
  authed: boolean;
  version: string;
}

export interface Config {
  version: string;
  repo: string;
  wan_ifaces: string[];
  main_queue: number;
  [k: string]: unknown;
}

export interface Strategy {
  id: string;
  name: string;
  l7: string;
  args: string;
  source: string;
}

export interface SavedStrategy {
  strategy_id: string;
  name: string;
  args: string;
  dns?: string;
  dns_id?: string;
  avg_ttfb_ms: number;
  avg_speed_bps: number;
  coefficient: number;
  found_at: number;
  run_id: string;
}

export interface List {
  id: string;
  name: string;
  domains: string[];
  ips: string[];
  base_strategy_ids?: string[];
  successful_strategies?: SavedStrategy[];
  test_url?: string;
  created_at: number;
  updated_at: number;
}

export interface TargetCheck {
  host: string;
  blocked: boolean;
  verdict: Verdict;
  code: number;
  size: number;
  ttfb_ms: number;
  speed_bps: number;
  err?: string;
}

export interface StrategyResult {
  strategy_id: string;
  name: string;
  args: string;
  l7: string;
  dns?: string;
  dns_id?: string;
  targets_total: number;
  targets_ok: number;
  avg_ttfb_ms: number;
  avg_speed_bps: number;
  coefficient: number;
  success: boolean;
  error?: string;
}

export interface Run {
  id: string;
  list_id: string;
  list_name: string;
  threads: number;
  auto: boolean;
  status: RunStatus;
  error?: string;
  total: number;
  done: number;
  started_at: number;
  finished_at?: number;
  targets: string[];
  baseline?: TargetCheck[];
  results: StrategyResult[];
}

export interface BlockCheck {
  id: string;
  list_id: string;
  list_name: string;
  threads: number;
  status: RunStatus;
  error?: string;
  total: number;
  done: number;
  targets: TargetCheck[];
}

export interface RunRequest {
  list_id?: string;
  targets?: string[];
  strategy_ids: string[];
  blobs: string[];
  dns: string[];
  auto: boolean;
  threads: number;
}

export interface DnsServer {
  id: string;
  name: string;
  type: DnsType;
  addr: string;
}

export interface QueueStat {
  queue: number;
  portid: number;
  queued: number;
  copy_mode: number;
  copy_range: number;
  queue_drop: number;
  user_drop: number;
  id_seq: number;
}

export interface IfaceBytes {
  iface: string;
  rx_bytes: number;
  tx_bytes: number;
  rx_packets: number;
  tx_packets: number;
}

export interface Conn {
  l3: string;
  proto: string;
  state: string;
  ttl: number;
  src: string;
  dst: string;
  sport: number;
  dport: number;
  packets: number;
  bytes: number;
  reply_bytes: number;
  assured: boolean;
  unreplied: boolean;
  fastnat: boolean;
  mac: string;
  zone: string;
}

export interface Device {
  ip: string;
  mac: string;
  iface: string;
  total: number;
  established: number;
  failing: number;
  working: string[];
  failing_dsts: string[];
}

export interface TgwsSnapshot {
  connections: { total: number; active: number; ws: number; tcp_fallback: number; cfproxy: number; bad: number; masked: number };
  traffic: { bytes_up: number; bytes_down: number; human_up: string; human_down: string };
  ws: { errors: number; pool_hits: number; pool_misses: number };
  started_at: number;
}

export interface TgwsConfig {
  enabled: boolean;
  port: number;
  secret: string;
  dc_redirects: Record<string, string>;
  buffer_size: number;
  pool_size: number;
  proxy_protocol: boolean;
  cfproxy: boolean;
  cfproxy_user_domain: string;
  cfproxy_worker_domain: string;
  fake_tls_domain: string;
  link_host: string;
}

export interface TgwsStatus {
  running: boolean;
  config: TgwsConfig;
  stats: TgwsSnapshot;
  link: string;
}

export interface Dashboard {
  tgws: TgwsStatus;
  conntrack: { count: number; max: number };
  conns: { total: number; failing: number; by_proto: Record<string, number> };
  queues: QueueStat[];
  main_queue: number;
  wan: IfaceBytes[];
}

export interface ConnectionsView {
  items: Conn[];
  count: number;
}

export interface DeviceActivityView {
  devices: Device[];
}

export interface GeoCategory {
  name: string;
  count: number;
}

export interface GeoFile {
  name: string;
  kind: string;
  categories: GeoCategory[];
}

export interface Blobs {
  system: string[];
  custom: string[];
}

/** {list_id} for a saved list, or {targets} for an ad-hoc/geo set. */
export type TargetSource = { list_id: string } | { targets: string[] };

export interface LogEntry {
  t: number; // unix millis
  module: string;
  level: string; // info | warn | error
  msg: string;
}

export interface TraceEvent {
  at_ms: number;
  kind: string; // new | unreplied | replied | gone
  proto: string;
  dst: string;
  note?: string;
}

export interface TraceConn {
  proto: string;
  dst: string;
  state: string;
  first_ms: number;
  last_ms: number;
  samples: number;
  max_packets: number;
  max_bytes: number;
  unreplied: boolean;
  gone: boolean;
}

export interface Trace {
  id: string;
  ip: string;
  seconds: number;
  status: string; // running | done | error
  error?: string;
  started_at: number;
  elapsed_ms: number;
  events: TraceEvent[];
  conns: TraceConn[];
}
