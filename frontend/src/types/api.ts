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

export interface Socks5Config {
  enabled: boolean;
  port: number;
  user: string;
  pass: string;
  buffer_size: number;
  dc_redirects: Record<string, string>;
  link_host: string;
}

export interface Socks5Snapshot {
  connections: { total: number; active: number; telegram: number; direct: number; bad: number };
  traffic: { bytes_up: number; bytes_down: number; human_up: string; human_down: string };
  last_dc: number;
  started_at: number;
}

export interface Socks5Status {
  running: boolean;
  config: Socks5Config;
  stats: Socks5Snapshot;
  link: string;
}

// Shared "route the ISP-blocked Telegram DCs (1/3/5) via AWG2" selection for both
// proxies. value: "off" | "auto" | "<server-id>".
export interface AwgFallbackServer { id: string; label: string; connected: boolean }
export interface AwgFallbackView { value: string; servers: AwgFallbackServer[] }

// ---- AWG2 (AmneziaWG 2.0). Secret fields (password/key_pem/key_pass/private_key/psk)
// are write-only: sent on save, never returned by the API. ----
export interface AwgObfuscation {
  jc: number; jmin: number; jmax: number;
  s1: number; s2: number; s3: number; s4: number;
  h1: string; h2: string; h3: string; h4: string;
  i1: string; i2: string; i3: string; i4: string; i5: string;
}
export interface AwgCredentials {
  host: string; port: number; user: string; auth_kind: string;
  password?: string; key_pem?: string; key_pass?: string; known_key: string;
}
export interface AwgPeer {
  id: string; name: string; public_key: string;
  private_key?: string; psk?: string;
  address: string; allowed_ips: string; keepalive: number;
  is_router: boolean; has_private: boolean; created_at: number;
}
export interface AwgZone { name: string; mode: string; domains: string[]; ips: string[]; enabled: boolean }
export interface AwgRoutingConfig {
  mode: string; zones: AwgZone[]; mtu: number; killswitch: boolean; domain_source: string;
  active?: boolean;
}
export interface AwgClientConfig { enabled: boolean; peer_id: string }
export interface AwgServerConfig {
  enabled: boolean;
  conn: AwgCredentials;
  install: string;
  private_key?: string;
  public_key: string;
  listen_port: number;
  address: string;
  subnet: string;
  mtu: number;
  dns: string;
  wan_iface: string;
  endpoint: string;
  obf: AwgObfuscation;
  peers: AwgPeer[];
  client: AwgClientConfig;
  routing: AwgRoutingConfig;
  interface: string;
  deployed_at: number;
}
export interface AwgStep { name: string; ok: boolean; detail: string }
export interface AwgDeployResult {
  ok: boolean; method: string; wan_iface: string; listening: boolean; handshake: boolean;
  steps: AwgStep[]; error?: string;
}
export interface AwgPeerStatus {
  id: string; name: string; public_key: string; endpoint: string;
  latest_handshake: number; rx_bytes: number; tx_bytes: number; online: boolean;
}
export interface AwgStatus {
  reachable: boolean; up: boolean; listen_port: number; peers: AwgPeerStatus[]; error?: string;
}
export interface AwgEngineInfo {
  installed: boolean; awg_version: string; arch: string; supported: boolean; tun_ok: boolean; error?: string;
}
export interface AwgClientStatus {
  running: boolean; iface_present: boolean; last_handshake: number; rx_bytes: number; tx_bytes: number;
  endpoint: string; address: string; mtu: number; connected: boolean; error?: string;
}
export interface Awg2Status {
  config: AwgServerConfig; // redacted (no secrets)
  has_password: boolean;
  has_key: boolean;
  has_server_key: boolean;
  deployed: boolean;
  last_deploy: AwgDeployResult | null;
  status: AwgStatus | null;
  endpoint: string;
  engine: AwgEngineInfo;
  client: AwgClientStatus | null;
}

export interface Dashboard {
  tgws: TgwsStatus;
  socks5: Socks5Status;
  nfqws2_running: boolean;
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
  trash: string[];
}

export interface ClientHelloCandidate {
  src_ip: string;
  dst_ip: string;
  dst_port: number;
  sni: string;
  size: number;
  valid: boolean;
  detail: string;
}

export interface SystemSettings {
  auth_enabled: boolean;
  auth_forced_off: boolean;
  logging_enabled: boolean;
  http_logs_enabled: boolean;
}

export interface BlobCapture {
  id: string;
  ip: string;
  iface: string;
  seconds: number;
  status: string; // running | done | error
  error?: string;
  started_at: number;
  elapsed_ms: number;
  candidates: ClientHelloCandidate[];
}

/** POST /api/devices/{ip}/blobcap → a started capture, or a prompt to install tcpdump. */
export type BlobCaptureStart = BlobCapture | { need_install: true; package: string };

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

export interface Pcap {
  id: string;
  ip: string;
  iface: string;
  seconds: number;
  status: string; // running | done | error
  error?: string;
  started_at: number;
  elapsed_ms: number;
  packets: number;
  dropped: number;
  size_bytes: number;
}

/** POST /api/devices/{ip}/pcap → a started capture, or a prompt to install tcpdump first. */
export type PcapStart = Pcap | { need_install: true; package: string };

/** POST /api/system/install → opkg result. */
export interface InstallResult {
  ok: boolean;
  output: string;
  error?: string;
}

// NFQWS2 engine file management + version.
export type Nfqws2Kind = "conf" | "list" | "lua";

export interface Nfqws2File {
  name: string;
  kind: Nfqws2Kind;
  size: number;
  gz: boolean;
  protected: boolean;
}

export interface Nfqws2Version {
  package: string;
  engine: string;
  latest: string;
  available: boolean;
  url: string;
  error?: string;
}
