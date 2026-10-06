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
  engine_log?: string;
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
  ipv6?: string[]; // every v6 address (global + link-local) the same MAC was seen using
  mac: string;
  hostname?: string;
  iface: string;
  total: number;
  established: number;
  failing: number;
  bytes_up: number;
  bytes_down: number;
  working: string[];
  failing_dsts: string[];
}

export interface PortForwardRange {
  start: number;
  end: number;
}

export interface PortForwardProfile {
  id: string;
  name: string;
  tcp: PortForwardRange[];
  udp: PortForwardRange[];
}

export interface PortForwardPreset {
  id: string;
  name: string;
  source: string;
  profiles: PortForwardProfile[];
}

export interface PortForwardRule {
  id: string;
  name: string;
  preset_id: string;
  profile_id: string;
  device_ip: string;
  device_name: string;
  device_mac: string;
  device_iface: string;
  enabled: boolean;
  tcp: PortForwardRange[];
  udp: PortForwardRange[];
  created_at: number;
  updated_at: number;
}

export interface PortForwardView {
  presets: PortForwardPreset[];
  rules: PortForwardRule[];
  wan_ifaces: string[];
  hook_path: string;
}

export interface ARPSpoofVendor {
  id: string;
  name: string;
  prefixes: string[];
}

export interface ARPSpoofConfig {
  enabled: boolean;
  mac: string;
  vendor_id: string;
  prefix: string;
  ifaces: string[];
  updated_at: number;
}

export interface ARPSpoofInterface {
  name: string;
  mac: string;
  up: boolean;
  suggested: boolean;
}

export interface ARPSpoofTools {
  ip: boolean;
  arptables: boolean;
  ebtables: boolean;
}

export interface ARPSpoofView {
  config: ARPSpoofConfig;
  vendors: ARPSpoofVendor[];
  ifaces: ARPSpoofInterface[];
  suggested_ifaces: string[];
  hook_path: string;
  tools: ARPSpoofTools;
  active: boolean;
  last_error: string;
  applied_at: number;
}

export interface TgwsSnapshot {
  connections: { total: number; active: number; ws: number; h2?: number; tcp_fallback: number; cfproxy: number; fronting: number; bad: number; masked: number };
  traffic: { bytes_up: number; bytes_down: number; human_up: string; human_down: string };
  ws: { errors: number; pool_hits: number; pool_misses: number; cf_pool_hits: number; cf_pool_misses: number };
  h2?: { tcp_connections: number; requests: number; errors: number; replays: number };
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
  force_test_dc: boolean;
  sni_fronting: boolean;
  disable_secure: boolean;
  cfproxy: boolean;
  cfproxy_h2_media?: boolean;
  cfproxy_user_domain: string;
  cfproxy_worker_domain: string;
  cfproxy_user_domains: string[];
  cfproxy_worker_domains: string[];
  fake_tls_domain: string;
  link_host: string;
}

export interface TgwsStatus {
  upstream_version: string;
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

// Shared "route the ISP-blocked Telegram DCs (1/3/5) via a tunnel backend" selection
// for both proxies. value: "off" | "auto" | "<awg-server-id>" | "awg:<id>".
export interface AwgFallbackServer { id: string; label: string; client_iface?: string; connected: boolean }
export interface AwgFallbackView { value: string; servers: AwgFallbackServer[] }

// ---- Local DNS service. Upstreams are DoH; listeners accept UDP/TCP DNS. ----
export interface DnsServerUpstream { address: string; bootstrap_ips: string[] }
export interface DnsServerDisabledMethod { upstream: string; route: string }
export type DnsBlockCategory = "ads" | "trackers" | "mixed";
export interface DnsCustomBlockRule { domain: string; category: DnsBlockCategory }
export interface DnsFilteringConfig {
  enabled: boolean;
  lists: string[];
  custom_rules: DnsCustomBlockRule[];
  allowlist: string[];
}
export interface DnsFilteringListStatus {
  id: string;
  name: string;
  category: DnsBlockCategory;
  url: string;
  homepage: string;
  description: string;
  selected: boolean;
  rules: number;
  last_updated: string;
  last_error: string;
}
export interface DnsFilteringStatus {
  enabled: boolean;
  ready: boolean;
  rules: number;
  ignored_rules?: number;
  approximate?: boolean;
  updating: boolean;
  last_updated: string;
  last_error: string;
  lists: DnsFilteringListStatus[];
}
export interface DnsServerRule {
  id: string;
  enabled: boolean;
  domain: string;
  include_subdomains: boolean;
  upstream: DnsServerUpstream;
  pool?: DnsServerUpstream[];
}
export interface DnsShadowDomain { domain: string; include_subdomains: boolean }
export interface DnsShadowConfig { enabled: boolean; servers: string[]; domains: DnsShadowDomain[] }
export interface DnsShadowDiagnosticEvent { at: string; stage: string; message: string; duration_ms?: number }
export interface DnsShadowDiagnosticAttempt {
  id: number;
  started_at: string;
  finished_at?: string;
  duration_ms: number;
  error?: string;
  servers: string[];
  next_retry_at?: string;
  events: DnsShadowDiagnosticEvent[];
}
export interface DnsShadowDiagnostics {
  version: 1;
  enabled?: boolean;
  app_version?: string;
  platform?: string;
  captured_at: string;
  in_progress: boolean;
  attempts: DnsShadowDiagnosticAttempt[];
}
export interface DnsShadowStatus { enabled: boolean; automatic: boolean; servers: string[]; error?: string; diagnostics?: DnsShadowDiagnostics; renewal_available?: boolean; fallback_active?: boolean; next_probe_at?: string }
export interface DnsShadowRenewResult {
  status: "resolved" | "waiting" | "no_dns" | "nak";
  interface: string;
  device: string;
  servers?: string[];
  message: string;
}
export interface DnsShadowRenewResponse { ok: true; result: DnsShadowRenewResult }
export interface DnsServerConfig {
  enabled: boolean;
  listen_host: string;
  dns_port: number;
  default_upstream: DnsServerUpstream;
  default_pool?: DnsServerUpstream[];
  logging_enabled: boolean;
  fast_dns: boolean;
  scheduler_enabled?: boolean;
  disabled_methods?: DnsServerDisabledMethod[];
  awg_fallback: string;
  route_mode?: "auto" | "vpn_only" | "";
  timeout_seconds: number;
  cache_size: number;
  cache_ttl_seconds: number;
  rules: DnsServerRule[];
  filtering?: DnsFilteringConfig;
  shadow_dns?: DnsShadowConfig;
}
export interface DnsServerSettingsDocument {
  format: "nfqws2-strategy-dnsserver";
  version: 1;
  exported_at: string;
  config: DnsServerConfig;
  connections?: DnsSettingsConnection[];
}
export interface DnsSettingsConnection {
  ref: string;
  label: string;
  endpoint: string;
  client_iface: string;
  protocol: string;
  server_public_key?: string;
  fingerprint: string;
}
export interface DnsSettingsImportPlan {
  config: DnsServerConfig;
  base_hash: string;
  listener: { host: string; port: number; address: string; enabled: boolean };
  vpn: {
    source_id: string;
    state: "auto" | "off" | "matched" | "selection_required" | "missing" | "ambiguous";
    resolution?: "selection_required" | "missing" | "ambiguous";
    matched_id?: string;
    candidates: DnsSettingsConnection[];
  };
  warnings: string[];
}
export interface DnsSettingsImportRequest {
  document: string;
  base_hash: string;
  mapping?: string;
  mapping_fingerprint?: string;
}
export type DnsRequestSource = "client" | "local" | "diagnostic" | "internal" | "probe" | "";
export type DnsRequestTransport = "udp" | "tcp" | "api" | "";
export interface DnsServerStats {
  queries: number;
  cache_hits: number;
  shared_responses?: number;
  nfqws_success: number;
  awg_success: number;
  shadow_success?: number;
  failures: number;
  blocked_total?: number;
  blocked_ads?: number;
  blocked_trackers?: number;
  blocked_mixed?: number;
  last_domain?: string;
  last_route?: string;
  last_upstream?: string;
  last_cached?: boolean;
  last_shared?: boolean;
  last_client_ip?: string;
  last_source?: DnsRequestSource;
  last_transport?: DnsRequestTransport;
  last_error?: string;
}
export interface DnsServerCache {
  entries: number;
  capacity: number;
  ttl_seconds: number;
}
export interface DnsServerFastDNSStatus {
  enabled: boolean;
  entries: number;
  ready: number;
  refreshing: number;
  last_refresh_at?: string;
  next_refresh_at?: string;
  last_error?: string;
}
export interface DnsServerStatus {
  config: DnsServerConfig;
  running: boolean;
  listen_host: string;
  endpoints: { dns: string };
  last_error?: string;
  stats: DnsServerStats;
  cache: DnsServerCache;
  fast_dns?: DnsServerFastDNSStatus;
  filtering?: DnsFilteringStatus;
  shadow_dns?: DnsShadowStatus;
  routes: { id: string; name: string; interface: string; available: boolean; error?: string }[];
}
export interface DnsServerTestResult {
  ok: boolean;
  domain: string;
  type: "A" | "AAAA" | "CNAME" | "HTTPS" | "SVCB";
  route: string;
  upstream: string;
  answers: string[];
  duration_ms: number;
  cached?: boolean;
  shared?: boolean;
  client_ip?: string;
  source?: DnsRequestSource;
  transport?: DnsRequestTransport;
  error?: string;
  blocked?: boolean;
  block_category?: DnsBlockCategory;
  block_rule?: string;
  block_source?: string;
  block_domain?: string;
}
export interface DnsServerLogEntry {
  id: number;
  time: string;
  level: string;
  event: string;
  domain?: string;
  qtype?: string;
  client_ip?: string;
  source?: DnsRequestSource;
  transport?: DnsRequestTransport;
  upstream?: string;
  route?: string;
  duration_ms?: number;
  message?: string;
  count?: number;
  block_category?: DnsBlockCategory;
  block_rule?: string;
  block_source?: string;
  block_domain?: string;
}
export interface DnsServerLogSnapshot {
  /** Omitted by older panels; changes only when their in-memory ring is replaced. */
  instance_id?: string;
  enabled: boolean;
  bytes: number;
  max_bytes: number;
  oldest_id: number;
  last_id: number;
  dropped: number;
  entries: DnsServerLogEntry[];
}
export interface DnsServerSchedulerCandidate {
  position: number;
  route: string;
  route_name: string;
  upstream: string;
  available: boolean;
  disabled?: boolean;
  score: number;
  reliability: number;
  latency_ms: number;
  latency_penalty: number;
  failure_penalty: number;
  attempts: number;
  successes: number;
  failures: number;
  consecutive_failures: number;
  last_error: string;
  last_attempt_at: string;
  last_result_at?: string;
  last_probe_at?: string;
  probing?: boolean;
  probe_attempts?: number;
  probe_successes?: number;
  probe_failures?: number;
  exploration: boolean;
}
export interface DnsServerSchedulerSnapshot {
  enabled?: boolean;
  effective?: boolean;
  reason?: "" | "disabled" | "single_candidate" | "no_candidates" | "shadow";
  effective_candidate_count?: number;
  domain: string;
  pool_source: string;
  formula: string;
  parallel_limit: number;
  tracked_pairs: number;
  active_probes?: number;
  probe_interval_seconds?: number;
  probe_recheck_seconds?: number;
  candidates: DnsServerSchedulerCandidate[];
}

// ---- AmneziaWG (legacy awg2 API paths). Secret fields, including
// obf.header_protection_key, are write-only; presence flags are safe to display. ----
export interface AwgObfuscation {
  jc: number; jmin: number; jmax: number;
  s1: number; s2: number; s3: number; s4: number;
  h1: string; h2: string; h3: string; h4: string;
  i1: string; i2: string; i3: string; i4: string; i5: string;
  header_protection_key?: string;
  has_header_protection_key?: boolean;
  content_padding_addition?: string;
  rekey_after_time?: string;
  rekey_timeout?: string;
  reject_after_time?: string;
  keepalive_timeout?: string;
  max_handshake_attempts?: string;
  random_trailers?: boolean;
  disable_cookies?: boolean;
}
export interface AwgCredentials {
  host: string; port: number; user: string; auth_kind: string;
  password?: string; key_pem?: string; key_pass?: string; known_key: string;
}
export interface AwgPeer {
  id: string; name: string; public_key: string;
  private_key?: string; psk?: string;
  address: string; allowed_ips: string; keepalive: number;
  keepalive_range?: string;
  is_router: boolean; has_private: boolean; created_at: number;
}
/** A routing rule (UI: «Правило»). Order in the parent zones[] array IS its
 *  priority — the first matching rule wins. `route` is the new vocabulary
 *  ("tunnel" / "direct"); `mode` ("include" / "exclude") is the legacy field
 *  still accepted by the backend for backward compat. Always write `route`. */
export interface AwgZone {
  name: string;
  tunnel_id?: string;
  /** Retain this rule without silently assigning a different VPN connection. */
  waiting_for_connection?: boolean;
  /** Ordered backups: primary tunnel_id is tried first, then these IDs. */
  fallback_tunnel_ids?: string[];
  order?: number;
  route?: "tunnel" | "direct";
  mode?: string; // legacy: "include"|"exclude"
  domains: string[];
  /** Omitted preserves legacy semantics; false makes plain domains exact. */
  include_subdomains?: boolean;
  ips: string[];
  source_ips?: string[];
  enabled: boolean;
}
export interface AwgRoutingConfig {
  mode: string; zones: AwgZone[]; mtu: number; killswitch: boolean; domain_source: string;
  sni_routing?: boolean;
  active?: boolean;
}
export interface AwgRoutingState {
  revision: number;
  applying: boolean;
  ready: boolean;
  error?: string;
}
export interface AwgConnectionReference {
  ref: string;
  label: string;
  endpoint?: string;
  client_iface?: string;
  protocol?: string;
  server_public_key?: string;
  fingerprint?: string;
}
export interface AwgRulesDocument {
  format: "nfqws2-strategy-routing";
  version: 1;
  routing: AwgRoutingConfig;
  connections: AwgConnectionReference[];
  warnings?: string[];
}
export interface AwgRulesImportConnection {
  source: AwgConnectionReference;
  matched_tunnel_id?: string;
  state: "matched" | "missing" | "ambiguous" | "changed";
  candidates: { id: string; label: string; endpoint?: string; client_iface?: string; protocol?: string; fingerprint: string }[];
  reason?: "identity_changed";
}
export interface AwgRulesImportPlan {
  connections: AwgRulesImportConnection[];
  rule_count: number;
  waiting_rule_count: number;
  warnings?: string[];
  policy_hash: string;
}
export type AwgRulesMappings = Record<string, string>;
export type AwgRulesImportMode = "replace" | "append";
export interface AwgRulesImportRequest {
  document: string;
  mappings: AwgRulesMappings;
  mapping_fingerprints: Record<string, string>;
  mode: AwgRulesImportMode;
  base_routing?: AwgRoutingConfig;
  expected_policy_hash: string;
}
export interface AwgRulesImportResult {
  rule_count: number;
  waiting_rule_count: number;
  routing_revision: number;
  routing: AwgRoutingConfig;
}
export interface AwgClientConfig { enabled: boolean; peer_id: string }
export interface AwgServerConfig {
  enabled: boolean;
  protocol?: string;
  protocol_version?: string;
  traffic_obfuscation?: boolean;
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
  client_iface?: string;
  deployed_at: number;
}
export interface AwgStep { name: string; ok: boolean; detail: string }
export interface AwgDeployResult {
  ok: boolean; method: string; wan_iface: string; listening: boolean; handshake: boolean;
  steps: AwgStep[]; error?: string;
  rollback_status?: "restored" | "removed_new" | "failed";
  rollback_error?: string; rollback_backup?: string;
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
  awg3_supported?: boolean; update_available?: boolean; target_version?: string;
}
export interface AwgClientStatus {
  running: boolean; iface_present: boolean; last_handshake: number; rx_bytes: number; tx_bytes: number;
  endpoint: string; address: string; mtu: number; connected: boolean; error?: string;
  recovering?: boolean; retry_at?: number; retry_count?: number; recovery_error?: string;
}
export interface Awg2ServerSummary {
  deployment_pending?: boolean;
  id: string; label: string; host: string; endpoint: string;
  client_iface?: string;
  client?: AwgClientStatus | null;
  enabled: boolean; imported: boolean; protocol: string;
  protocol_version?: string; traffic_obfuscation?: boolean; is_warp?: boolean;
  active: boolean; deployed: boolean; connected: boolean; reachable: boolean;
  has_password: boolean; has_key: boolean; has_server_key: boolean; last_error?: string;
}
export interface AwgDeployServerResult {
  id: string; label: string; ok: boolean; result: AwgDeployResult; error?: string;
}
export interface Awg2Status {
  deployment_pending?: boolean;
  config: AwgServerConfig; // redacted (no secrets)
  active_server_id: string;
  servers: Awg2ServerSummary[];
  routing_rules?: AwgZone[];
  /** Shared router routing settings, independent of the selected VPN profile. */
  routing_config?: AwgRoutingConfig;
  routing_state?: AwgRoutingState;
  connection_refs?: Record<string, AwgConnectionReference>;
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

export interface AwgConn {
  id: string;
  label: string;
  endpoint: string;
  state: "connected" | "stale" | "down" | "off" | string;
  connected: boolean;
  running: boolean;
  last_handshake: number;
  rx_bytes: number;
  tx_bytes: number;
  mtu: number;
  address: string;
}

export interface TempZone { label: string; c: number; }
export interface ServiceStat {
  name: string;
  pid: number;
  cpu_percent: number;
  rss_kb: number;
  uptime_sec: number;
}
export interface SystemStats {
  cpu_percent: number;
  load_avg: [number, number, number];
  mem_total_kb: number;
  mem_free_kb: number;
  mem_avail_kb: number;
  mem_used_kb: number;
  mem_apps_kb: number;
  mem_kernel_kb: number;
  mem_cache_kb: number;
  swap_total_kb: number;
  swap_free_kb: number;
  uptime_sec: number;
  temps: TempZone[];
  services: ServiceStat[];
}

export interface AutomationStatus {
  mode: "off" | "on" | "auto";
  auto_pick: boolean;
  periodic_scan: boolean;
  interval_h: number;
  last_pick_at?: number;
  last_pick_args?: string;
  last_pick_name?: string;
  last_pick_error?: string;
  awg_healthy: boolean;
  handshake_age_sec: number;
  nfqws2_running: boolean;
  pick_in_progress: boolean;
  note?: string;
}

export interface Dashboard {
  tgws: TgwsStatus;
  socks5: Socks5Status;
  dnsserver: {
    enabled: boolean;
    running: boolean;
    endpoint: string;
    last_error?: string;
    stats: DnsServerStats;
    cache: DnsServerCache;
  };
  awg: AwgConn[];
  nfqws2_running: boolean;
  conntrack: { count: number; max: number };
  conns: { total: number; failing: number; by_proto: Record<string, number> };
  queues: QueueStat[];
  main_queue: number;
  wan: IfaceBytes[];
  system: SystemStats;
  top_devices: Device[];
  trace_counters: TraceCounters;
}

export interface TraceCounters {
  dns: number;
  sni: number;
  flow: number;
  tunnel: number;
  direct: number;
  blocked: number;
  cdn_skip: number;
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

export interface GeoAutoConfig {
  enabled: boolean;
  geosite_url: string;
  geoip_url: string;
  interval_hours: number;
  last_fetched_at: number;
  last_error: string;
  last_geosite_at: number;
  last_geoip_at: number;
  last_geosite_len: number;
  last_geoip_len: number;
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
  trace_mode: "off" | "auto" | "always";
}

export interface SystemPorts {
  panel_port: number;
  dns_port: number;
  panel_url?: string;
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

/** POST /api/system/install → apk/opkg result. */
export interface InstallResult {
  ok: boolean;
  output: string;
  error?: string;
}

// NFQWS2 engine file management + version.
export type Nfqws2Kind = "conf" | "list" | "lua" | "bypass";

export interface Nfqws2File {
  name: string;
  kind: Nfqws2Kind;
  size: number;
  gz: boolean;
  protected: boolean;
}

export interface Nfqws2Version {
  package: string;
  package_status?: "installed" | "missing" | "unknown";
  engine: string;
  latest: string;
  available: boolean;
  url: string;
  error?: string;
}

export interface OpenWrtDnsState {
  supported: boolean;
  reason?: string;
  interfaces: { id: string; label: string }[];
  instances: { id: string; label: string }[];
  managed: boolean;
  pending?: boolean;
  binding?: { interface: string; instance: string; endpoint: { host: string; port: number } };
  conflict?: string;
  warnings: string[];
  revision: string;
}
