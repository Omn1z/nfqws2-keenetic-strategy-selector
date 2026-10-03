export interface ARPBlockSegment {
  id: string;
  name: string;
  address: string;
  members: string[];
  ssids: string[];
  enabled: boolean;
  up: boolean;
  eligible: boolean;
  reason: string;
  home: boolean;
}

export interface ARPBlockClient {
  mac: string;
  ip: string;
  hostname: string;
  segment: string;
  ap: string;
}

export interface ARPBlockView {
  platform: string;
  supported: boolean;
  reason: string;
  revision: string;
  segments: ARPBlockSegment[];
  clients: ARPBlockClient[];
  checked_at: number;
}

export interface IsolationRequest {
  segment: string;
  enabled: boolean;
  revision: string;
}
