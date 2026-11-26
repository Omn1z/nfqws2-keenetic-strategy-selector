import type { DnsServerLogEntry, DnsServerLogSnapshot } from "@/types/api";

// A normalized backend entry occupies more than 64 JSON bytes. This additional
// guard exceeds every valid 128 KiB ring while bounding malformed responses too.
const MAX_LOG_BYTES = 128 * 1024;
const MAX_LOG_ENTRIES = MAX_LOG_BYTES / 64;
const entrySizes = new WeakMap<DnsServerLogEntry, number>();
const encoder = new TextEncoder();
type Read = { revision: number; sequence: number; after: number; full: boolean; path: string };
type Accepted = { snapshot: DnsServerLogSnapshot; reload: boolean };

function mergeSnapshot(previous: DnsServerLogSnapshot | null, incoming: DnsServerLogSnapshot): DnsServerLogSnapshot {
  if (previous && previous.instance_id === incoming.instance_id && !incoming.entries.length && incoming.last_id === previous.last_id && incoming.oldest_id === previous.oldest_id &&
    incoming.bytes === previous.bytes && incoming.max_bytes === previous.max_bytes && incoming.dropped === previous.dropped && incoming.enabled === previous.enabled) {
    return previous;
  }
  if (!incoming.oldest_id) return { ...incoming, entries: [] };
  const entries = new Map<number, DnsServerLogEntry>();
  for (const entry of [...(previous?.entries ?? []), ...incoming.entries]) {
    if (Number.isSafeInteger(entry.id) && entry.id >= incoming.oldest_id && entry.id <= incoming.last_id) entries.set(entry.id, entry);
  }
  const ordered = [...entries.values()].sort((a, b) => a.id - b.id);
  const limit = Number.isSafeInteger(incoming.max_bytes) && incoming.max_bytes > 0 ? Math.min(MAX_LOG_BYTES, incoming.max_bytes) : MAX_LOG_BYTES;
  const retained: DnsServerLogEntry[] = [];
  let bytes = 0;
  for (let i = ordered.length - 1; i >= 0 && retained.length < MAX_LOG_ENTRIES; i--) {
    const entry = ordered[i];
    let size = entrySizes.get(entry);
    if (size === undefined) {
      // Compute only newly received rows. Weak keys release size bookkeeping
      // when evicted entries are no longer retained by the displayed snapshot.
      size = encoder.encode(JSON.stringify(entry)).byteLength + 1;
      entrySizes.set(entry, size);
    }
    if (bytes + size > limit) break;
    retained.push(entry); bytes += size;
  }
  return { ...incoming, entries: retained.reverse() };
}

/** The server's IDs survive Clear, but reset when the panel process restarts.
 * Keep the cursor and the displayed history together, outside React's queued
 * updates. Revision/sequence tokens reject old polls after mutations or a newer
 * response, and an interrupted restart reload remains a full read next time. */
export class DnsLogFeed {
  private snapshot: DnsServerLogSnapshot | null = null;
  private revision = 0;
  private sequence = 0;
  private acceptedSequence = 0;
  private fullRead = false;

  read(): Read {
    const full = this.fullRead || !this.snapshot;
    const after = full ? 0 : this.snapshot?.last_id ?? 0;
    return { revision: this.revision, sequence: ++this.sequence, after, full, path: `/api/dnsserver/logs${full ? "" : `?after=${after}`}` };
  }

  isCurrent(read: Read): boolean {
    return read.revision === this.revision && read.sequence >= this.acceptedSequence;
  }

  accept(read: Read, incoming: DnsServerLogSnapshot): Accepted | null {
    if (!this.isCurrent(read)) return null;
    this.acceptedSequence = read.sequence;
    const previous = this.snapshot;
    // Treat the first appearance/disappearance of this optional field as a
    // generation change too, so an upgrade/downgrade cannot keep stale rows.
    const instanceChanged = previous && previous.instance_id !== incoming.instance_id && Boolean(previous.instance_id || incoming.instance_id);
    const restarted = !read.full && previous && (instanceChanged || incoming.last_id < previous.last_id ||
      incoming.oldest_id > 0 && previous.oldest_id > 0 && incoming.oldest_id < previous.oldest_id ||
      incoming.dropped < previous.dropped && incoming.oldest_id > 0 && incoming.oldest_id <= previous.last_id);
    if (restarted) {
      // Never retain rows from the old process while a full reload is pending.
      this.snapshot = { ...incoming, entries: [] };
      this.fullRead = true;
      return { snapshot: this.snapshot, reload: true };
    }
    this.snapshot = mergeSnapshot(read.full ? null : previous, incoming);
    this.fullRead = false;
    return { snapshot: this.snapshot, reload: false };
  }

  invalidate(): void { this.revision++; }

  replace(incoming: DnsServerLogSnapshot): DnsServerLogSnapshot {
    this.invalidate();
    this.snapshot = mergeSnapshot(null, incoming);
    this.fullRead = false;
    return this.snapshot;
  }
}
