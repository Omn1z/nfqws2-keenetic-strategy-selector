import type { Sort } from "@/components/ui/Table";
import type { Blobs } from "@/types/api";

export interface BlobEntry { name: string; custom: boolean; }
export type BlobSource = "all" | "custom" | "system";

/** ResolveBlob uses a custom file before a same-named system file. */
export function blobCatalog(blobs: Blobs): BlobEntry[] {
  const names = new Set<string>();
  const entries: BlobEntry[] = [];
  for (const [files, custom] of [[blobs.custom, true], [blobs.system, false]] as const) {
    for (const name of files) {
      if (names.has(name)) continue;
      names.add(name); entries.push({ name, custom });
    }
  }
  return entries;
}

export function blobRows(entries: BlobEntry[], query: string, source: BlobSource, sort: Sort): BlobEntry[] {
  const search = query.trim().toLowerCase();
  return entries.filter(entry => (!search || entry.name.toLowerCase().includes(search)) &&
    (source === "all" || entry.custom === (source === "custom"))).sort((first, second) => {
    const a = sort.key === "type" ? first.custom ? "custom" : "system" : first.name;
    const b = sort.key === "type" ? second.custom ? "custom" : "system" : second.name;
    return a < b ? -sort.dir : a > b ? sort.dir : first.name.localeCompare(second.name);
  });
}

export function availableBlobSelection(selection: Set<string>, entries: BlobEntry[]): Set<string> {
  const available = new Set(entries.map(entry => entry.name));
  const retained = new Set([...selection].filter(name => available.has(name)));
  return retained.size === selection.size ? selection : retained;
}
