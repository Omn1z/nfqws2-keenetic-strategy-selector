type HostEntry = { domain: string; strict: boolean; annotated: boolean };

export interface SubdomainDedupResult {
  content: string;
  removed: number;
  examples: { domain: string; coveredBy: string }[];
  skipped?: "format";
}

function hostEntry(line: string): HostEntry | null {
  // Match nfq2/hostlist.c's ASCII whitespace rules. Do not strip inline '#',
  // trailing dots, Unicode whitespace, or turn wildcard/IDN/URL syntax into a
  // different key. Unknown forms are retained byte-for-byte.
  const match = /^[ \t]*(\^?)([^ \t\0]+)([\s\S]*)$/.exec(line);
  if (!match) return null;
  const domain = match[2];
  if (domain.length > 253 || /^[\d.]+$/.test(domain)) return null;
  if (!domain.split(".").every(label => label.length <= 63 && /^[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?$/.test(label))) return null;
  return { domain: domain.toLowerCase(), strict: match[1] === "^", annotated: /[^ \t]/.test(match[3]) };
}

/** Remove only plain subdomain entries covered by an existing non-strict
 * ancestor in this same hostlist. No public-suffix guessing or new domains.
 * This runs once on an explicit editor action, not in the router's data path.
 * Hash lookups walk label boundaries, avoiding pairwise comparison of lists.
 *
 * Upstream semantics: nfq2/hostlist.c SearchHostList/addpool and pools.c
 * ADD_HOSTLIST_POOL keep the FIRST occurrence's strict flag for each key.
 * https://github.com/bol-van/zapret2/blob/master/nfq2/hostlist.c
 */
export function dedupSubdomains(content: string): SubdomainDedupResult {
  // Plain and gzip loaders can interpret NUL/bare CR differently. The plain
  // loader reads LF lines and never treats text after bare CR as a new record.
  // Preserve ambiguous input instead of accidentally broadening its hostlist.
  const unsupported = (): SubdomainDedupResult => ({ content, removed: 0, examples: [], skipped: "format" });
  if (content.includes("\0") || /\r(?!\n)/.test(content)) return unsupported();
  const lines = content.split(/(\r\n|\n)/);
  // fgets(s, 4096) can interpret a long physical line as several records.
  // Only encode potentially long lines (UTF-8 uses at most 3 bytes per UTF-16
  // code unit), keeping the common short-hostname path allocation-free here.
  const encoder = new TextEncoder();
  for (let index = 0; index < lines.length; index += 2) {
    if (lines[index].length >= 1365 && encoder.encode(lines[index]).length >= 4095) return unsupported();
  }
  const entries: (HostEntry | null)[] = [];
  const effective = new Map<string, boolean>();
  for (let index = 0; index < lines.length; index += 2) {
    const entry = hostEntry(lines[index]);
    entries.push(entry);
    if (entry && !effective.has(entry.domain)) effective.set(entry.domain, entry.strict);
  }

  const output: string[] = [];
  const examples: SubdomainDedupResult["examples"] = [];
  let removed = 0;
  for (let index = 0; index < lines.length; index += 2) {
    const entry = entries[index / 2];
    let coveredBy: string | undefined;
    // Preserve exact-match rules and annotated lines, including their notes.
    // Annotated parents still contribute to the effective hostlist above.
    if (entry && !entry.strict && !entry.annotated) {
      for (let dot = entry.domain.indexOf("."); dot !== -1; dot = entry.domain.indexOf(".", dot + 1)) {
        const parent = entry.domain.slice(dot + 1);
        if (effective.get(parent) === false) { coveredBy = parent; break; }
      }
    }
    if (coveredBy !== undefined) {
      removed++;
      if (examples.length < 8) examples.push({ domain: entry!.domain, coveredBy });
    } else output.push(lines[index], lines[index + 1] ?? "");
  }
  return { content: removed ? output.join("") : content, removed, examples };
}
