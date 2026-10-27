import type { GeoCategory, GeoFile } from "@/types/api";

export function geoSummary(files: GeoFile[]) {
  const count = (kind: string) => files.filter(file => file.kind === kind).reduce((total, file) => total + (file.categories ?? []).length, 0);
  return { files: files.length, geosite: count("geosite"), geoip: count("geoip"), text: count("text") };
}

/** A refreshed database must not silently substitute another category. */
export function retainedGeoCategory(category: string, categories: GeoCategory[]): string {
  return categories.some(item => item.name === category) ? category : "";
}

export function geoImportPayload(geo: string, category: string, limit: string, listId: string, newName: string) {
  const amount = Number(limit.trim());
  if (!Number.isSafeInteger(amount) || amount < 0) throw new Error("Лимит должен быть целым числом от 0; 0 — все записи");
  return { geo, category, limit: amount, list_id: listId, list_name: newName.trim() };
}
