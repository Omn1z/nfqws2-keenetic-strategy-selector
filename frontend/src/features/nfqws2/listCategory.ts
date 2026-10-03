export type ListCategory = "current" | "original";

export const listCategories = [
  { id: "current", label: "Текущие", extension: ".list" },
  { id: "original", label: "Оригинальные", extension: ".list-opkg" },
] as const;

// These are display categories, not directories. Keep all other supported list
// formats with current files; never rename a path or infer a category from a
// parent directory whose name happens to end in .list-opkg.
export function listCategory(path: string): ListCategory {
  return /\.list-opkg(?:\.gz)?$/i.test(path) ? "original" : "current";
}
