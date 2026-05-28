export type ClassValue = string | false | null | undefined;

/** Join truthy class names (tiny clsx). */
export const cn = (...parts: ClassValue[]): string => parts.filter(Boolean).join(" ");
