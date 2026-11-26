import type { ReactNode } from "react";
import type { ThemeMode } from "@/lib/theme";

// Shared theme metadata so the TopBar (desktop), the SideNav drawer (mobile) and
// the System settings selector render the same icons/labels.
export const THEME_MODES: ThemeMode[] = ["auto", "light", "dark"];

export const THEME_LABEL: Record<ThemeMode, string> = { auto: "Авто", light: "Светлая", dark: "Тёмная" };

export const THEME_ICON: Record<ThemeMode, ReactNode> = {
  auto: <svg viewBox="0 0 24 24" width="16" height="16"><circle cx="12" cy="12" r="9" fill="none" stroke="currentColor" strokeWidth="2" /><path d="M12 3a9 9 0 0 0 0 18z" fill="currentColor" /></svg>,
  light: <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round"><circle cx="12" cy="12" r="4.3" /><path d="M12 1.6v3M12 19.4v3M4.2 4.2l2.1 2.1M17.7 17.7l2.1 2.1M1.6 12h3M19.4 12h3M4.2 19.8l2.1-2.1M17.7 6.3l2.1-2.1" /></svg>,
  dark: <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" strokeWidth="2" strokeLinejoin="round"><path d="M21 12.8A9 9 0 1 1 11.2 3 7 7 0 0 0 21 12.8z" /></svg>,
};
