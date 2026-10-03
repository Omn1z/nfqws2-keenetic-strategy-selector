import type { SVGProps } from "react";

const paths = {
  folder: "M3 7V5a1 1 0 0 1 1-1h5l2 2h9a1 1 0 0 1 1 1v12a1 1 0 0 1-1 1H4a1 1 0 0 1-1-1V7Z",
  file: "M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8ZM14 2v6h6M8 13h8M8 17h5",
  code: "m8 9-4 3 4 3m8-6 4 3-4 3m-3-9-2 18",
  blob: "M4 4h16v16H4ZM8 8h2v2H8Zm6 0h2v2h-2ZM8 14h2v2H8Zm6 0h2v2h-2Z",
  download: "M12 3v12m-5-5 5 5 5-5M4 16v4h16v-4",
  upload: "M12 16V4m-5 5 5-5 5 5M4 16v4h16v-4",
  trash: "M3 6h18M9 6V3h6v3M5 6l1 15h12l1-15M10 10v7m4-7v7",
  refresh: "M20 7v5h-5M4 17v-5h5M6 6a8 8 0 0 1 13 2M5 16a8 8 0 0 0 13 2",
  up: "m5 12 7-7 7 7m-7-7v15",
  chevron: "m9 5 7 7-7 7",
  close: "m6 6 12 12M6 18 18 6",
  search: "M21 21l-5-5M18 10a8 8 0 1 1-16 0 8 8 0 0 1 16 0",
  lock: "M6 10V7a6 6 0 0 1 12 0v3M4 10h16v12H4Zm8 5v3",
};
export function ExplorerIcon({ name, ...props }: SVGProps<SVGSVGElement> & { name: keyof typeof paths | "more" }) {
  return <svg aria-hidden="true" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.65" strokeLinecap="round" strokeLinejoin="round" className="size-4 shrink-0" {...props}>
    {name === "more" ? <><circle cx="5" cy="12" r="1" /><circle cx="12" cy="12" r="1" /><circle cx="19" cy="12" r="1" /></> : <path d={paths[name]} />}
  </svg>;
}
