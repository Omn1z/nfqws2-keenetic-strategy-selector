import { useRef, useState } from "react";
import type { ReactNode } from "react";
import { cn } from "@/lib/cn";

interface DropzoneProps {
  multiple?: boolean;
  accept?: string;
  onFiles: (files: FileList) => void;
  children: ReactNode;
}

export function Dropzone({ multiple, accept, onFiles, children }: DropzoneProps) {
  const ref = useRef<HTMLInputElement>(null);
  const [drag, setDrag] = useState(false);
  return (
    <div
      role="button"
      tabIndex={0}
      onClick={() => ref.current?.click()}
      onKeyDown={(e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); ref.current?.click(); } }}
      onDragEnter={(e) => { e.preventDefault(); setDrag(true); }}
      onDragOver={(e) => { e.preventDefault(); setDrag(true); }}
      onDragLeave={(e) => { if (!e.currentTarget.contains(e.relatedTarget as Node)) setDrag(false); }}
      onDrop={(e) => { e.preventDefault(); setDrag(false); onFiles(e.dataTransfer.files); }}
      className={cn(
        "cursor-pointer rounded-xl border-2 border-dashed p-5 text-center text-ink-soft outline-none transition",
        drag ? "border-accent bg-accent-w" : "border-line bg-line-soft hover:border-accent hover:bg-accent-w",
      )}
    >
      {children}
      <input
        ref={ref}
        type="file"
        multiple={multiple}
        accept={accept}
        hidden
        onChange={(e) => { if (e.target.files) onFiles(e.target.files); e.target.value = ""; }}
      />
    </div>
  );
}
