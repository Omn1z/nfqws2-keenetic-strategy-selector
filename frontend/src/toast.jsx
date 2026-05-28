import { useState, useEffect } from "react";

// Minimal global toast: toast(msg, kind) from anywhere; <Toaster/> renders it.
let pushFn = null;
export function toast(msg, kind) { if (pushFn) pushFn(msg, kind); }

export function Toaster() {
  const [t, setT] = useState(null);
  useEffect(() => {
    let timer;
    pushFn = (msg, kind) => {
      setT({ msg, kind, id: Date.now() });
      clearTimeout(timer);
      timer = setTimeout(() => setT(null), 4200);
    };
    return () => { pushFn = null; clearTimeout(timer); };
  }, []);
  if (!t) return null;
  return <div key={t.id} className={"toast " + (t.kind || "")}>{t.msg}</div>;
}
