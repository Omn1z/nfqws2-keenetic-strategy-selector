import { useEffect, useState } from "react";
import { api, setUnauthorizedHandler } from "@/lib/api";
import { StoreProvider } from "@/providers/StoreProvider";
import { Toaster } from "@/components/ui/Toast";
import { Spinner } from "@/components/ui/Spinner";
import { Shell } from "@/components/layout/Shell";
import { Login } from "@/components/Login";
import type { AuthStatus } from "@/types/api";

type Phase = "checking" | "login" | "ready";

export default function App() {
  const [phase, setPhase] = useState<Phase>("checking");
  const [authEnabled, setAuthEnabled] = useState(false);

  useEffect(() => {
    setUnauthorizedHandler(() => setPhase("login"));
    void (async () => {
      try {
        const st = await api<AuthStatus>("GET", "/api/auth/status");
        setAuthEnabled(st.enabled);
        setPhase(st.enabled && !st.authed ? "login" : "ready");
      } catch {
        setPhase("ready");
      }
    })();
  }, []);

  if (phase === "checking") return <div className="grid h-screen place-items-center"><Spinner /></div>;
  if (phase === "login") return (<><Login onSuccess={() => setPhase("ready")} /><Toaster /></>);
  return (
    <StoreProvider>
      <Shell authEnabled={authEnabled} />
      <Toaster />
    </StoreProvider>
  );
}
