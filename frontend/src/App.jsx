import { useState, useEffect } from "react";
import { api, setUnauthorizedHandler } from "./api.js";
import { StoreProvider } from "./store.jsx";
import { Toaster } from "./toast.jsx";
import { Shell } from "./shell.jsx";
import { Login } from "./login.jsx";

export default function App() {
  const [phase, setPhase] = useState("checking"); // checking | login | ready
  const [authEnabled, setAuthEnabled] = useState(false);

  useEffect(() => {
    setUnauthorizedHandler(() => setPhase("login"));
    (async () => {
      try {
        const st = await api("GET", "/api/auth/status");
        setAuthEnabled(!!st.enabled);
        setPhase(st.enabled && !st.authed ? "login" : "ready");
      } catch (_) {
        setPhase("ready");
      }
    })();
  }, []);

  if (phase === "checking") return <div className="boot"><div className="spinner" /></div>;
  if (phase === "login") return (<><Login onSuccess={() => setPhase("ready")} /><Toaster /></>);
  return (
    <StoreProvider>
      <Shell authEnabled={authEnabled} />
      <Toaster />
    </StoreProvider>
  );
}
