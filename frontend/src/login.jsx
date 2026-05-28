import { useState } from "react";
import { api } from "./api.js";

export function Login({ onSuccess }) {
  const [user, setUser] = useState("root");
  const [pass, setPass] = useState("");
  const [err, setErr] = useState("");
  const submit = async (e) => {
    e.preventDefault();
    setErr("");
    try { await api("POST", "/api/auth/login", { user, password: pass }); onSuccess(); }
    catch (e) { setErr(e.message); }
  };
  return (
    <div className="overlay">
      <form className="overlay-card login-card" onSubmit={submit}>
        <span className="logo big" aria-hidden="true">
          <svg viewBox="0 0 24 24" width="26" height="26"><path d="M13 2 4 14h6l-1 8 9-12h-6z" fill="currentColor" /></svg>
        </span>
        <h3>Вход</h3>
        <p className="hint">Логин и пароль роутера (как в веб-интерфейсе nfqws).</p>
        <label className="field">Логин<input type="text" autoComplete="username" value={user} onChange={(e) => setUser(e.target.value)} /></label>
        <label className="field">Пароль<input type="password" autoComplete="current-password" value={pass} onChange={(e) => setPass(e.target.value)} /></label>
        <button className="btn btn-primary btn-block" type="submit">Войти</button>
        <div className="login-err">{err}</div>
      </form>
    </div>
  );
}
