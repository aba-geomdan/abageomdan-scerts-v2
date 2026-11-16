// ★ 검단ABA 공통 — 앱 사용 칸 + 통합본에서 로그인 없이 열기 (AAC·가정 자료·BIP·SCERTS·학교준비반 모두 같은 파일)
//
// 1) 통합본에서 이 앱을 열면, 통합본이 새 창에 이 앱 전용 로그인을 넣어 준다(aba-app-handoff).
//    이 파일이 앱보다 먼저 읽혀서 그것을 이 앱의 로그인 칸으로 옮긴다 → 로그인 화면 없이 바로 열림.
// 2) 로그인한 사람이 이 앱을 써도 되는지 확인한다.
//    원장님(관리자)은 늘 됨. 선생님은 원장님이 통합본 '선생님 계정 관리'에서 켜 준 앱만 됨.
//    안 되는 앱이면 앱 대신 '아직 열려 있지 않아요' 화면만 보인다.
//    (인터넷 문제 등으로 확인을 못 한 경우에는 막지 않고 잠시 뒤 다시 확인한다)
import React, { useState, useEffect } from "react";

const GATE_URL = "https://vdubgrxwijydwfabwpnk.supabase.co";
const GATE_ANON = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InZkdWJncnh3aWp5ZHdmYWJ3cG5rIiwicm9sZSI6ImFub24iLCJpYXQiOjE3ODE2MDk1ODgsImV4cCI6MjA5NzE4NTU4OH0.nqNO3vany3M6fzmG5BG6QVdvi8BW2UbhTDhxNnwvA88";
const HANDOFF_KEY = "aba-app-handoff";

// 주소로 어느 앱인지 알아낸다 (앱마다 로그인 칸 이름이 다름)
const GATE_APPS = [
  { path: "/aac-maker", app: "aac", key: "sb-auth-session" },
  { path: "/geomdan-guide", app: "guide", key: "sb-auth-session" },
  { path: "/bip-maker", app: "bip", key: "sb-auth-session" },
  { path: "/abageomdan-scerts-v2", app: "scerts", key: "sb-auth-session" },
  { path: "/school-prep", app: "prep", key: "sb-auth-session-sp" },
];
const GATE = (() => {
  try {
    const p = String(window.location.pathname || "");
    return GATE_APPS.find((a) => p === a.path || p.startsWith(a.path + "/")) || null;
  } catch (e) { return null; }
})();

// 1) 통합본이 넘겨준 로그인 옮기기 — 이 파일을 읽는 순간(앱보다 먼저) 한 번
(function adoptHandoff() {
  try {
    const raw = sessionStorage.getItem(HANDOFF_KEY);
    if (!raw) return;
    sessionStorage.removeItem(HANDOFF_KEY);
    if (!GATE) return;
    const h = JSON.parse(raw);
    if (!h || h.app !== GATE.app || !h.session || !h.session.access_token || !h.session.refresh_token) return;
    if (Date.now() - (Number(h.ts) || 0) > 5 * 60 * 1000) return; // 오래된 것은 쓰지 않음
    sessionStorage.setItem(GATE.key, JSON.stringify(h.session));
    sessionStorage.removeItem("sb-aba-auth-session"); // 창을 열 때 따라온 통합본 로그인은 이 창에 필요 없음
  } catch (e) {}
})();

function readSession() {
  try { return GATE ? JSON.parse(sessionStorage.getItem(GATE.key) || "null") : null; } catch (e) { return null; }
}
// true: 써도 됨 / false: 안 됨 / null: 확인 못 함(막지 않고 다시 확인)
async function checkAccess() {
  const s = readSession();
  const token = s && s.access_token;
  if (!token) return null;
  const headers = { apikey: GATE_ANON, Authorization: `Bearer ${token}`, "Content-Type": "application/json" };
  try {
    const a = await fetch(`${GATE_URL}/rest/v1/rpc/is_admin`, { method: "POST", headers, body: "{}" });
    if (a.ok && (await a.json()) === true) return true;
    const r = await fetch(`${GATE_URL}/rest/v1/rpc/my_app_allowed`, { method: "POST", headers, body: JSON.stringify({ p_app: GATE.app }) });
    if (r.ok) return (await r.json()) === true;
    if (r.status === 404) return a.ok ? false : null; // 앱 사용 칸이 아직 없음 → 원장님이 아니면 막음
    return null;
  } catch (e) { return null; }
}

export function AppAccessGate({ children }) {
  const [st, setSt] = useState({ uid: null, denied: false });
  useEffect(() => {
    if (!GATE) return undefined;
    let alive = true;
    let lastUid;
    let retryAt = 0;
    const uidNow = () => { const s = readSession(); return (s && s.user && s.user.id) || null; };
    const run = async (uid) => {
      if (!uid) { setSt({ uid: null, denied: false }); return; }
      const ok = await checkAccess();
      if (!alive || uidNow() !== uid) return;
      if (ok === null) { retryAt = Date.now() + 15000; return; } // 확인 못 함 → 15초 뒤 다시
      retryAt = 0;
      setSt({ uid, denied: ok === false });
    };
    const tick = () => {
      const u = uidNow();
      if (u !== lastUid) { lastUid = u; retryAt = 0; run(u); return; }
      if (u && retryAt && Date.now() > retryAt) { retryAt = 0; run(u); }
    };
    tick();
    const t = setInterval(tick, 1000);
    return () => { alive = false; clearInterval(t); };
  }, []);

  if (!st.denied) return children;
  const logout = () => {
    try { sessionStorage.removeItem(GATE.key); } catch (e) {}
    window.location.reload();
  };
  return (
    <div style={{ minHeight: "100vh", background: "#FFF7F9", display: "flex", alignItems: "center", justifyContent: "center", padding: 20, fontFamily: "'Pretendard', -apple-system, sans-serif" }}>
      <div data-testid="app-locked" style={{ background: "#fff", borderRadius: 18, padding: "36px 28px", maxWidth: 420, width: "100%", textAlign: "center", boxShadow: "0 8px 30px rgba(212,114,138,0.12)" }}>
        <div style={{ fontSize: 40 }}>🔒</div>
        <div style={{ fontSize: 18, fontWeight: 800, color: "#D4728A", margin: "10px 0 8px" }}>이 앱은 아직 열려 있지 않아요</div>
        <div style={{ fontSize: 13, color: "#777", lineHeight: 1.7 }}>원장님께 사용을 요청해 주세요.<br />원장님이 통합본 '선생님 계정 관리'에서 켜 주시면 바로 쓸 수 있습니다.</div>
        <button onClick={logout} style={{ marginTop: 18, padding: "8px 18px", borderRadius: 10, border: "1.5px solid #F5A0B1", background: "#fff", color: "#D4728A", fontWeight: 700, fontSize: 13, cursor: "pointer", fontFamily: "inherit" }}>로그아웃</button>
      </div>
    </div>
  );
}
