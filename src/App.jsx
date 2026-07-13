import React, { useState, useEffect, useMemo, useCallback, useRef } from 'react';

// ============================================================
// 도메인 잠금 — 허용된 주소에서만 앱이 작동.
// 남이 코드를 복사해 다른 사이트에 올려도 화면이 뜨지 않게 함.
// 허용: aba-geomdan.github.io (배포) + localhost/127.0.0.1 (로컬 개발)
// ============================================================
(function domainGuard() {
  try {
    if (typeof window === 'undefined') return;
    const host = window.location.hostname || '';
    const allowed =
      host === 'aba-geomdan.github.io' ||
      host === 'localhost' ||
      host === '127.0.0.1' ||
      host === '' ||
      host.endsWith('.local');
    if (!allowed) {
      document.documentElement.innerHTML =
        '<body style="margin:0;display:flex;align-items:center;justify-content:center;' +
        'min-height:100vh;font-family:sans-serif;background:#fdf5f5;color:#a84960;' +
        'text-align:center;padding:24px;">' +
        '<div><div style="font-size:18px;font-weight:700;margin-bottom:8px;">' +
        '접근할 수 없는 페이지입니다</div>' +
        '<div style="font-size:13px;color:#8a6571;line-height:1.6;">' +
        '이 애플리케이션은 검단ABA언어행동연구소의 지적재산이며,<br>' +
        '허가된 주소에서만 이용할 수 있습니다.</div></div></body>';
      throw new Error('unauthorized host');
    }
  } catch (e) {
    if (e && e.message === 'unauthorized host') throw e;
  }
})();

// =====================================================================
// Supabase 연결 설정
// =====================================================================
const SUPABASE_URL = import.meta.env?.VITE_SUPABASE_URL || '';
const SUPABASE_ANON_KEY = import.meta.env?.VITE_SUPABASE_ANON_KEY || '';

// =====================================================================
// Auth 세션 관리 (Supabase Auth)
// =====================================================================
const AUTH_SESSION_KEY = 'sb-auth-session';

function getStoredSession() {
  try {
    const raw = sessionStorage.getItem(AUTH_SESSION_KEY);
    if (!raw) return null;
    const s = JSON.parse(raw);
    // 만료 확인 (5분 여유)
    if (s.expires_at && s.expires_at * 1000 < Date.now() + 5 * 60 * 1000) {
      return null; // 만료됨 (refresh 필요)
    }
    return s;
  } catch (e) { return null; }
}

function saveSession(session) {
  try {
    if (session) sessionStorage.setItem(AUTH_SESSION_KEY, JSON.stringify(session));
    else sessionStorage.removeItem(AUTH_SESSION_KEY);
    // 과거 localStorage에 남아있던 자동로그인 흔적 제거 (보안)
    localStorage.removeItem(AUTH_SESSION_KEY);
  } catch (e) {}
}

async function refreshSession(refreshToken) {
  try {
    const r = await fetch(`${SUPABASE_URL}/auth/v1/token?grant_type=refresh_token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'apikey': SUPABASE_ANON_KEY },
      body: JSON.stringify({ refresh_token: refreshToken }),
    });
    if (!r.ok) return null;
    const data = await r.json();
    if (data.access_token) {
      saveSession(data);
      return data;
    }
    return null;
  } catch (e) { return null; }
}

async function getValidAccessToken() {
  let session = getStoredSession();
  if (session?.access_token) return session.access_token;
  // 만료됐거나 없음: refresh 시도
  const raw = sessionStorage.getItem(AUTH_SESSION_KEY);
  if (raw) {
    try {
      const old = JSON.parse(raw);
      if (old.refresh_token) {
        const refreshed = await refreshSession(old.refresh_token);
        if (refreshed?.access_token) return refreshed.access_token;
      }
    } catch (e) {}
  }
  return null;
}

// 인증 헤더 (Auth 세션의 access_token 사용)
async function authHeaders() {
  const token = await getValidAccessToken();
  return {
    'apikey': SUPABASE_ANON_KEY,
    'Authorization': token ? `Bearer ${token}` : `Bearer ${SUPABASE_ANON_KEY}`,
    'Content-Type': 'application/json',
  };
}

// =====================================================================
// Auth API 함수들
// =====================================================================
async function signInWithPassword(email, password) {
  try {
    const r = await fetch(`${SUPABASE_URL}/auth/v1/token?grant_type=password`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'apikey': SUPABASE_ANON_KEY },
      body: JSON.stringify({ email, password }),
    });
    const data = await r.json();
    if (!r.ok) {
      return { error: data.error_description || data.msg || data.error || '로그인 실패' };
    }
    saveSession(data);
    return { session: data, user: data.user };
  } catch (e) {
    return { error: '네트워크 오류: ' + e.message };
  }
}

async function signOut() {
  try {
    const token = await getValidAccessToken();
    if (token) {
      await fetch(`${SUPABASE_URL}/auth/v1/logout`, {
        method: 'POST',
        headers: { 'apikey': SUPABASE_ANON_KEY, 'Authorization': `Bearer ${token}` },
      });
    }
  } catch (e) {}
  saveSession(null);
}

async function getCurrentUser() {
  try {
    const token = await getValidAccessToken();
    if (!token) return null;
    const r = await fetch(`${SUPABASE_URL}/auth/v1/user`, {
      headers: { 'apikey': SUPABASE_ANON_KEY, 'Authorization': `Bearer ${token}` },
    });
    if (!r.ok) return null;
    return await r.json();
  } catch (e) { return null; }
}

// 관리자용: 새 유저 만들기 (Edge Function 호출)
async function adminCreateUser(email, password, displayName) {
  try {
    const headers = await authHeaders();
    const r = await fetch(`${SUPABASE_URL}/functions/v1/admin-users`, {
      method: 'POST',
      headers,
      body: JSON.stringify({
        action: 'create',
        email,
        password,
        display_name: displayName || email.split('@')[0],
      }),
    });
    const data = await r.json();
    if (!r.ok) return { error: data.error || '계정 생성 실패' };
    return { user: data.user };
  } catch (e) { return { error: '네트워크 오류: ' + e.message }; }
}

async function adminDeleteUser(userId) {
  try {
    const headers = await authHeaders();
    const r = await fetch(`${SUPABASE_URL}/functions/v1/admin-users`, {
      method: 'POST',
      headers,
      body: JSON.stringify({ action: 'delete', user_id: userId }),
    });
    if (!r.ok) {
      const data = await r.json().catch(() => ({}));
      return { error: data.error || '삭제 실패' };
    }
    return { ok: true };
  } catch (e) { return { error: '네트워크 오류: ' + e.message }; }
}

async function adminUpdateUserPassword(userId, newPassword) {
  try {
    const headers = await authHeaders();
    const r = await fetch(`${SUPABASE_URL}/functions/v1/admin-users`, {
      method: 'POST',
      headers,
      body: JSON.stringify({ action: 'update_password', user_id: userId, password: newPassword }),
    });
    const data = await r.json();
    if (!r.ok) return { error: data.error || '비번 변경 실패' };
    return { ok: true };
  } catch (e) { return { error: '네트워크 오류: ' + e.message }; }
}

// 관리자용: 전체 유저 목록 (RPC)
async function adminListUsers() {
  try {
    const headers = await authHeaders();
    const r = await fetch(`${SUPABASE_URL}/rest/v1/rpc/admin_list_users`, {
      method: 'POST',
      headers,
      body: '{}',
    });
    if (!r.ok) return [];
    return await r.json();
  } catch (e) { return []; }
}

async function adminGetUserData(userId) {
  try {
    const headers = await authHeaders();
    const r = await fetch(`${SUPABASE_URL}/rest/v1/rpc/admin_get_user_data`, {
      method: 'POST',
      headers,
      body: JSON.stringify({ target_user_id: userId }),
    });
    if (!r.ok) return [];
    return await r.json();
  } catch (e) { return []; }
}

// =====================================================================
// 데이터 저장/조회 (scerts_data 테이블 — RLS로 본인 데이터만 접근)
// =====================================================================
async function dataGet(key) {
  try {
    const headers = await authHeaders();
    const user = await getCurrentUser();
    if (!user?.id) return null;
    const url = `${SUPABASE_URL}/rest/v1/scerts_data?user_id=eq.${user.id}&key=eq.${encodeURIComponent(key)}&select=key,value`;
    const r = await fetch(url, { headers });
    if (!r.ok) return null;
    const rows = await r.json();
    if (rows && rows.length > 0) {
      return { key: rows[0].key, value: rows[0].value };
    }
    return null;
  } catch (e) { return null; }
}

async function dataSet(key, value) {
  try {
    const headers = await authHeaders();
    const user = await getCurrentUser();
    if (!user?.id) return null;
    const r = await fetch(`${SUPABASE_URL}/rest/v1/scerts_data`, {
      method: 'POST',
      headers: { ...headers, 'Prefer': 'resolution=merge-duplicates,return=minimal' },
      body: JSON.stringify({
        user_id: user.id,
        key,
        value,
        updated_at: new Date().toISOString(),
      }),
    });
    if (!r.ok) return null;
    return { key, value };
  } catch (e) { return null; }
}

async function dataDelete(key) {
  try {
    const headers = await authHeaders();
    const user = await getCurrentUser();
    if (!user?.id) return null;
    const url = `${SUPABASE_URL}/rest/v1/scerts_data?user_id=eq.${user.id}&key=eq.${encodeURIComponent(key)}`;
    await fetch(url, { method: 'DELETE', headers });
    return { key, deleted: true };
  } catch (e) { return null; }
}

async function dataList(prefix) {
  try {
    const headers = await authHeaders();
    const user = await getCurrentUser();
    if (!user?.id) return { keys: [] };
    const filter = prefix ? `&key=like.${encodeURIComponent(prefix)}*` : '';
    const url = `${SUPABASE_URL}/rest/v1/scerts_data?user_id=eq.${user.id}&select=key${filter}`;
    const r = await fetch(url, { headers });
    if (!r.ok) return { keys: [] };
    const rows = await r.json();
    return { keys: (rows || []).map((row) => row.key) };
  } catch (e) { return { keys: [] }; }
}

// window.storage 인터페이스 (기존 코드 호환용)
// shared 파라미터는 이제 무시됨 (모든 데이터가 본인 소유이거나 관리자 조회)
if (typeof window !== 'undefined') {
  window.storage = {
    get: (key) => dataGet(key),
    set: (key, value) => dataSet(key, value),
    delete: (key) => dataDelete(key),
    list: (prefix) => dataList(prefix),
  };
}

// =====================================================================
// SCERTS 진단 데이터 정의 (사회적/언어/대화 파트너 단계)
// 출처: SCERTS 진단 양식 (Prizant, Wetherby, Rubin, Laurent, Rydell, 2006)
// =====================================================================

const STAGE_KEYS = {
  SOCIAL: 'social',
  LANGUAGE: 'language',
  CONVERSATION: 'conversation',
};

// ── 인쇄 헬퍼 ────────────────────────────────────────────────────
// 보고서를 독립 HTML 문서로 추출해 (1) 새 창에서 인쇄/PDF 저장 시도,
// (2) 새 창이 막히면 HTML 파일로 다운로드 → 사용자가 열어 PDF 저장.

// 모든 textarea를 내용 높이에 맞춰 펼친다 (추출 전 호출)
// 생년월일 + 기준일 → "만 N세 M개월" 문자열 (영유아 개월 표기)
// birth, asOf 둘 다 'YYYY-MM-DD' 형식. 계산 불가하면 '' 반환.
// 한글 받침 유무 판별
function hasJongseong(word) {
  if (!word) return false;
  const ch = word[word.length - 1];
  const code = ch.charCodeAt(0);
  if (code < 0xac00 || code > 0xd7a3) return false;
  return (code - 0xac00) % 28 !== 0;
}

// 한국 복성(두 글자 성) 목록 — 이 경우 성을 2글자로 분리
const COMPOUND_SURNAMES = ['남궁', '선우', '독고', '황보', '제갈', '사공', '서문', '동방', '망절'];

// 문자열이 전부 한글 음절(가~힣)로만 이루어졌는지
function isAllHangul(str) {
  if (!str) return false;
  for (const ch of str) {
    const code = ch.charCodeAt(0);
    if (code < 0xac00 || code > 0xd7a3) return false;
  }
  return true;
}

// 전체 이름에서 성을 떼고 '이름'만 반환. 예: '민다슬' → '다슬', '남궁민수' → '민수'
// 분리가 부적절한 경우(비한글 포함, 너무 짧음, 복성 단독)에는 전체를 그대로 반환.
function firstNameOnly(fullName) {
  const name = (fullName || '').trim();
  if (!name) return '';
  // 한글 이외 문자가 섞이면(영문/숫자 등) 성 분리하지 않고 그대로 사용
  if (!isAllHangul(name)) return name;
  // 복성(두 글자 성) 단독이면 분리하지 않음 (예: '남궁' → '남궁')
  if (COMPOUND_SURNAMES.includes(name)) return name;
  // 복성 + 이름이 있을 때만 복성 분리 (남은 글자가 1자 이상)
  for (const s of COMPOUND_SURNAMES) {
    if (name.startsWith(s) && name.length >= s.length + 1) {
      return name.slice(s.length);
    }
  }
  // 일반 단성: 3글자 이상이면 첫 글자를 성으로 분리 (민다슬→다슬, 김민준→민준)
  if (name.length >= 3) return name.slice(1);
  // 2글자(예: 김수)는 성+외자 이름 → 첫 글자 성 분리 (수)
  if (name.length === 2) return name.slice(1);
  // 1글자는 성인지 이름인지 알 수 없음 → 그대로 둠 (성만 입력된 경우 분리하면 안 됨)
  return name;
}

// 호칭용 이름 + 조사. 받침 있으면 '이'를 넣어 '다슬이는' 형태로.
//   childCallName('민다슬','은','는') → '다슬이는'
//   childCallName('이서아','은','는') → '서아는'
//   이름 없으면 '아동' + 조사(받침형)
function childName(fullName, withBatchim, withoutBatchim) {
  const first = firstNameOnly(fullName);
  if (!first) return '아동' + withBatchim; // '아동'은 받침 있음
  const lastCh = first[first.length - 1];
  const isKoreanLast = lastCh && lastCh.charCodeAt(0) >= 0xac00 && lastCh.charCodeAt(0) <= 0xd7a3;
  if (!isKoreanLast) {
    // 비한글(영문/숫자 등)로 끝나면 '이' 삽입 없이 받침형 조사를 기본 사용 (예: John은)
    return first + withBatchim;
  }
  if (hasJongseong(first)) {
    // 받침 있는 한글 이름 → '이' 삽입 후 받침없는 조사 ('이'로 끝나므로)
    return first + '이' + withoutBatchim;
  }
  // 받침 없는 한글 이름 → 그대로 + 받침없는 조사
  return first + withoutBatchim;
}
// 자주 쓰는 조사 단축 (호칭형)
const nmEunNeun = (n) => childName(n, '은', '는');   // 은/는 → 다슬이는 / 서아는
const nmIGa = (n) => childName(n, '이', '가');       // 이/가 → 다슬이가 / 서아가
const nmEulReul = (n) => childName(n, '을', '를');   // 을/를 → 다슬이를 / 서아를
const nmUi = (n) => {                                 // 의 → 다슬이의 / 서아의
  const first = firstNameOnly(n);
  if (!first) return '아동의';
  const lastCh = first[first.length - 1];
  const isKoreanLast = lastCh && lastCh.charCodeAt(0) >= 0xac00 && lastCh.charCodeAt(0) <= 0xd7a3;
  if (!isKoreanLast) return first + '의';
  return hasJongseong(first) ? first + '이의' : first + '의';
};

// 표준 설명문(MR_SR 해설 등)을 특정 아동 보고서에 끼워 넣을 때,
// 문장 속 "아동은/이/가/을/를/의/에게" 등을 아동 이름+조사로 치환하고
// 격식체(~입니다/습니다)를 평서체(~다)로 정리한다.
function localizeText(text, fullName) {
  if (!text) return '';
  let t = text;
  // 조사별 치환 (긴 것부터: 에게 → 의 → 은/는/이/가/을/를 순서 주의)
  t = t.replace(/아동에게/g, () => {
    const f = firstNameOnly(fullName);
    if (!f) return '아동에게';
    const lc = f[f.length - 1];
    const isK = lc && lc.charCodeAt(0) >= 0xac00 && lc.charCodeAt(0) <= 0xd7a3;
    return (isK && hasJongseong(f)) ? f + '이에게' : f + '에게';
  });
  t = t.replace(/아동의/g, () => nmUi(fullName));
  t = t.replace(/아동은/g, () => childName(fullName, '은', '는'));
  t = t.replace(/아동이/g, () => childName(fullName, '이', '가'));  // 주격 '이'
  t = t.replace(/아동가/g, () => childName(fullName, '이', '가'));  // 안전망
  t = t.replace(/아동을/g, () => childName(fullName, '을', '를'));
  t = t.replace(/아동를/g, () => childName(fullName, '을', '를'));  // 안전망
  // 남은 '아동' (조사 없이 단독) → 이름만
  t = t.replace(/아동/g, () => {
    const f = firstNameOnly(fullName);
    if (!f) return '아동';
    const lc = f[f.length - 1];
    const isK = lc && lc.charCodeAt(0) >= 0xac00 && lc.charCodeAt(0) <= 0xd7a3;
    return (isK && hasJongseong(f)) ? f + '이' : f;
  });
  // 격식체 → 평서체
  t = t.replace(/입니다\./g, '다.').replace(/습니다\./g, '다.');
  return t;
}

function calcAge(birth, asOf) {
  if (!birth) return '';
  const b = new Date(birth);
  const d = asOf ? new Date(asOf) : new Date();
  if (isNaN(b.getTime()) || isNaN(d.getTime()) || d < b) return '';
  let years = d.getFullYear() - b.getFullYear();
  let months = d.getMonth() - b.getMonth();
  if (d.getDate() < b.getDate()) months -= 1;
  if (months < 0) { years -= 1; months += 12; }
  if (years <= 0) return `만 ${months}개월`;
  return months > 0 ? `만 ${years}세 ${months}개월` : `만 ${years}세`;
}

function autosizeTextareas() {
  document.querySelectorAll('textarea').forEach((ta) => {
    ta.style.height = 'auto';
    const hasContent = ta.value && ta.value.trim().length > 0;
    ta.style.height = hasContent ? (ta.scrollHeight + 2) + 'px' : '1.7em';
  });
}

// 보고서 영역을 독립 HTML 문서 문자열로 추출
function buildReportHTML() {
  const report = document.getElementById('printable-report');
  if (!report) return null;

  // 1) 보고서 노드 복제
  const clone = report.cloneNode(true);

  // 2) 복제본 안의 textarea/input을 정적 텍스트(div)로 치환
  //    (입력칸 테두리 없이 내용만 깔끔히 인쇄되도록)
  clone.querySelectorAll('textarea').forEach((ta) => {
    const div = document.createElement('div');
    div.className = 'static-text';
    div.textContent = ta.value || '';
    ta.parentNode.replaceChild(div, ta);
  });
  clone.querySelectorAll('input').forEach((inp) => {
    if (inp.type === 'text' || inp.type === 'number' || !inp.type) {
      const span = document.createElement('span');
      span.className = 'static-text';
      span.textContent = inp.value || '';
      inp.parentNode.replaceChild(span, inp);
    }
  });

  // 3) no-print 요소 제거 (예시 버튼, 안내 배너 등)
  clone.querySelectorAll('.no-print, .ex-bar, .step-banner').forEach((el) => el.remove());

  // 4) 페이지의 모든 <style> 수집 (보고서 디자인 유지)
  let css = '';
  document.querySelectorAll('style').forEach((s) => { css += s.textContent + '\n'; });

  // 5) 독립 문서 조립
  const title = (clone.querySelector('h1, .report-title')?.textContent || 'SCERTS 보고서').trim();
  return `<!DOCTYPE html>
<html lang="ko">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${title}</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Gowun+Batang:wght@400;700&family=IBM+Plex+Sans+KR:wght@400;500;600;700&display=swap" rel="stylesheet">
<style>
${css}
/* 독립 문서용 보정 */
body { margin: 0; background: #fff; font-family: 'IBM Plex Sans KR', sans-serif; }
.static-text { white-space: pre-wrap; word-break: break-word; line-height: 1.55; }
.print-only { display: inline !important; }
.closing-reason-print, .closing-status-print { display: inline !important; }
#printable-report, .printable { width: 100%; max-width: 100%; margin: 0 auto; padding: 24px; box-sizing: border-box; }
@page { size: A4; margin: 16mm; }
@media print { #printable-report, .printable { padding: 0; } }
</style>
</head>
<body>
${clone.outerHTML}
</body>
</html>`;
}

// 메인: 보고서를 PDF로 (새 창 자동인쇄 → 실패 시 HTML 다운로드)
function exportReportPDF() {
  autosizeTextareas();
  const html = buildReportHTML();
  if (!html) {
    return { ok: false, reason: 'no-report' };
  }

  // (1) 새 창 시도
  let win = null;
  try {
    win = window.open('', '_blank');
  } catch (e) { win = null; }

  if (win && win.document) {
    try {
      win.document.open();
      win.document.write(html);
      win.document.close();
      // 폰트/렌더 후 인쇄 대화상자 호출
      setTimeout(() => { try { win.focus(); win.print(); } catch (e) {} }, 600);
      return { ok: true, mode: 'window' };
    } catch (e) {
      try { win.close(); } catch (e2) {}
    }
  }

  // (2) 새 창이 막혔으면 HTML 파일 다운로드
  try {
    const blob = new Blob([html], { type: 'text/html;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    const fname = (document.querySelector('#printable-report h1, #printable-report .report-title')?.textContent || 'SCERTS_보고서')
      .trim().replace(/[\\/:*?"<>|]/g, '_').slice(0, 60);
    a.href = url;
    a.download = `${fname}.html`;
    document.body.appendChild(a);
    a.click();
    setTimeout(() => { document.body.removeChild(a); URL.revokeObjectURL(url); }, 1000);
    return { ok: true, mode: 'download' };
  } catch (e) {
    return { ok: false, reason: 'download-failed' };
  }
}

function printReport() {
  exportReportPDF();
}


// ── 전역 다이얼로그 ───────────────────────────────
// 브라우저 기본 confirm/prompt/alert 대신 사용하는 자체 모달 시스템.
// 사용법: await appConfirm('메시지'), await appPrompt('질문','기본값'), appAlert('메시지')
let _dialogHandler = null;
function registerDialogHandler(fn) { _dialogHandler = fn; }

function appConfirm(message) {
  if (_dialogHandler) return _dialogHandler({ type: 'confirm', message });
  try { return Promise.resolve(window.confirm(message)); } catch (e) { return Promise.resolve(true); }
}
function appPrompt(message, defaultValue = '') {
  if (_dialogHandler) return _dialogHandler({ type: 'prompt', message, defaultValue });
  try { return Promise.resolve(window.prompt(message, defaultValue)); } catch (e) { return Promise.resolve(null); }
}
function appAlert(message) {
  if (_dialogHandler) return _dialogHandler({ type: 'alert', message });
  try { window.alert(message); } catch (e) {}
  return Promise.resolve();
}

// 다이얼로그 렌더링 컴포넌트 (App 최상위에 1개 마운트)
function AppDialog() {
  const [dialog, setDialog] = useState(null);
  const resolverRef = useRef(null);
  const inputRef = useRef(null);

  useEffect(() => {
    registerDialogHandler((opts) => new Promise((resolve) => {
      resolverRef.current = resolve;
      setDialog(opts);
    }));
    return () => registerDialogHandler(null);
  }, []);

  useEffect(() => {
    if (dialog && dialog.type === 'prompt' && inputRef.current) {
      setTimeout(() => { inputRef.current?.focus(); inputRef.current?.select(); }, 50);
    }
  }, [dialog]);

  if (!dialog) return null;

  const close = (result) => {
    const r = resolverRef.current;
    setDialog(null);
    resolverRef.current = null;
    if (r) r(result);
  };
  const handleConfirm = () => {
    if (dialog.type === 'prompt') {
      close(inputRef.current ? inputRef.current.value : (dialog.defaultValue || ''));
    } else {
      close(true);
    }
  };
  const handleCancel = () => {
    close(dialog.type === 'prompt' ? null : false);
  };

  return (
    <div className="app-dialog-overlay" onClick={(e) => { if (e.target === e.currentTarget) handleCancel(); }}>
      <div className="app-dialog" role="dialog" aria-modal="true">
        <div className="app-dialog-message">{dialog.message}</div>
        {dialog.type === 'prompt' && (
          <input
            ref={inputRef}
            type="text"
            className="app-dialog-input"
            defaultValue={dialog.defaultValue || ''}
            onKeyDown={(e) => {
              if (e.key === 'Enter') handleConfirm();
              if (e.key === 'Escape') handleCancel();
            }}
          />
        )}
        <div className="app-dialog-actions">
          {dialog.type !== 'alert' && (
            <button className="btn-ghost" onClick={handleCancel}>취소</button>
          )}
          <button className="btn-primary" onClick={handleConfirm}>확인</button>
        </div>
      </div>
    </div>
  );
}

const STAGE_LABELS = {
  social: '사회적 파트너 단계',
  language: '언어 파트너 단계',
  conversation: '대화 파트너 단계',
};

// ── 단계 결정 기록지 ──────────────────────────────────────────────
const STAGE_DECISION = {
  q1: {
    title: '1. 다음의 모든 항목에 해당되는가?',
    items: [
      { id: '1a', label: '적어도 3개의 다양한 단어나 구(말, 수어, 그림, 문자 또는 기타 상징 체계)를 사용하는가?' },
      { id: '1b', label: '적어도 3개 이상의 단어나 구를 참조의 목적으로(구체적인 물건, 사람 또는 활동을 언급) 사용하는가?' },
      { id: '1c', label: '적어도 3개 이상의 단어나 구를 의사소통 의도로(몸짓이나 눈맞춤과 조합) 사용하는가?' },
      { id: '1d', label: '적어도 3개 이상의 단어나 구를 정기적으로(자주) 사용하는가?' },
    ],
    instruction: '모두 "예"가 아니면 → 사회적 파트너 단계. 모두 "예"면 → 질문 2로 이동',
  },
  q2: {
    title: '2. 다음의 모든 항목에 해당되는가?',
    items: [
      { id: '2a', label: '적어도 100개의 다양한 단어나 구를 사용하는가?' },
      { id: '2b', label: '적어도 100개 이상의 단어나 구를 참조의 목적으로 사용하는가?' },
      { id: '2c', label: '적어도 100개 이상의 단어나 구를 의사소통 의도로 사용하는가?' },
      { id: '2d', label: '적어도 100개 이상의 단어나 구를 정기적으로 사용하는가?' },
      { id: '2e', label: '적어도 20개 이상의 창의적인 단어 조합(정확한 모방이 아님)을 사용하는가?' },
    ],
    instruction: '모두 "예"가 아니면 → 언어 파트너 단계. 모두 "예"면 → 대화 파트너 단계',
  },
};

// ── 채점 기준 공통 ─────────────────────────────────────────────────
const SCORING_LEGEND = [
  { score: 2, label: '일관성 있게 도달', desc: '두 가지 상황에서 두 명의 파트너에 걸쳐 준거에 도달' },
  { score: 1, label: '부분적 도달', desc: '일관성 없이/하나의 활동에서/보조를 받아 도달' },
  { score: 0, label: '미도달', desc: '관찰 또는 보고에 근거할 때 준거에 도달하지 못함' },
];

// ── 사회-정서 성장 지표 (모든 단계 공통) ───────────────────────
const SES_INDICATORS = [
  { id: 'happiness', label: '행복감' },
  { id: 'selfAwareness', label: '자아의식' },
  { id: 'otherAwareness', label: '타인의식' },
  { id: 'activeLearning', label: '적극적인 학습 및 조직화' },
  { id: 'flexibility', label: '융통성 및 회복력' },
  { id: 'cooperation', label: '협력 및 행동의 적절성' },
  { id: 'independence', label: '독립성' },
  { id: 'belonging', label: '사회적 소속감 및 우정' },
];

// =====================================================================
// 사회적 파트너 단계 진단 항목
// =====================================================================
const SOCIAL_PARTNER = {
  // 사회 의사소통 - 공동관심 (JA) /54
  joinAttention: {
    label: '공동관심 (Joint Attention)',
    code: 'JA',
    maxScore: 54,
    groups: [
      {
        title: '1. 상호적 상호작용에 참여하기',
        items: [
          { id: 'JA1.1', label: '상호작용 시도에 반응하기' },
          { id: 'JA1.2', label: '상호작용 시도 시작하기' },
          { id: 'JA1.3', label: '간단한 상호적 상호작용에 참여하기' },
          { id: 'JA1.4', label: '확장된 상호적 상호작용에 참여하기' },
        ],
      },
      {
        title: '2. 관심 공유하기',
        items: [
          { id: 'JA2.1', label: '사람 쳐다보기' },
          { id: 'JA2.2', label: '사람과 사물 간에 시선 옮기기' },
          { id: 'JA2.3', label: '짚어서 가리키는 것을 쳐다보기' },
          { id: 'JA2.4', label: '멀리 있는 것을 가리킬 때 쳐다보기' },
        ],
      },
      {
        title: '3. 정서 공유하기',
        items: [
          { id: 'JA3.1', label: '얼굴 표정/발성으로 부정적인 정서 공유하기' },
          { id: 'JA3.2', label: '얼굴 표정/발성으로 긍정적인 정서 공유하기' },
          { id: 'JA3.3', label: '파트너의 정서 표현 변화에 반응하기' },
          { id: 'JA3.4', label: '파트너의 정서 표현 변화에 동조하기' },
        ],
      },
      {
        title: '4. 다른 사람의 행동을 조절하기 위해 의도 공유하기',
        items: [
          { id: 'JA4.1', label: '원하는 음식이나 사물 요구하기' },
          { id: 'JA4.2', label: '원하지 않는 음식이나 사물 거부/거절하기' },
          { id: 'JA4.3', label: '도움 또는 기타 행동 요구하기' },
          { id: 'JA4.4', label: '원하지 않는 행동이나 활동 거부하기' },
        ],
      },
      {
        title: '5. 사회적 상호작용을 위해 의도 공유하기',
        items: [
          { id: 'JA5.1', label: '위로 구하기' },
          { id: 'JA5.2', label: '사회적 게임 요구하기' },
          { id: 'JA5.3', label: '차례 주고받기' },
          { id: 'JA5.4', label: '인사하기' },
          { id: 'JA5.5', label: '부르기' },
          { id: 'JA5.6', label: '자랑하기' },
        ],
      },
      {
        title: '6. 공동관심을 위해 의도 공유하기',
        items: [
          { id: 'JA6.1', label: '사물에 대해 언급하기' },
          { id: 'JA6.2', label: '행동이나 사건에 대해 언급하기' },
        ],
      },
      {
        title: '7. 의사소통 실패를 복구하고 지속하기',
        items: [
          { id: 'JA7.1', label: '맥락에 적절한 비율로 의사소통하기' },
          { id: 'JA7.2', label: '의사소통 실패를 복구하기 위해 반복하기' },
          { id: 'JA7.3', label: '의사소통 실패를 복구하기 위해 수정하기' },
        ],
      },
    ],
  },

  // 상징 사용 (SU) /62
  symbolUse: {
    label: '상징 사용 (Symbol Use)',
    code: 'SU',
    maxScore: 62,
    groups: [
      {
        title: '1. 익숙한 행동과 소리 모방을 통해 학습하기',
        items: [
          { id: 'SU1.1', label: '자신의 행동/소리를 반복하면서 차례 주고받기' },
          { id: 'SU1.2', label: '시범 후 즉시 유도하면 익숙한 행동/소리 모방하기' },
          { id: 'SU1.3', label: '시범 후 즉시 자발적으로 익숙한 행동/소리 모방하기' },
          { id: 'SU1.4', label: '시간이 경과된 후 자발적으로 익숙한 행동/소리 모방하기' },
        ],
      },
      {
        title: '2. 익숙한 활동에서 비구어 단서 이해하기',
        items: [
          { id: 'SU2.1', label: '익숙한 일과에서 다른 사람의 행동 예상하기' },
          { id: 'SU2.2', label: '익숙한 일과에서 상황 단서 따르기' },
          { id: 'SU2.3', label: '가리키기 이외의 몸짓 단서 따르기' },
          { id: 'SU2.4', label: '짚어서 가리키는 것을 쳐다보기' },
          { id: 'SU2.5', label: '멀리 있는 것을 가리킬 때 쳐다보기' },
          { id: 'SU2.6', label: '시각적 단서(사진/그림)에 반응하기' },
          { id: 'SU2.7', label: '얼굴 표정과 억양 단서에 반응하기' },
        ],
      },
      {
        title: '3. 놀이 중 익숙한 사물을 관습적인 방식으로 사용하기',
        items: [
          { id: 'SU3.1', label: '사물에 대한 탐색 행동 보이기' },
          { id: 'SU3.2', label: '구성놀이에서 익숙한 사물 사용하기' },
          { id: 'SU3.3', label: '익숙한 사물을 관습적으로 자신에게 사용하기' },
          { id: 'SU3.4', label: '익숙한 사물을 관습적으로 다른 사람에게 사용하기' },
        ],
      },
      {
        title: '4. 의도 공유를 위해 몸짓이나 비구어 수단 사용하기',
        items: [
          { id: 'SU4.1', label: '근접성 사용하기' },
          { id: 'SU4.2', label: '얼굴 표정 사용하기' },
          { id: 'SU4.3', label: '간단한 동작 사용하기' },
          { id: 'SU4.4', label: '관습적인 접촉 몸짓 사용하기' },
          { id: 'SU4.5', label: '먼 곳을 향한 관습적인 몸짓 사용하기' },
          { id: 'SU4.6', label: '재연 또는 먼 곳을 향한 상징적 몸짓 사용하기' },
          { id: 'SU4.7', label: '일련의 몸짓이나 비구어 수단 사용하기' },
          { id: 'SU4.8', label: '몸짓과 시선 일치시키기' },
        ],
      },
      {
        title: '5. 의도 공유를 위해 발성 사용하기',
        items: [
          { id: 'SU5.1', label: '차별화된 발성 사용하기' },
          { id: 'SU5.2', label: '다양한 자음+모음 조합 사용하기' },
          { id: 'SU5.3', label: '일과와 밀접하게 관련된 단어 사용하기' },
          { id: 'SU5.4', label: '발성을 시선과 몸짓에 일치시키기' },
        ],
      },
      {
        title: '6. 2~3개의 익숙한 단어 이해하기',
        items: [
          { id: 'SU6.1', label: '자신의 이름에 반응하기' },
          { id: 'SU6.2', label: '익숙한 사회적 게임에서 2~3개의 단어에 반응하기' },
          { id: 'SU6.3', label: '2~3개의 친숙한 사람/신체부위/사물 이름에 반응하기' },
          { id: 'SU6.4', label: '익숙한 일과에서 자주 사용되는 2~3개의 구절에 반응하기' },
        ],
      },
    ],
  },

  // 정서 조절 - 상호조절 (MR) /38
  mutualReg: {
    label: '상호조절 (Mutual Regulation)',
    code: 'MR',
    maxScore: 38,
    groups: [
      {
        title: '1. 다양한 정서 표현하기',
        items: [
          { id: 'MR1.1', label: '기쁨 표현하기' },
          { id: 'MR1.2', label: '슬픔 표현하기' },
          { id: 'MR1.3', label: '분노 표현하기' },
          { id: 'MR1.4', label: '두려움 표현하기' },
        ],
      },
      {
        title: '2. 파트너가 제공하는 지원에 반응하기',
        items: [
          { id: 'MR2.1', label: '파트너의 위로에 진정하기' },
          { id: 'MR2.2', label: '파트너가 주의를 환기시킬 때 참여하기' },
          { id: 'MR2.3', label: '상호작용 시도에 반응하기' },
          { id: 'MR2.4', label: '파트너의 정서 표현 변화에 반응하기' },
          { id: 'MR2.5', label: '파트너의 정서 표현 변화에 동조하기' },
          { id: 'MR2.6', label: '파트너의 제안에 따라 선택하기' },
        ],
      },
      {
        title: '3. 상태를 조절하기 위해 파트너에게 도움 청하기',
        items: [
          { id: 'MR3.1', label: '위로를 구하기 위해 부정적인 정서 공유하기' },
          { id: 'MR3.2', label: '상호작용을 하기 위해 긍정적인 정서 공유하기' },
          { id: 'MR3.3', label: '좌절했을 때 도움 청하기' },
          { id: 'MR3.4', label: '괴로울 때 거부하기' },
        ],
      },
      {
        title: '4. 파트너의 지원을 받아 극심한 조절장애로부터 회복하기',
        items: [
          { id: 'MR4.1', label: '활동으로부터 떨어져 있게 하는 회복 노력에 반응하기' },
          { id: 'MR4.2', label: '파트너의 행동 전략 사용에 반응하기' },
          { id: 'MR4.3', label: '상호작용/활동에 다시 참여하게 하는 파트너 시도에 반응하기' },
          { id: 'MR4.4', label: '파트너 지원으로 극심한 조절장애로부터 회복되는 시간 단축하기' },
          { id: 'MR4.5', label: '파트너 지원으로 극심한 조절장애 상태의 강도 줄이기' },
        ],
      },
    ],
  },

  // 자기조절 (SR) /40
  selfReg: {
    label: '자기조절 (Self-Regulation)',
    code: 'SR',
    maxScore: 40,
    groups: [
      {
        title: '1. 학습 또는 상호작용의 가능성 보이기',
        items: [
          { id: 'SR1.1', label: '환경 내 사람과 사물 인식하기' },
          { id: 'SR1.2', label: '다양한 감각 및 사회적 경험에 흥미 보이기' },
          { id: 'SR1.3', label: '다양한 감각 체험을 추구하고 참아내기' },
          { id: 'SR1.4', label: '상호작용 시도 시작하기' },
          { id: 'SR1.5', label: '간단한 상호적 상호작용에 참여하기' },
          { id: 'SR1.6', label: '확장된 상호적 상호작용에 참여하기' },
          { id: 'SR1.7', label: '차별화된 정서로 감각 및 사회적 경험에 반응하기' },
        ],
      },
      {
        title: '2. 익숙한 활동 중 각성 수준을 조절하기 위해 행동 전략 사용하기',
        items: [
          { id: 'SR2.1', label: '혼자 하는 활동 중 행동 전략 사용하기' },
          { id: 'SR2.2', label: '사회적 상호작용 중 행동 전략 사용하기' },
          { id: 'SR2.3', label: '파트너가 시범 보인 행동 전략 사용하기' },
          { id: 'SR2.4', label: '장시간 활동에 생산적으로 참여하기 위해 행동 전략 사용하기' },
        ],
      },
      {
        title: '3. 새롭고 변화하는 상황에서 정서 조절하기',
        items: [
          { id: 'SR3.1', label: '익숙한 일과에서 다른 사람의 행동 예상하기' },
          { id: 'SR3.2', label: '새롭고 변화하는 상황에 참여하기' },
          { id: 'SR3.3', label: '새롭고 변화하는 상황에서 행동 전략 사용하기' },
          { id: 'SR3.4', label: '전이 중 행동 전략 사용하기' },
        ],
      },
      {
        title: '4. 극심한 조절장애로부터 스스로 회복하기',
        items: [
          { id: 'SR4.1', label: '지나치게 자극적/원하지 않는 활동으로부터 스스로 떠나기' },
          { id: 'SR4.2', label: '극심한 조절장애로부터 회복하기 위해 행동 전략 사용하기' },
          { id: 'SR4.3', label: '극심한 조절장애 회복 후 상호작용/활동에 다시 참여하기' },
          { id: 'SR4.4', label: '극심한 조절장애로부터 회복되는 시간 단축하기' },
          { id: 'SR4.5', label: '조절장애 상태의 강도 줄이기' },
        ],
      },
    ],
  },

  // 교류 지원 - 대인관계 지원 (IS) /66
  interpersonalSupport: {
    label: '대인관계 지원 (Interpersonal Support)',
    code: 'IS',
    maxScore: 66,
    groups: [
      {
        title: '1. 파트너는 아동에게 반응적이다.',
        items: [
          { id: 'IS1.1', label: '아동의 관심 초점 따르기' },
          { id: 'IS1.2', label: '아동의 정서 및 속도에 맞추기' },
          { id: 'IS1.3', label: '의사소통 효능감 증진을 위해 아동 신호에 적절하게 반응하기' },
          { id: 'IS1.4', label: '각성 수준 조절을 위한 아동의 행동 전략 인식/지원하기' },
          { id: 'IS1.5', label: '조절장애 신호 인식하고 지원하기' },
          { id: 'IS1.6', label: '아동을 모방하기' },
          { id: 'IS1.7', label: '필요할 때 상호작용/활동으로부터 휴식 제공하기' },
          { id: 'IS1.8', label: '휴식 후 상호작용/활동에 다시 참여하도록 촉진하기' },
        ],
      },
      {
        title: '2. 파트너는 시작행동을 촉진한다.',
        items: [
          { id: 'IS2.1', label: '비구어/구어로 선택의 기회 제공하기' },
          { id: 'IS2.2', label: '시작행동 기다리고 격려하기' },
          { id: 'IS2.3', label: '시작행동과 반응행동의 균형 유지하기' },
          { id: 'IS2.4', label: '아동이 활동을 시작하고 마치도록 해 주기' },
        ],
      },
      {
        title: '3. 파트너는 아동의 독립성을 존중한다.',
        items: [
          { id: 'IS3.1', label: '필요시 활동 중간에 돌아다닐 수 있도록 휴식 허락하기' },
          { id: 'IS3.2', label: '자신의 속도로 문제 해결/활동 완수할 시간 허용하기' },
          { id: 'IS3.3', label: '문제행동을 의사소통/조절 기능으로 이해하기' },
          { id: 'IS3.4', label: '적절한 경우 저항/거부/거절 존중하기' },
        ],
      },
      {
        title: '4. 파트너는 참여를 위한 장을 마련한다.',
        items: [
          { id: 'IS4.1', label: '의사소통할 때 아동 눈높이에 맞추기' },
          { id: 'IS4.2', label: '의사소통 전에 아동 주의 확보하기' },
          { id: 'IS4.3', label: '상호작용 촉진을 위해 적절한 근접성/비구어 행동 사용하기' },
          { id: 'IS4.4', label: '최적 각성 상태/참여 지원을 위해 적절한 단어/억양 사용하기' },
        ],
      },
      {
        title: '5. 파트너는 발달을 지원한다.',
        items: [
          { id: 'IS5.1', label: '모방 격려하기' },
          { id: 'IS5.2', label: '또래와의 상호작용 격려하기' },
          { id: 'IS5.3', label: '구어/비구어로 의사소통 실패 복구 시도하기' },
          { id: 'IS5.4', label: '활동 성공을 위해 필요시 안내/피드백 제공하기' },
          { id: 'IS5.5', label: '아동의 놀이와 비구어 의사소통 확장하기' },
        ],
      },
      {
        title: '6. 파트너는 언어 사용을 조절한다.',
        items: [
          { id: 'IS6.1', label: '이해를 돕기 위해 비구어 단서 사용하기' },
          { id: 'IS6.2', label: '아동의 발달 수준에 따라 언어 복잡성 조절하기' },
          { id: 'IS6.3', label: '아동의 각성 수준에 따라 언어의 질 조절하기' },
        ],
      },
      {
        title: '7. 파트너는 적절한 행동을 시범 보인다.',
        items: [
          { id: 'IS7.1', label: '적절한 비구어 의사소통/정서 표현 시범 보이기' },
          { id: 'IS7.2', label: '다양한 의사소통 기능 시범 보이기' },
          { id: 'IS7.3', label: '적절한 놀이 시범 보이기' },
          { id: 'IS7.4', label: '부적절한 행동을 할 때 적절한 행동 시범 보이기' },
          { id: 'IS7.5', label: "'아동 입장'에서 언어 시범 보이기" },
        ],
      },
    ],
  },

  // 학습 지원 (LS) /50
  learningSupport: {
    label: '학습 지원 (Learning Support)',
    code: 'LS',
    maxScore: 50,
    groups: [
      {
        title: '1. 파트너는 적극적인 참여를 위해 활동을 구조화한다.',
        items: [
          { id: 'LS1.1', label: '활동의 시작과 종료를 분명하게 정하기' },
          { id: 'LS1.2', label: '차례 주고받기 기회를 만들고 참여 여지 남겨 두기' },
          { id: 'LS1.3', label: '활동에 예측 가능한 순서 마련하기' },
          { id: 'LS1.4', label: '반복되는 학습 기회 제공하기' },
          { id: 'LS1.5', label: '다양한 학습 기회 제공하기' },
        ],
      },
      {
        title: '2. 파트너는 발달 촉진을 위해 보완의사소통 지원을 사용한다.',
        items: [
          { id: 'LS2.1', label: '의사소통/표현언어 강화를 위해 보완의사소통 지원 사용하기' },
          { id: 'LS2.2', label: '언어/행동 이해 강화를 위해 보완의사소통 지원 사용하기' },
          { id: 'LS2.3', label: '정서 표현/이해 능력 강화를 위해 보완의사소통 지원 사용하기' },
          { id: 'LS2.4', label: '정서 조절 강화를 위해 보완의사소통 지원 사용하기' },
        ],
      },
      {
        title: '3. 파트너는 시각적 지원 및 조직화 지원을 사용한다.',
        items: [
          { id: 'LS3.1', label: '과제 수행 단계를 명확히 하기 위해 지원 사용하기' },
          { id: 'LS3.2', label: '활동 완수에 필요한 시간/단계 명확화를 위해 지원 사용하기' },
          { id: 'LS3.3', label: '활동 간 원활한 전이를 위해 시각적 지원 사용하기' },
          { id: 'LS3.4', label: '하루 시간 분할 조직화를 위해 지원 사용하기' },
          { id: 'LS3.5', label: '집단 활동에서 주의집중 증진을 위해 시각적 지원 사용하기' },
          { id: 'LS3.6', label: '집단 활동에서 적극적인 참여 촉진을 위해 시각적 지원 사용하기' },
        ],
      },
      {
        title: '4. 파트너는 목표, 활동, 학습 환경을 수정한다.',
        items: [
          { id: 'LS4.1', label: '조직화/상호작용 지원을 위해 사회적 복잡성 조절하기' },
          { id: 'LS4.2', label: '아동의 성공을 위해 과제 난이도 조절하기' },
          { id: 'LS4.3', label: '학습 환경의 감각적 속성 수정하기' },
          { id: 'LS4.4', label: '주의집중을 높일 수 있도록 학습 환경 구성하기' },
          { id: 'LS4.5', label: '시작행동을 촉진하는 학습 환경 구성하기' },
          { id: 'LS4.6', label: '활동이 발달적으로 적절하도록 고안하고 수정하기' },
          { id: 'LS4.7', label: '활동 내 동기유발 가능한 교재/주제 포함시키기' },
          { id: 'LS4.8', label: '시작행동/확장된 상호작용 촉진 활동 제공하기' },
          { id: 'LS4.9', label: '필요에 따라 동적/정적 활동 교대하기' },
          { id: 'LS4.10', label: "'요구의 정도를 높이거나' 기대감을 적절하게 높이기" },
        ],
      },
    ],
  },
};

// =====================================================================
// 언어 파트너 단계 (LP) - 항목 다수, 핵심만 우선 수록
// =====================================================================
const LANGUAGE_PARTNER = {
  joinAttention: {
    label: '공동관심 (Joint Attention)',
    code: 'JA',
    maxScore: 62,
    groups: [
      {
        title: '1. 상호적 상호작용에 참여하기',
        items: [
          { id: 'JA1.1', label: '상호작용 시도 시작하기' },
          { id: 'JA1.2', label: '간단한 상호적 상호작용에 참여하기' },
          { id: 'JA1.3', label: '확장된 상호적 상호작용에 참여하기' },
        ],
      },
      {
        title: '2. 관심 공유하기',
        items: [
          { id: 'JA2.1', label: '사람과 사물 간에 시선 옮기기' },
          { id: 'JA2.2', label: '짚어서/멀리 가리킬 때 쳐다보기' },
          { id: 'JA2.3', label: '사회적 파트너의 관심 초점 따르기' },
          { id: 'JA2.4', label: '의도 표현 전 자신에게로 주의 끌기' },
        ],
      },
      {
        title: '3. 정서 공유하기',
        items: [
          { id: 'JA3.1', label: '부정적/긍정적 정서 공유하기' },
          { id: 'JA3.2', label: '다양한 정서 표현을 위해 상징 이해/사용하기' },
          { id: 'JA3.3', label: '파트너의 정서 표현 변화에 동조하기' },
          { id: 'JA3.4', label: '다른 사람의 정서 상태 설명하기' },
        ],
      },
      {
        title: '4. 다른 사람의 행동을 조절하기 위해 의도 공유하기',
        items: [
          { id: 'JA4.1', label: '원하는 음식이나 사물 요구하기' },
          { id: 'JA4.2', label: '원하지 않는 음식이나 사물 거부/거절하기' },
          { id: 'JA4.3', label: '도움 또는 기타 행동 요구하기' },
          { id: 'JA4.4', label: '원하지 않는 행동이나 활동 거부하기' },
        ],
      },
      {
        title: '5. 사회적 상호작용을 위해 의도 공유하기',
        items: [
          { id: 'JA5.1', label: '위로 구하기' },
          { id: 'JA5.2', label: '사회적 게임 요구하기' },
          { id: 'JA5.3', label: '차례 주고받기' },
          { id: 'JA5.4', label: '인사하기' },
          { id: 'JA5.5', label: '부르기' },
          { id: 'JA5.6', label: '자랑하기' },
          { id: 'JA5.7', label: '허락 구하기' },
        ],
      },
      {
        title: '6. 공동관심을 위해 의도 공유하기',
        items: [
          { id: 'JA6.1', label: '사물에 대해 언급하기' },
          { id: 'JA6.2', label: '행동/사건에 대해 언급하기' },
          { id: 'JA6.3', label: '관심 있는 것에 대해 정보 요구하기' },
        ],
      },
      {
        title: '7. 의사소통 실패를 복구하고 지속하기',
        items: [
          { id: 'JA7.1', label: '맥락에 적절한 비율로 의사소통하기' },
          { id: 'JA7.2', label: '의사소통 실패 복구를 위해 반복/수정하기' },
          { id: 'JA7.3', label: '의사소통 실패 인식하기' },
        ],
      },
      {
        title: '8. 상호적 상호작용에서 경험 공유하기',
        items: [
          { id: 'JA8.1', label: '경험 공유를 위해 관심/정서/의도 조절하기' },
          { id: 'JA8.2', label: '경험 공유 위해 청자/화자 역할 바꾸며 상호작용하기' },
          { id: 'JA8.3', label: '친구와 상호작용 시작하고 경험 공유하기' },
        ],
      },
    ],
  },

  symbolUse: {
    label: '상징 사용 (Symbol Use)',
    code: 'SU',
    maxScore: 50,
    groups: [
      {
        title: '1. 익숙하거나 익숙하지 않은 행동/단어를 관찰/모방하여 학습하기',
        items: [
          { id: 'SU1.1', label: '시범 후 즉시 자발적으로 익숙한 행동/단어 모방하기' },
          { id: 'SU1.2', label: '시범 후 즉시 자발적으로 익숙하지 않은 행동/단어 모방하기' },
          { id: 'SU1.3', label: '동작/단어를 자발적으로 모방하고 다른 행동을 더하기' },
          { id: 'SU1.4', label: '시간 경과 후 다른 맥락에서 다양한 행동을 자발적으로 모방하기' },
        ],
      },
      {
        title: '2. 익숙/익숙하지 않은 활동에서 비구어 단서 이해하기',
        items: [
          { id: 'SU2.1', label: '익숙/익숙하지 않은 활동에서 상황 및 몸짓 단서 따르기' },
          { id: 'SU2.2', label: '짚어서/멀리 가리킬 때 쳐다보기' },
          { id: 'SU2.3', label: '시각적 단서(사진/그림)를 동반한 지시 따르기' },
          { id: 'SU2.4', label: '얼굴 표정과 억양 단서에 반응하기' },
        ],
      },
      {
        title: '3. 놀이 중 익숙한 사물을 관습적인 방식으로 사용하기',
        items: [
          { id: 'SU3.1', label: '구성놀이에서 다양한 사물 사용하기' },
          { id: 'SU3.2', label: '여러 익숙한 사물을 관습적으로 자신에게 사용하기' },
          { id: 'SU3.3', label: '여러 익숙한 사물을 관습적으로 다른 사람에게 사용하기' },
          { id: 'SU3.4', label: '놀이 중 사물을 사용하여 다양한 행동 조합하기' },
        ],
      },
      {
        title: '4. 의도 공유를 위해 몸짓/비구어 수단 사용하기',
        items: [
          { id: 'SU4.1', label: '다양한 관습적/상징적 몸짓 사용하기' },
          { id: 'SU4.2', label: '일련의 몸짓/비구어 수단을 시선과 함께 사용하기' },
        ],
      },
      {
        title: '5. 의미 표현을 위해 단어와 단어 조합 사용하기',
        items: [
          { id: 'SU5.1', label: '소리/단어를 시선/몸짓과 함께 조합하여 사용하기' },
          { id: 'SU5.2', label: '상징으로 5~10개의 단어/반향어 구 사용하기' },
          { id: 'SU5.3', label: '초기 관계어 사용하기' },
          { id: 'SU5.4', label: '사물/신체부위/행위자에 대해 다양한 이름 사용하기' },
          { id: 'SU5.5', label: '상위 수준의 관계어를 다양하게 사용하기' },
          { id: 'SU5.6', label: '단어조합에서 다양한 관계 의미 사용하기' },
        ],
      },
      {
        title: '6. 맥락적 단서 없이 다양한 단어와 단어 조합 이해하기',
        items: [
          { id: 'SU6.1', label: '자신의 이름에 반응하기' },
          { id: 'SU6.2', label: '여러 익숙한 단어/구절에 반응하기' },
          { id: 'SU6.3', label: '맥락적 단서 없이 다양한 이름 이해하기' },
          { id: 'SU6.4', label: '맥락적 단서 없이 다양한 관계어 이해하기' },
          { id: 'SU6.5', label: '맥락적 단서 없이 단어 조합에서 다양한 관계 의미 이해하기' },
        ],
      },
    ],
  },

  mutualReg: {
    label: '상호조절 (Mutual Regulation)',
    code: 'MR',
    maxScore: 46,
    groups: [
      {
        title: '1. 다양한 정서 표현하기',
        items: [
          { id: 'MR1.1', label: '부정적/긍정적 정서 공유하기' },
          { id: 'MR1.2', label: '다양한 정서 표현을 위해 상징 이해/사용하기' },
          { id: 'MR1.3', label: '익숙한 활동에서 파트너 피드백에 따라 정서 표현 바꾸기' },
        ],
      },
      {
        title: '2. 파트너가 제공하는 지원에 반응하기',
        items: [
          { id: 'MR2.1', label: '파트너의 위로에 진정하기' },
          { id: 'MR2.2', label: '파트너가 주의를 환기시킬 때 참여하기' },
          { id: 'MR2.3', label: '상호작용 시도에 반응하기' },
          { id: 'MR2.4', label: '파트너의 정서 표현 변화에 반응하기' },
          { id: 'MR2.5', label: '파트너의 정서 표현 변화에 동조하기' },
          { id: 'MR2.6', label: '파트너의 제안에 따라 선택하기' },
          { id: 'MR2.7', label: '익숙한 활동에서 파트너 피드백에 따라 조절 전략 바꾸기' },
        ],
      },
      {
        title: '3. 상태를 조절하기 위해 파트너에게 도움 청하기',
        items: [
          { id: 'MR3.1', label: '위로를 구하기 위해 부정적인 정서 공유하기' },
          { id: 'MR3.2', label: '상호작용을 위해 긍정적인 정서 공유하기' },
          { id: 'MR3.3', label: '좌절했을 때 도움 청하기' },
          { id: 'MR3.4', label: '괴로울 때 거부하기' },
          { id: 'MR3.5', label: '휴식 요구를 위해 언어 전략 사용하기' },
          { id: 'MR3.6', label: '활동/자극 조절을 요구하기 위해 언어 전략 사용하기' },
          { id: 'MR3.7', label: '사회적 조절 수행을 위해 언어 전략 사용하기' },
        ],
      },
      {
        title: '4. 파트너의 지원을 받아 극심한 조절장애로부터 회복하기',
        items: [
          { id: 'MR4.1', label: '활동으로부터 떨어져 있게 하는 회복 노력에 반응하기' },
          { id: 'MR4.2', label: '파트너의 행동 전략 사용에 반응하기' },
          { id: 'MR4.3', label: '파트너의 언어 전략 사용에 반응하기' },
          { id: 'MR4.4', label: '상호작용/활동에 다시 참여하게 하는 파트너 시도에 반응하기' },
          { id: 'MR4.5', label: '파트너 지원으로 회복 시간 단축하기' },
          { id: 'MR4.6', label: '파트너 지원으로 조절장애 상태의 강도 줄이기' },
        ],
      },
    ],
  },

  selfReg: {
    label: '자기조절 (Self-Regulation)',
    code: 'SR',
    maxScore: 56,
    groups: [
      {
        title: '1. 학습 또는 상호작용의 가능성 보이기',
        items: [
          { id: 'SR1.1', label: '상호작용 시도 시작하기' },
          { id: 'SR1.2', label: '간단한 상호적 상호작용에 참여하기' },
          { id: 'SR1.3', label: '확장된 상호적 상호작용에 참여하기' },
          { id: 'SR1.4', label: '차별화된 정서로 감각/사회적 경험에 반응하기' },
          { id: 'SR1.5', label: '행위 및 행동 억제 능력 보이기' },
          { id: 'SR1.6', label: '여러 익숙한 단어/구절에 반응하기' },
          { id: 'SR1.7', label: '합리적인 요구를 지닌 과제 지속하기' },
          { id: 'SR1.8', label: '맥락에 적절하게 정서 표현하기' },
        ],
      },
      {
        title: '2. 익숙한 활동 중 행동 전략 사용하기',
        items: [
          { id: 'SR2.1', label: '혼자 하는/사회적 활동 중 행동 전략 사용하기' },
          { id: 'SR2.2', label: '파트너가 시범 보인 행동 전략 사용하기' },
          { id: 'SR2.3', label: '장시간 활동에 생산적으로 참여하기 위해 행동 전략 사용하기' },
        ],
      },
      {
        title: '3. 익숙한 활동 중 언어 전략 사용하기',
        items: [
          { id: 'SR3.1', label: '혼자 하는 활동 중 언어 전략 사용하기' },
          { id: 'SR3.2', label: '사회적 상호작용 중 언어 전략 사용하기' },
          { id: 'SR3.3', label: '파트너가 시범 보인 언어 전략 사용하기' },
          { id: 'SR3.4', label: '장시간 활동에 생산적으로 참여하기 위해 언어 전략 사용하기' },
          { id: 'SR3.5', label: '다양한 정서 표현을 위해 상징 사용하기' },
        ],
      },
      {
        title: '4. 새롭고 변화하는 상황에서 정서 조절하기',
        items: [
          { id: 'SR4.1', label: '새롭고 변화하는 상황에 참여하기' },
          { id: 'SR4.2', label: '익숙하지 않은 활동에서 상황/몸짓 단서 따르기' },
          { id: 'SR4.3', label: '새/변화 상황에서 행동 전략 사용하기' },
          { id: 'SR4.4', label: '새/변화 상황에서 언어 전략 사용하기' },
          { id: 'SR4.5', label: '전이 중 행동 전략 사용하기' },
          { id: 'SR4.6', label: '전이 중 언어 전략 사용하기' },
        ],
      },
      {
        title: '5. 극심한 조절장애로부터 스스로 회복하기',
        items: [
          { id: 'SR5.1', label: '지나친 자극/원치 않는 활동으로부터 스스로 떠나기' },
          { id: 'SR5.2', label: '회복을 위해 행동 전략 사용하기' },
          { id: 'SR5.3', label: '회복을 위해 언어 전략 사용하기' },
          { id: 'SR5.4', label: '회복 후 상호작용/활동에 다시 참여하기' },
          { id: 'SR5.5', label: '회복 시간 단축하기' },
          { id: 'SR5.6', label: '조절장애 상태의 강도 줄이기' },
        ],
      },
    ],
  },

  interpersonalSupport: {
    label: '대인관계 지원 (Interpersonal Support)',
    code: 'IS',
    maxScore: 66,
    groups: [
      {
        title: '1. 파트너는 아동에게 반응적이다.',
        items: [
          { id: 'IS1.1', label: '아동의 관심 초점 따르기' },
          { id: 'IS1.2', label: '아동의 정서 및 속도에 맞추기' },
          { id: 'IS1.3', label: '의사소통 효능감 증진을 위해 아동 신호에 적절하게 반응하기' },
          { id: 'IS1.4', label: '아동의 행동/언어 전략 인식/지원하기' },
          { id: 'IS1.5', label: '조절장애 신호 인식/지원하기' },
          { id: 'IS1.6', label: '아동을 모방하기' },
          { id: 'IS1.7', label: '필요할 때 휴식 제공하기' },
          { id: 'IS1.8', label: '휴식 후 다시 참여하도록 촉진하기' },
        ],
      },
      {
        title: '2. 파트너는 시작행동을 촉진한다.',
        items: [
          { id: 'IS2.1', label: '비구어/구어로 선택의 기회 제공하기' },
          { id: 'IS2.2', label: '시작행동 기다리고 격려하기' },
          { id: 'IS2.3', label: '시작/반응 행동의 균형 유지하기' },
          { id: 'IS2.4', label: '아동이 활동을 시작/마치도록 해 주기' },
        ],
      },
      {
        title: '3. 파트너는 아동의 독립성을 존중한다.',
        items: [
          { id: 'IS3.1', label: '필요시 활동 중간 휴식 허락하기' },
          { id: 'IS3.2', label: '자신의 속도로 문제 해결/활동 완수 시간 허용하기' },
          { id: 'IS3.3', label: '문제행동을 의사소통/조절 기능으로 이해하기' },
          { id: 'IS3.4', label: '적절한 경우 저항/거부/거절 존중하기' },
        ],
      },
      {
        title: '4. 파트너는 참여를 위한 장을 마련한다.',
        items: [
          { id: 'IS4.1', label: '아동 눈높이에 맞추기' },
          { id: 'IS4.2', label: '의사소통 전에 아동 주의 확보하기' },
          { id: 'IS4.3', label: '적절한 근접성/비구어 행동 사용하기' },
          { id: 'IS4.4', label: '적절한 단어/억양 사용하기' },
        ],
      },
      {
        title: '5. 파트너는 발달을 지원한다.',
        items: [
          { id: 'IS5.1', label: '모방 격려하기' },
          { id: 'IS5.2', label: '또래와의 상호작용 격려하기' },
          { id: 'IS5.3', label: '구어/비구어로 의사소통 실패 복구 시도하기' },
          { id: 'IS5.4', label: '활동 성공을 위해 안내/피드백 제공하기' },
          { id: 'IS5.5', label: '정서 표현/원인 이해 안내하기' },
        ],
      },
      {
        title: '6. 파트너는 언어 사용을 조절한다.',
        items: [
          { id: 'IS6.1', label: '이해를 돕기 위해 비구어 단서 사용하기' },
          { id: 'IS6.2', label: '아동 발달 수준에 따라 언어 복잡성 조절하기' },
          { id: 'IS6.3', label: '아동 각성 수준에 따라 언어의 질 조절하기' },
        ],
      },
      {
        title: '7. 파트너는 적절한 행동을 시범 보인다.',
        items: [
          { id: 'IS7.1', label: '적절한 비구어 의사소통/정서 표현 시범 보이기' },
          { id: 'IS7.2', label: '다양한 의사소통 기능 시범 보이기' },
          { id: 'IS7.3', label: '적절한 구성놀이/상징놀이 시범 보이기' },
          { id: 'IS7.4', label: '부적절한 행동시 적절한 행동 시범 보이기' },
          { id: 'IS7.5', label: "'아동 입장'에서 언어 시범 보이기" },
        ],
      },
    ],
  },

  learningSupport: {
    label: '학습 지원 (Learning Support)',
    code: 'LS',
    maxScore: 50,
    groups: [
      {
        title: '1. 파트너는 적극적인 참여를 위해 활동을 구조화한다.',
        items: [
          { id: 'LS1.1', label: '활동의 시작/종료를 분명하게 정하기' },
          { id: 'LS1.2', label: '차례 주고받기 기회 만들고 참여 여지 남겨 두기' },
          { id: 'LS1.3', label: '예측 가능한 순서 마련하기' },
          { id: 'LS1.4', label: '반복되는 학습 기회 제공하기' },
          { id: 'LS1.5', label: '다양한 학습 기회 제공하기' },
        ],
      },
      {
        title: '2. 파트너는 발달 촉진을 위해 보완의사소통 지원을 사용한다.',
        items: [
          { id: 'LS2.1', label: '의사소통/표현언어 강화' },
          { id: 'LS2.2', label: '언어/행동 이해 강화' },
          { id: 'LS2.3', label: '정서 표현/이해 능력 강화' },
          { id: 'LS2.4', label: '정서 조절 강화' },
        ],
      },
      {
        title: '3. 파트너는 시각적 지원/조직화 지원을 사용한다.',
        items: [
          { id: 'LS3.1', label: '과제 수행 단계 명확화' },
          { id: 'LS3.2', label: '활동 완수 시간/단계 명확화' },
          { id: 'LS3.3', label: '활동 간 원활한 전이' },
          { id: 'LS3.4', label: '하루 시간 분할 조직화' },
          { id: 'LS3.5', label: '집단 활동 주의집중 증진' },
          { id: 'LS3.6', label: '집단 활동 적극적 참여 촉진' },
        ],
      },
      {
        title: '4. 파트너는 목표, 활동, 학습 환경을 수정한다.',
        items: [
          { id: 'LS4.1', label: '사회적 복잡성 조절' },
          { id: 'LS4.2', label: '과제 난이도 조절' },
          { id: 'LS4.3', label: '학습 환경 감각적 속성 수정' },
          { id: 'LS4.4', label: '주의집중 환경 구성' },
          { id: 'LS4.5', label: '시작행동 촉진 환경 구성' },
          { id: 'LS4.6', label: '발달적으로 적절하도록 활동 고안/수정' },
          { id: 'LS4.7', label: '동기유발 교재/주제 포함' },
          { id: 'LS4.8', label: '시작행동/확장 상호작용 촉진 활동 제공' },
          { id: 'LS4.9', label: '동적/정적 활동 교대' },
          { id: 'LS4.10', label: "'요구의 정도 높이거나' 기대감 적절히 높이기" },
        ],
      },
    ],
  },
};

// =====================================================================
// 대화 파트너 단계 (CP)
// =====================================================================
const CONVERSATION_PARTNER = {
  joinAttention: {
    label: '공동관심 (Joint Attention)',
    code: 'JA',
    maxScore: 58,
    groups: [
      {
        title: '1. 관심 공유하기',
        items: [
          { id: 'JA1.1', label: '사회적 파트너의 관심 초점 따르기' },
          { id: 'JA1.2', label: '의도 표현 전 자신에게로 주의 끌기' },
          { id: 'JA1.3', label: '관심 초점 변화에 대한 비구어 단서 이해하기' },
          { id: 'JA1.4', label: '파트너가 보거나 들은 것을 기초로 언어 수정하기' },
          { id: 'JA1.5', label: '파트너와 내적 사고/정신적 계획 공유하기' },
        ],
      },
      {
        title: '2. 정서 공유하기',
        items: [
          { id: 'JA2.1', label: '초기 정서 단어 이해/사용하기' },
          { id: 'JA2.2', label: '다른 사람의 정서 상태를 초기 정서 단어로 묘사하기' },
          { id: 'JA2.3', label: '상위 수준 정서 단어 이해/사용하기' },
          { id: 'JA2.4', label: '다른 사람의 정서 상태를 상위 수준 정서 단어로 묘사하기' },
          { id: 'JA2.5', label: '단계적인 정서 이해/사용하기' },
          { id: 'JA2.6', label: '정서를 표현하는 비구어 단서 이해하기' },
          { id: 'JA2.7', label: '자신/타인의 정서에 대한 타당한 원인 요소 설명하기' },
        ],
      },
      {
        title: '3. 다양한 목적을 위해 의도 공유하기',
        items: [
          { id: 'JA3.1', label: '다른 사람의 행동을 조절하기 위해 의도 공유하기' },
          { id: 'JA3.2', label: '사회적 상호작용을 위해 의도 공유하기' },
          { id: 'JA3.3', label: '공동관심을 위해 의도 공유하기' },
        ],
      },
      {
        title: '4. 상호적 상호작용에서 경험 공유하기',
        items: [
          { id: 'JA4.1', label: '청자/화자 역할 바꾸며 상호작용하기' },
          { id: 'JA4.2', label: '다양한 대화 주제 시작하기' },
          { id: 'JA4.3', label: '파트너 관심에 맞게 대화 시작/유지하기' },
          { id: 'JA4.4', label: '관련 정보 요구/제공하여 상호작용 유지하기' },
          { id: 'JA4.5', label: '파트너의 지식 기초로 필요한 정보 제공하기' },
          { id: 'JA4.6', label: '파트너에 따라 대화 차례 길이/내용 판단하기' },
          { id: 'JA4.7', label: '파트너와 함께하기를 선호하기' },
          { id: 'JA4.8', label: '관심을 공유하는 파트너와 우정 맺기' },
        ],
      },
      {
        title: '5. 의사소통 실패를 복구하고 지속하기',
        items: [
          { id: 'JA5.1', label: '맥락에 적절한 비율로 의사소통하기' },
          { id: 'JA5.2', label: '의사소통 실패 복구를 위해 반복/수정하기' },
          { id: 'JA5.3', label: '의사소통 실패 인식하고 명료화 요구하기' },
          { id: 'JA5.4', label: '파트너 의견 변화에 따라 언어/행동 수정하기' },
          { id: 'JA5.5', label: '파트너 정서 반응에 따라 언어/행동 수정하기' },
          { id: 'JA5.6', label: '상호작용 중 성취감/자신감 표현하기' },
        ],
      },
    ],
  },

  symbolUse: {
    label: '상징 사용 (Symbol Use)',
    code: 'SU',
    maxScore: 58,
    groups: [
      {
        title: '1. 모방, 관찰, 교수, 협력을 통해 학습하기',
        items: [
          { id: 'SU1.1', label: '시간 경과 후 다른 맥락에서 다양한 행동을 자발적으로 모방하기' },
          { id: 'SU1.2', label: '사회적 행동 안내 위해 파트너가 시범 보인 행동 사용하기' },
          { id: 'SU1.3', label: '성인이 시범 보인 내재화된 규칙 사용하기' },
          { id: 'SU1.4', label: '행동 안내를 위해 자기점검/혼잣말 사용하기' },
          { id: 'SU1.5', label: '문제 해결시 또래와 협력하고 타협하기' },
        ],
      },
      {
        title: '2. 상호적 상호작용에서 비구어 단서/비문자적 의미 이해하기',
        items: [
          { id: 'SU2.1', label: '차례 주고받기/주제 변화에 대한 비구어 단서 이해하기' },
          { id: 'SU2.2', label: '정서를 표현하는 비구어 단서 이해하기' },
          { id: 'SU2.3', label: '유머/비유 표현의 비구어 단서/비문자적 의미 이해하기' },
          { id: 'SU2.4', label: '놀림/비꼬는 말/속임수의 비구어 단서/비문자적 의미 이해하기' },
        ],
      },
      {
        title: '3. 극놀이와 여가활동에 관습적인 방식으로 참여하기',
        items: [
          { id: 'SU3.1', label: '익숙한 사건 놀이에서 행동의 논리적 순서 사용하기' },
          { id: 'SU3.2', label: '모형/추상적 사물을 소품으로 사용하기' },
          { id: 'SU3.3', label: '덜 익숙한 사건 놀이에서 논리적 순서 사용하기' },
          { id: 'SU3.4', label: '극놀이에서 역할을 맡아 참여하기' },
          { id: 'SU3.5', label: '다른 아동과 공동 놀이 활동에 참여하기' },
          { id: 'SU3.6', label: '극놀이에서 역할 맡아 또래와 협력하기' },
          { id: 'SU3.7', label: '규칙이 있는 집단 놀이 활동에 참여하기' },
        ],
      },
      {
        title: '4. 맥락에 적절한 몸짓/비구어 행동 사용하기',
        items: [
          { id: 'SU4.1', label: '맥락/파트너에 맞게 적절한 얼굴 표정 사용하기' },
          { id: 'SU4.2', label: '맥락/파트너에 맞게 적절한 몸짓 사용하기' },
          { id: 'SU4.3', label: '맥락/파트너에 맞게 적절한 자세/근접성 사용하기' },
          { id: 'SU4.4', label: '맥락/파트너에 맞게 목소리 크기/억양 사용하기' },
        ],
      },
      {
        title: '5. 의미 표현 위해 생성적 언어 이해/사용하기',
        items: [
          { id: 'SU5.1', label: '다양한 상위 수준 관계어 이해/사용하기' },
          { id: 'SU5.2', label: '어떤 것을 나타내는 지시어 이해/사용하기' },
          { id: 'SU5.3', label: '다양한 동사구 이해/사용하기' },
          { id: 'SU5.4', label: '다양한 문장 구조 이해/사용하기' },
          { id: 'SU5.5', label: '구어/쓰기 담화에서 연결된 문장 이해/사용하기' },
        ],
      },
      {
        title: '6. 대화 규칙 따르기',
        items: [
          { id: 'SU6.1', label: '관습에 따라 대화 시작/차례 주고받기' },
          { id: 'SU6.2', label: '관습에 따라 대화 주제 전환하기' },
          { id: 'SU6.3', label: '관습에 따라 대화 종료하기' },
          { id: 'SU6.4', label: '예의범절 관습 따르고 표현하기' },
        ],
      },
    ],
  },

  mutualReg: {
    label: '상호조절 (Mutual Regulation)',
    code: 'MR',
    maxScore: 56,
    groups: [
      {
        title: '1. 다양한 정서 표현하기',
        items: [
          { id: 'MR1.1', label: '초기 정서 단어 이해/사용하기' },
          { id: 'MR1.2', label: '상위 수준 정서 단어 이해/사용하기' },
          { id: 'MR1.3', label: '단계적인 정서 이해/사용하기' },
          { id: 'MR1.4', label: '파트너 피드백에 따라 정서 표현 바꾸기' },
          { id: 'MR1.5', label: '정서 표현하는 비구어 단서 사용하기' },
        ],
      },
      {
        title: '2. 파트너가 제공하는 지원에 반응하기',
        items: [
          { id: 'MR2.1', label: '파트너의 위로에 진정하기' },
          { id: 'MR2.2', label: '파트너가 주의를 환기시킬 때 참여하기' },
          { id: 'MR2.3', label: '상호작용 시도에 반응하기' },
          { id: 'MR2.4', label: '파트너의 정서 표현 변화에 반응하기' },
          { id: 'MR2.5', label: '파트너의 정서 표현 변화에 동조하기' },
          { id: 'MR2.6', label: '파트너가 제공한 정보/전략에 반응하기' },
        ],
      },
      {
        title: '3. 행동에 대한 피드백 및 안내에 반응하기',
        items: [
          { id: 'MR3.1', label: '정서 표현 적절성 피드백에 반응하기' },
          { id: 'MR3.2', label: '조절 전략 적절성 피드백에 반응하기' },
          { id: 'MR3.3', label: '파트너 시범 행동 사용하기' },
          { id: 'MR3.4', label: '문제 해결시 또래와 협력/타협하기' },
          { id: 'MR3.5', label: '합의점 도달 위해 타협 중 파트너 의견 수용하기' },
        ],
      },
      {
        title: '4. 상태를 조절하기 위해 파트너에게 도움 청하기',
        items: [
          { id: 'MR4.1', label: '위로 구하기 위해 부정적 정서 공유하기' },
          { id: 'MR4.2', label: '상호작용 위해 긍정적 정서 공유하기' },
          { id: 'MR4.3', label: '다른 사람의 행동 조절 위해 의도 공유하기' },
          { id: 'MR4.4', label: '사회적 상호작용 위해 의도 공유하기' },
          { id: 'MR4.5', label: '공동관심 위해 의도 공유하기' },
          { id: 'MR4.6', label: '갈등 및 문제 해결 상황에서 지원 요구하기' },
        ],
      },
      {
        title: '5. 파트너의 지원을 받아 극심한 조절장애로부터 회복하기',
        items: [
          { id: 'MR5.1', label: '활동으로부터 떨어져 있게 하는 회복 노력에 반응하기' },
          { id: 'MR5.2', label: '파트너의 행동 전략 사용에 반응하기' },
          { id: 'MR5.3', label: '파트너의 언어 전략 사용에 반응하기' },
          { id: 'MR5.4', label: '상호작용/활동 재참여 파트너 시도에 반응하기' },
          { id: 'MR5.5', label: '파트너 지원으로 회복 시간 단축하기' },
          { id: 'MR5.6', label: '파트너 지원으로 조절장애 강도 줄이기' },
        ],
      },
    ],
  },

  selfReg: {
    label: '자기조절 (Self-Regulation)',
    code: 'SR',
    maxScore: 64,
    groups: [
      {
        title: '1. 학습 또는 상호작용의 가능성 보이기',
        items: [
          { id: 'SR1.1', label: '차별화된 정서로 감각/사회적 경험에 반응하기' },
          { id: 'SR1.2', label: '사회적 파트너의 관심 초점 따르기' },
          { id: 'SR1.3', label: '청자/화자 역할 바꾸며 상호작용하기' },
          { id: 'SR1.4', label: '행위 및 행동 억제 능력 보이기' },
          { id: 'SR1.5', label: '합리적인 요구의 과제 지속하기' },
          { id: 'SR1.6', label: '맥락에 적절하게 정서 표현하기' },
        ],
      },
      {
        title: '2. 익숙한 활동 중 행동 전략 사용하기',
        items: [
          { id: 'SR2.1', label: '혼자 하는/사회적 활동 중 행동 전략 사용하기' },
          { id: 'SR2.2', label: '파트너가 시범 보인 행동 전략 사용하기' },
          { id: 'SR2.3', label: '장시간 활동 위해 행동 전략 사용하기' },
        ],
      },
      {
        title: '3. 익숙한 활동 중 언어 전략 사용하기',
        items: [
          { id: 'SR3.1', label: '초기 정서 단어 이해/사용하기' },
          { id: 'SR3.2', label: '상위 수준 정서 단어 이해/사용하기' },
          { id: 'SR3.3', label: '단계적인 정서 이해/사용하기' },
          { id: 'SR3.4', label: '혼자/사회적 활동 중 언어 전략 사용하기' },
          { id: 'SR3.5', label: '파트너가 시범 보인 언어 전략 사용하기' },
          { id: 'SR3.6', label: '장시간 활동 위해 언어 전략 사용하기' },
        ],
      },
      {
        title: '4. 익숙한 활동 중 초인지 전략 사용하기',
        items: [
          { id: 'SR4.1', label: '성인이 시범 보인 내재화된 규칙 사용하기' },
          { id: 'SR4.2', label: '활동 계획 달성 위해 초인지 전략 사용하기' },
          { id: 'SR4.3', label: '행동 안내 위해 자기점검/혼잣말 사용하기' },
          { id: 'SR4.4', label: '정서 조절 위해 정서 기억 사용하기' },
          { id: 'SR4.5', label: '조절 지원 전략 파악하고 반영하기' },
        ],
      },
      {
        title: '5. 새롭고 변화하는 상황에서 정서 조절하기',
        items: [
          { id: 'SR5.1', label: '새/변화 상황에서 행동 전략 사용하기' },
          { id: 'SR5.2', label: '새/변화 상황에서 언어 전략 사용하기' },
          { id: 'SR5.3', label: '새/변화 상황에서 초인지 전략 사용하기' },
          { id: 'SR5.4', label: '전이 중 행동 전략 사용하기' },
          { id: 'SR5.5', label: '전이 중 언어 전략 사용하기' },
          { id: 'SR5.6', label: '전이 중 초인지 전략 사용하기' },
        ],
      },
      {
        title: '6. 극심한 조절장애로부터 스스로 회복하기',
        items: [
          { id: 'SR6.1', label: '지나친 자극/원치 않는 활동으로부터 스스로 떠나기' },
          { id: 'SR6.2', label: '회복을 위해 행동 전략 사용하기' },
          { id: 'SR6.3', label: '회복을 위해 언어 전략 사용하기' },
          { id: 'SR6.4', label: '회복 후 상호작용/활동에 다시 참여하기' },
          { id: 'SR6.5', label: '회복 시간 단축하기' },
          { id: 'SR6.6', label: '조절장애 상태의 강도 줄이기' },
        ],
      },
    ],
  },

  interpersonalSupport: {
    label: '대인관계 지원 (Interpersonal Support)',
    code: 'IS',
    maxScore: 66,
    groups: [
      {
        title: '1. 파트너는 아동에게 반응적이다.',
        items: [
          { id: 'IS1.1', label: '아동의 관심 초점 따르기' },
          { id: 'IS1.2', label: '아동의 정서/속도에 맞추기' },
          { id: 'IS1.3', label: '의사소통 효능감 증진' },
          { id: 'IS1.4', label: '아동의 행동/언어/초인지 전략 인식/지원' },
          { id: 'IS1.5', label: '조절장애 신호 인식/지원' },
          { id: 'IS1.6', label: '상태 조절 정보/도움 제공' },
          { id: 'IS1.7', label: '필요할 때 휴식 제공' },
          { id: 'IS1.8', label: '휴식 후 재참여 촉진' },
        ],
      },
      {
        title: '2. 파트너는 시작행동을 촉진한다.',
        items: [
          { id: 'IS2.1', label: '비구어/구어로 선택 기회 제공' },
          { id: 'IS2.2', label: '시작행동 기다리고 격려' },
          { id: 'IS2.3', label: '시작/반응행동 균형 유지' },
          { id: 'IS2.4', label: '활동 시작/마치도록 해 주기' },
        ],
      },
      {
        title: '3. 파트너는 아동의 독립성을 존중한다.',
        items: [
          { id: 'IS3.1', label: '필요시 휴식 허락' },
          { id: 'IS3.2', label: '자신의 속도로 문제 해결/활동 완수 시간 허용' },
          { id: 'IS3.3', label: '문제행동을 의사소통/조절 기능으로 이해' },
          { id: 'IS3.4', label: '적절시 저항/거부/거절 존중' },
        ],
      },
      {
        title: '4. 파트너는 참여를 위한 장을 마련한다.',
        items: [
          { id: 'IS4.1', label: '의사소통 전 아동 주의 확보' },
          { id: 'IS4.2', label: '적절한 근접성/비구어 행동 사용' },
          { id: 'IS4.3', label: '적절한 단어/억양 사용' },
          { id: 'IS4.4', label: '정서/내적 상태/정신적 계획 공유' },
        ],
      },
      {
        title: '5. 파트너는 발달을 지원한다.',
        items: [
          { id: 'IS5.1', label: '또래 상호작용 성공 안내 제공' },
          { id: 'IS5.2', label: '구어/비구어 의사소통 실패 복구 시도' },
          { id: 'IS5.3', label: '활동 성공 안내/피드백 제공' },
          { id: 'IS5.4', label: '정서 표현/원인 이해 안내' },
          { id: 'IS5.5', label: '다른 사람의 감정/생각 해석 안내' },
        ],
      },
      {
        title: '6. 파트너는 언어 사용을 조절한다.',
        items: [
          { id: 'IS6.1', label: '이해 돕기 위해 비구어 단서 사용' },
          { id: 'IS6.2', label: '아동 발달 수준에 따라 언어 복잡성 조절' },
          { id: 'IS6.3', label: '아동 각성 수준에 따라 언어의 질 조절' },
        ],
      },
      {
        title: '7. 파트너는 적절한 행동을 시범 보인다.',
        items: [
          { id: 'IS7.1', label: '적절한 비구어 의사소통/정서 표현 시범' },
          { id: 'IS7.2', label: '다양한 의사소통 기능 시범' },
          { id: 'IS7.3', label: '적절한 극놀이/여가활동 시범' },
          { id: 'IS7.4', label: '부적절시 적절 행동 시범' },
          { id: 'IS7.5', label: "'아동 입장'에서 언어/혼잣말 사용 시범" },
        ],
      },
    ],
  },

  learningSupport: {
    label: '학습 지원 (Learning Support)',
    code: 'LS',
    maxScore: 50,
    groups: [
      {
        title: '1. 파트너는 적극적인 참여를 위해 활동을 구조화한다.',
        items: [
          { id: 'LS1.1', label: '활동 시작/종료 분명하게 정하기' },
          { id: 'LS1.2', label: '차례 주고받기 기회 및 참여 여지' },
          { id: 'LS1.3', label: '예측 가능한 순서 마련' },
          { id: 'LS1.4', label: '반복 학습 기회 제공' },
          { id: 'LS1.5', label: '다양한 학습 기회 제공' },
        ],
      },
      {
        title: '2. 파트너는 보완의사소통 지원을 사용한다.',
        items: [
          { id: 'LS2.1', label: '의사소통/표현언어 강화' },
          { id: 'LS2.2', label: '언어/행동 이해 강화' },
          { id: 'LS2.3', label: '정서 표현/이해 강화' },
          { id: 'LS2.4', label: '정서 조절 강화' },
        ],
      },
      {
        title: '3. 파트너는 시각적 지원/조직화 지원을 사용한다.',
        items: [
          { id: 'LS3.1', label: '과제 수행 단계 명확화' },
          { id: 'LS3.2', label: '활동 완수 시간/단계 명확화' },
          { id: 'LS3.3', label: '활동 간 원활한 전이' },
          { id: 'LS3.4', label: '하루 시간 분할 조직화' },
          { id: 'LS3.5', label: '집단 활동 주의집중 증진' },
          { id: 'LS3.6', label: '집단 활동 적극적 참여 촉진' },
        ],
      },
      {
        title: '4. 파트너는 목표, 활동, 학습 환경을 수정한다.',
        items: [
          { id: 'LS4.1', label: '사회적 복잡성 조절' },
          { id: 'LS4.2', label: '과제 난이도 조절' },
          { id: 'LS4.3', label: '학습 환경 감각적 속성 수정' },
          { id: 'LS4.4', label: '주의집중 환경 구성' },
          { id: 'LS4.5', label: '시작행동 촉진 환경 구성' },
          { id: 'LS4.6', label: '발달적으로 적절한 활동 고안/수정' },
          { id: 'LS4.7', label: '동기유발 교재/주제 포함' },
          { id: 'LS4.8', label: '시작/확장 상호작용 촉진 활동' },
          { id: 'LS4.9', label: '동적/정적 활동 교대' },
          { id: 'LS4.10', label: "'요구 정도 높이거나' 기대감 적절히 높이기" },
        ],
      },
    ],
  },
};

// 통합 매핑
const STAGE_DATA = {
  social: SOCIAL_PARTNER,
  language: LANGUAGE_PARTNER,
  conversation: CONVERSATION_PARTNER,
};

// 6대 영역 카테고리 표시용
const DOMAIN_GROUPS = [
  {
    title: '사회 의사소통 (Social Communication)',
    domains: ['joinAttention', 'symbolUse'],
  },
  {
    title: '정서 조절 (Emotional Regulation)',
    domains: ['mutualReg', 'selfReg'],
  },
  {
    title: '교류 지원 (Transactional Support)',
    domains: ['interpersonalSupport', 'learningSupport'],
  },
];

// =====================================================================
// SCERTS 지식 베이스 — 자동 가이드, 우선순위, 단계별 특징
// =====================================================================

// ── 단계별 특징 (보고서에 자동 삽입되는 단계 설명) ───────────────
const STAGE_PROFILE = {
  social: {
    headline: '사회적 파트너 단계',
    subtitle: '의도적 의사소통의 시작',
    age: '발달적 약 12~24개월 수준',
    summary:
      '아직 단어를 거의 사용하지 않거나, 3개 미만의 단어/구를 사용하는 단계입니다. ' +
      '의사소통은 주로 시선, 얼굴 표정, 몸짓, 발성을 통해 이루어지며, ' +
      '"혼자 노는 아이"에서 "사람과 함께 노는 아이"로의 전환이 핵심 발달 과제입니다.',
    features: [
      '비구어적 의사소통(시선·몸짓·발성) 중심',
      '의사소통 의도가 명확해지기 시작 (요청, 거부, 사회적 게임 요구)',
      '익숙한 일과에서 차례 주고받기 출현',
      '얼굴 표정으로 다양한 정서 표현',
      '파트너의 위로·주의 환기에 반응하기 시작',
    ],
    priorities: [
      '공동관심(JA)의 토대 — 시선 옮기기, 가리키기, 보여주기',
      '상호조절(MR) — 위로받기, 도움 청하기',
      '간단한 자기조절(SR) — 행동 전략 사용',
      '파트너의 반응성(IS) — 아동의 의사소통 신호 인식 및 반응',
    ],
  },
  language: {
    headline: '언어 파트너 단계',
    subtitle: '상징적 의사소통의 확장',
    age: '발달적 약 2~3세 수준',
    summary:
      '3개 이상의 단어/구를 의도적으로 사용하지만, 100개 미만이거나 창의적 단어 조합이 부족한 단계입니다. ' +
      '단어와 단어 조합으로 의도를 표현하기 시작하며, ' +
      '의사소통 의도의 다양화와 정서 어휘의 확장이 핵심 발달 과제입니다.',
    features: [
      '단일 단어에서 2~3어 조합으로 확장',
      '다양한 의사소통 기능 출현 (요청, 거부, 인사, 관심 끌기, 정보 요구)',
      '초기 정서 단어 이해 및 사용',
      '확장된 차례 주고받기 (3~4 차례)',
      '언어 전략을 이용한 자기조절 시도',
    ],
    priorities: [
      '관계어·서술어 확장 (SU 5번대)',
      '경험 공유와 청자-화자 역할 바꾸기 (JA8)',
      '언어 전략을 통한 자기조절 (SR3)',
      '파트너의 언어 시범 조절 (IS6, IS7)',
    ],
  },
  conversation: {
    headline: '대화 파트너 단계',
    subtitle: '사회적 담화로의 진입',
    age: '발달적 약 3세 이후',
    summary:
      '100개 이상의 어휘와 창의적 단어 조합을 정기적으로 사용하는 단계입니다. ' +
      '대화 규칙, 청자 고려, 정서의 미묘한 차이를 다루며, ' +
      '또래 우정과 사회적 담화 능력의 발달이 핵심 과제입니다.',
    features: [
      '확장된 문장과 복문 사용',
      '대화 차례 주고받기, 주제 유지·전환',
      '상위 수준 정서 단어와 단계적 정서 이해',
      '청자의 관심·지식에 맞춘 언어 조절',
      '초인지 전략을 통한 자기조절',
      '또래와의 협력 및 우정 형성',
    ],
    priorities: [
      '대화 차례·주제 관리 (JA4, SU6)',
      '정서 단어 정교화 + 원인 설명 (MR1, JA2)',
      '초인지 전략 (SR4) — 자기점검, 혼잣말, 정서 기억',
      '또래 협력과 우정 지원 (IS5, JA4.8)',
    ],
  },
};

// ── 예시 문구 모음 (정형화된 임상 문구만. 가족 개별 의견은 제외) ──
// "💡 예시 보기" 버튼으로 제공. 클릭하면 칸에 채워지고 이후 수정 가능.
const EXAMPLE_BANK = {
  // 중간보고서 — 영역별 관찰 행동
  domainBehavior: [
    '시선 공유, 공동 관심, 요청하기',
    '모방, 차례 주고받기, 사물 요구',
    '발성·단어 사용, 몸짓 의사소통',
    '전이 상황 반응, 정서 표현, 진정 행동',
  ],
  // 중간보고서 — 영역별 진전
  domainProgress: [
    '요청 시 발화 출현 빈도가 증가하고, 시선 유지 시간이 향상되었다.',
    '파트너의 촉구 수준이 신체적 → 시각적 → 자연적 단서로 점진적으로 줄었다.',
    '전이 상황에서 시각일과표 사용 후 거부 행동이 감소하였다.',
    '활동 중 자발적 모방이 증가하고, 차례 주고받기 시도가 관찰되었다.',
  ],
  // 중간보고서 — 종합 요약(틀만, 구체 내용은 직접)
  interimSummary: [
    '[아동명]은(는) 이번 평가 기간 동안 세 영역에서 점진적 진전을 보였으며, 특히 [영역]에서 변화가 확인되었다. 강점은 [강점]이며, 우선 지원이 필요한 영역은 [영역]이다.',
  ],
  // 중간보고서 — 향후 중재 방향
  interimDirection: [
    '다음 분기에는 자발적 의사소통 빈도를 높이기 위해 자연스러운 의사소통 기회를 확대하고, 촉구 계층을 점진적으로 줄여간다.',
    '정서 조절 영역에서 전이 예고 루틴과 시각 단서 사용을 강화하고, 파트너의 일관된 반응을 유지한다.',
    '가정·교실 간 전략 일관성을 확보하기 위해 시각일과표와 강화계획을 공유한다.',
  ],
  // 활동기록 — 회기 관찰(영역별)
  sessionSocial: [
    '놀이 중 자발적으로 시선을 맞추고 요청하는 행동이 관찰됨',
    '차례 주고받기 활동에서 파트너의 신호를 기다리는 모습',
  ],
  sessionEmo: [
    '전이 시 타이머 사용으로 안정적으로 다음 활동에 참여',
    '좌절 상황에서 진정 전략 사용 후 활동에 재참여',
  ],
  sessionTs: [
    '시각 단서 제공 시 지시 수행이 향상됨',
    '파트너의 반응 속도를 늦추자 시작행동이 증가',
  ],
  // 전문가 지원 폼 — 가정 전략/시점/자원
  homeStrategy: [
    '식사·놀이 등 일상 루틴에 의사소통 기회를 의도적으로 배치한다.',
    '선택 기회를 자주 제공하여 자발적 요청을 유도한다.',
    '시각일과표로 다음 활동을 예측하게 한다.',
  ],
  homeWhen: [
    '식사 시간, 간식 준비 중',
    '놀이 시작 전 / 활동 전이 시점',
    '외출 준비 등 일과 전환 상황',
  ],
  homeResources: [
    '시각 카드(PECS), 타이머, 선택판',
    '사진 일과표, 강화물 목록',
  ],
  // 활동 흐름
  activityFlow: [
    '시작(인사·노래로 주의 환기) → 본 활동(목표 기술 연습) → 마무리(정리·강화·다음 예고)',
  ],
};


// SCERTS 항목은 발달 순서대로 번호가 매겨져 있으나, 매뉴얼이 항목 간 의존성을 강제하지는 않습니다.
// 본 트리는 발달 심리학의 일반적 순서를 반영한 임상 판단 보조 도구이며,
// 개별 아동의 발달 양상에 따라 임상가가 판단을 우선해야 합니다.
const JA_DEVELOPMENT_TREE = {
  social: {
    // 1.x 그룹: 상호적 상호작용
    'JA1.2': ['JA1.1'], // 시작은 반응이 먼저
    'JA1.3': ['JA1.1', 'JA1.2'], // 간단한 상호적 ← 시작+반응
    'JA1.4': ['JA1.3'], // 확장된 ← 간단한
    // 2.x 그룹: 관심 공유
    'JA2.2': ['JA2.1'], // 시선 옮기기 ← 사람 쳐다보기
    'JA2.3': ['JA2.1'], // 가까운 가리키기 ← 사람 쳐다보기
    'JA2.4': ['JA2.3'], // 멀리 가리키기 ← 가까운 가리키기
    // 4.x 그룹: 행동 조절 의도 (요구는 거부보다 먼저 안정화)
    'JA4.3': ['JA4.1'], // 도움 청하기 ← 원하는 것 요구
    'JA4.4': ['JA4.2'], // 활동 거부 ← 사물 거부
    // 5.x 그룹: 사회적 의도 (위로→게임→인사 순)
    'JA5.2': ['JA5.1'], // 게임 요구 ← 위로 구하기
    'JA5.4': ['JA5.3'], // 인사 ← 차례 주고받기
    'JA5.5': ['JA5.4'], // 부르기 ← 인사
    'JA5.6': ['JA5.5'], // 자랑하기 ← 부르기
    // 6.x 그룹: 공동관심 의도 (사물 언급 → 행동 언급)
    'JA6.2': ['JA6.1'],
    // 7.x 그룹: 의사소통 복구
    'JA7.2': ['JA7.1'], // 반복 ← 의사소통 비율 확보
    'JA7.3': ['JA7.2'], // 수정 ← 반복
  },
};

// ── 원전 교차참조: 동일 항목 매핑 (=) ────────────────────────────
// SCERTS 진단 양식의 "=" 표기는 한 행동이 두 영역에서 동시에 채점되는
// 동일 항목임을 의미합니다 (예: JA1.1 = MR2.3). 한쪽을 채점하면 연동 항목도
// 같은 점수가 되어야 진단 일관성이 유지됩니다. (≈ 유사, ↔ 그룹 관련은 제외)
// 출처: SCERTS 1권 부록 진단-관찰 기록지 (사회적 파트너 단계)
const EQUIVALENT_ITEMS = {
  social: [
    ['JA1.1', 'MR2.3'],
    ['JA1.2', 'SR1.4'],
    ['JA1.3', 'SR1.5'],
    ['JA1.4', 'SR1.6'],
    ['JA2.3', 'SU2.4'],
    ['JA2.4', 'SU2.5'],
    ['JA3.3', 'MR2.4'],
    ['JA3.4', 'MR2.5'],
    ['SU2.1', 'SR3.1'],
  ],
};

// 항목 ID → 동등 항목 ID 목록 (양방향 조회용)
function getEquivalentItems(stage, itemId) {
  const pairs = EQUIVALENT_ITEMS[stage] || [];
  const result = [];
  pairs.forEach(([a, b]) => {
    if (a === itemId) result.push(b);
    else if (b === itemId) result.push(a);
  });
  return result;
}

// ── MR ↔ SR 다리 놓기 전략 ──────────────────────────────────────
// 상호조절(타인이 도와줌)에서 자기조절(스스로)로 가는 발달 다리
const MR_SR_BRIDGE = {
  // MR에서 강하지만 SR에서 약한 패턴 → 자율화 전략 필요
  highMR_lowSR: {
    title: '"파트너 의존형" 패턴',
    interpretation:
      '아동이 다른 사람의 도움으로는 조절이 잘 되지만, 혼자서는 조절 전략을 사용하기 어려운 상태입니다. ' +
      '이는 안정적인 관계가 형성되어 있다는 강점이지만, 점진적 자율화가 필요한 단계입니다.',
    strategies: [
      '파트너가 사용하던 진정 전략을 아동 스스로 따라 할 수 있도록 시범 보이기',
      '파트너의 언어 단서(예: "심호흡해볼까?")를 아동이 혼잣말로 사용하도록 안내',
      '"내가 도와줄까? 아니면 혼자 해볼래?" 선택 기회 제공',
      '시각적 정서 차트(감정 온도계)를 도입하여 자기 상태 인식 지원',
      '익숙한 활동에서 먼저 자기조절 연습 → 새로운 상황으로 확장',
    ],
  },
  // SR이 MR보다 강한 드문 패턴 → 사회적 연결 보강 필요
  lowMR_highSR: {
    title: '"단절된 자율형" 패턴',
    interpretation:
      '아동이 혼자서는 조절 전략을 사용하지만, 다른 사람의 도움을 받아들이거나 요청하지 못하는 상태입니다. ' +
      '도움을 거부하거나 회피하는 경향이 있을 수 있어, 사회적 신뢰 형성이 우선됩니다.',
    strategies: [
      '아동이 좋아하는 활동에서 파트너의 존재를 부담 없이 경험하게 하기',
      '아동의 조절 전략을 파트너가 함께 사용해 주며 공감 보이기',
      '도움 청하기를 작은 단위로 시범 보이기 (예: "이거 좀 도와줘")',
      '예측 가능한 일과 안에서 파트너 의존 경험을 점진적으로 늘리기',
    ],
  },
  // 둘 다 낮은 경우 → MR 먼저
  lowMR_lowSR: {
    title: '"조절 토대 형성 필요" 패턴',
    interpretation:
      '상호조절과 자기조절 모두 낮은 수준입니다. 자기조절은 상호조절 경험 위에서 발달하므로, ' +
      'MR 항목을 먼저 안정화하는 것이 발달적으로 우선됩니다.',
    strategies: [
      '파트너의 반응성·예측가능성 확보 (IS1 영역 강조)',
      '아동이 좋아하는 감각 자극이나 활동으로 진정·각성 조절 시범',
      '간단한 신호(예: 그림 카드)로 도움 요청을 가르치기',
      '안정 후 단계적으로 자기조절 전략(혼자서 할 수 있는 행동) 도입',
    ],
  },
  // 둘 다 높음
  balanced: {
    title: '"균형적 조절" 패턴',
    interpretation: '상호조절과 자기조절이 모두 안정적입니다. 더 복잡한 상황에서의 일반화와 새로운 전략 학습으로 확장합니다.',
    strategies: [
      '새롭고 도전적인 상황에서 조절 전략 적용 연습',
      '또래·집단 상황에서의 조절 경험 확장',
      '단계적 정서(짜증→화남→격분)와 같은 미묘한 정서 다루기',
      '초인지 전략(자기점검, 정서 기억) 도입',
    ],
  },
};

// ── IEP 목표 우선순위 알고리즘 가중치 ────────────────────────────
// SCERTS 매뉴얼(2권 제1장 5절, 책 p.32)은 교수목표 결정에 세 가지 주요 기준을 적용:
//   ① 기능성    — 이 기술이 아동의 삶에 가져올 변화 (앱: 점수 0~1 항목 우선, scoreBoost)
//   ② 가족의 우선순위 — 가족의 가치관·희망과 일치 (앱: familyChoiceBoost, 최대 가중치)
//   ③ 발달적 적합성  — 발달 능력에 비추어 적절 (앱: FOUNDATION_ITEMS + 선행 의존성 트리)
// 교수목표는 사회적→언어→대화 파트너 단계를 근거로 계열화되며(2권 p.35),
// 공동관심·상징 사용 능력의 단계 이동이 핵심 장기목표(2권 p.35).
// 주간 교수목표 개수는 아동·상황에 따라 유연하며 고정된 수치가 아님.
// (Prizant et al., 2006, Vol.2 Program Planning 책 p.27-36 / Vol.1 부록 요약지)
const IEP_PRIORITY_WEIGHTS = {
  // 가족이 우선 선택한 항목은 SCERTS의 핵심 가치 (가장 큰 가중치)
  familyChoiceBoost: 50,
  // 점수가 낮을수록 우선순위 ↑ (학습 기회 많음)
  scoreBoost: { 0: 30, 1: 20 },
  // 영역별 발달적 토대성 (각 단계에서 임상적으로 우선되는 영역)
  // ※ SCERTS 매뉴얼이 영역 가중치를 수치로 명시하지는 않음. 임상적 발달 우선순위를 반영한 보조 지표.
  domainBoost: {
    social: {
      joinAttention: 25,
      symbolUse: 18,
      mutualReg: 22,
      selfReg: 15,
      interpersonalSupport: 15,
      learningSupport: 12,
    },
    language: {
      joinAttention: 18,
      symbolUse: 25,
      mutualReg: 18,
      selfReg: 20,
      interpersonalSupport: 15,
      learningSupport: 12,
    },
    conversation: {
      joinAttention: 22,
      symbolUse: 18,
      mutualReg: 18,
      selfReg: 22,
      interpersonalSupport: 15,
      learningSupport: 12,
    },
  },
  foundationBoost: 10,
};

// 단계별 토대 항목 ID (각 영역에서 가장 먼저 도달해야 하는 항목)
const FOUNDATION_ITEMS = {
  social: new Set([
    'JA1.1', 'JA2.1', 'JA3.1', 'JA4.1', 'JA5.1', 'JA6.1', 'JA7.1',
    'SU1.1', 'SU2.1', 'SU3.1', 'SU4.1', 'SU5.1', 'SU6.1',
    'MR1.1', 'MR2.1', 'MR3.1', 'MR4.1',
    'SR1.1', 'SR2.1', 'SR3.1', 'SR4.1',
  ]),
  language: new Set([
    'JA1.1', 'JA2.1', 'JA3.1', 'JA4.1', 'JA5.1', 'JA6.1', 'JA7.1', 'JA8.1',
    'SU1.1', 'SU2.1', 'SU3.1', 'SU4.1', 'SU5.1', 'SU6.1',
    'MR1.1', 'MR2.1', 'MR3.1', 'MR4.1',
    'SR1.1', 'SR2.1', 'SR3.1', 'SR4.1', 'SR5.1',
  ]),
  conversation: new Set([
    'JA1.1', 'JA2.1', 'JA3.1', 'JA4.1', 'JA5.1',
    'SU1.1', 'SU2.1', 'SU3.1', 'SU4.1', 'SU5.1', 'SU6.1',
    'MR1.1', 'MR2.1', 'MR3.1', 'MR4.1', 'MR5.1',
    'SR1.1', 'SR2.1', 'SR3.1', 'SR4.1', 'SR5.1', 'SR6.1',
  ]),
};

// ── 사회-정서 성장 지표 해석 가이드 ──────────────────────────────
const SES_INTERPRETATION = {
  // 점수대별 해석 (0-10 스케일)
  ranges: [
    { min: 0, max: 3, label: '발달 초기', color: '#b54a3a',
      meaning: '이 지표 영역에서 발달이 초기 단계에 있습니다. 기초적인 경험과 지원이 우선됩니다.' },
    { min: 4, max: 6, label: '발달 중', color: '#c19a3a',
      meaning: '발달이 진행 중이며, 일관성과 다양한 상황으로의 확장이 다음 과제입니다.' },
    { min: 7, max: 10, label: '안정적 발달', color: '#2d4a3e',
      meaning: '이 영역은 비교적 안정적입니다. 더 복잡한 상황과 또래 관계로 확장할 수 있습니다.' },
  ],
};


// =====================================================================
// SCERTS 부록 추가 양식 (질문지 / 관찰 계획 / 활동 일지 / 주간 기록 / 활동 계획서)
// PDF 부록 A "SCERTS 진단 양식" 원본 그대로 반영
// =====================================================================

// ── 질문지 유형 정의 ─────────────────────────────────────────────
// text: 자유 서술
// checklist: 다중 선택 체크 (selectedItems / 각 항목 별 추가 텍스트)
// frequency: "거의 또는 전혀 하지 않음 | 가끔 | 자주" 빈도 행렬
// emotionPairs: 긍정/부정 감정 짝 표현
// scale02: 0/1/2 점수
// scaleLevel: 단계 또는 레벨

// =====================================================================
// 사회적 파트너 단계 질문지
// =====================================================================
const SP_INTERVIEW = {
  stage: 'social',
  intro:
    '이 질문지는 아동과 매일 또는 정기적으로 상호작용하는 부모, 교사, 기타 주변인이 기록하도록 작성되었습니다. ' +
    '아동의 사회 의사소통(사회적 상호작용에서 비구어 및 구어 의사소통 이해하고 사용하기), ' +
    '정서 조절(주의집중, 각성 및 정서 상태를 조절하는 능력), ' +
    '교류 지원(파트너 및 학습 활동이 발달을 지원하는 방법)에 대한 아래의 질문에 답하십시오. ' +
    '아동을 관찰할 수 있을 때, 또는 아동을 관찰한 직후 아래의 행동을 확인하여 작성하십시오. 구체적인 예를 기록하십시오.',
  meta: ['이름', '연령', '작성일', '작성자', '아동과의 관계'],
  sections: [
    {
      key: 'social',
      title: '사회 의사소통',
      questions: [
        {
          id: 'sp_sc_1',
          type: 'text',
          q: '다른 사람과 어떻게 상호작용하는지 기술하시오. 예를 들어, 다른 사람의 상호작용 시도에 반응하는가? 상호작용을 시작하는가? 두세 번 정도 차례를 주고받는가? 파트너와 관심을 공유하면서 여러 번 차례를 주고받는가?',
        },
        {
          id: 'sp_sc_2',
          type: 'text',
          q: '상호작용을 하는 동안 시선을 어떻게 사용하는지 기술하시오. 예를 들어, 사람을 전혀 또는 거의 쳐다보지 않는가, 아니면 자주 쳐다보는가? 놀잇감을 가지고 놀 때 당신이 지켜보는지를 살피기 위해 고개를 들어 쳐다본 다음 다시 물건을 향해 시선을 옮기는가?',
        },
        {
          id: 'sp_sc_3',
          type: 'checklist',
          q: '다음 중 아동이 의사소통할 때 일상적으로 사용하는 방법을 모두 골라서 표시하시오.',
          options: [
            '물건 건네주기', '물건 밀어내기', '다른 사람의 손을 당겨 물건 위에 놓기',
            '손 뻗기/만지기', '물건 보여 주기', '가리키기/만지기',
            '손 흔들기', '손뼉 치기', '고개 젓기(거절 또는 거부하기 위해)',
            '멀리 있는 것을 향해 손 뻗기', '멀리 있는 것 가리키기',
          ],
          withText: [
            { id: 'vocal', label: '발성(아동이 내는 소리를 모두 적으시오)' },
            { id: 'word', label: '단어(또는 단어 시도)(아동이 말하고자 하는 단어를 모두 적으시오)' },
            { id: 'problem', label: '문제행동(예를 적으시오)' },
          ],
        },
        {
          id: 'sp_sc_4',
          type: 'checklist',
          q: '아동이 의사소통을 하는 이유는 무엇인가? 다음 중 해당되는 것에 표시하고 예를 적으시오.',
          options: [
            '원하는 물건 요구하기', '원하지 않는 것 거절하기',
            '도움 청하기', '사회적 게임 요구하기(예: 까꿍놀이, 뒤쫓아가기, 간지럼 태우기)',
            '위로 구하기', '인사하기',
            '다른 사람이 알아주기를 원하는 무엇인가로 그 사람의 관심 끌기',
          ],
        },
        {
          id: 'sp_sc_5',
          type: 'frequency',
          q: '상호작용할 때 얼마나 자주 의사소통을 시작하는가?',
          partners: ['친숙한 사람과 함께', '친숙하지 않은 사람과 함께', '소집단 내에서'],
        },
        {
          id: 'sp_sc_6',
          type: 'text',
          q: '아동의 요구를 알아채지 못할 때 어떤 일이 발생하는가? 아동은 어떻게 행동하는가?',
        },
        {
          id: 'sp_sc_7',
          type: 'text',
          q: '아동이 가장 좋아하는 놀잇감은 무엇인가? 그것을 가지고 어떻게 놀이하는가?',
        },
        {
          id: 'sp_sc_8',
          type: 'text',
          q: '친숙한 성인이 놀이에 끼어들면 아동은 어떻게 반응하는가? 친숙한 또래나 형제가 끼어들면 어떻게 반응하는가?',
        },
        {
          id: 'sp_sc_9',
          type: 'frequency',
          q: '다른 사람이 시범을 보인 행동이나 소리에 대해 어떻게 반응하는가?',
          partners: ['차례를 주고받는가?', '익숙한 행동이나 소리를 모방하는가?', '새로운 행동이나 소리를 모방하는가?'],
        },
        {
          id: 'sp_sc_10',
          type: 'checklist',
          q: '다음의 교수나 단서 중 아동이 이해하는 것에 모두 표시하시오.',
          options: [
            '가리키기 외의 몸짓', '가리키기', '사진이나 그림',
            '얼굴 표정', '억양', '아동의 이름',
          ],
          withText: [
            { id: 'game_word', label: '사회적 게임에서의 단어(예를 적으시오)' },
            { id: 'name_word', label: '친숙한 사람이나 익숙한 물건의 이름(예를 적으시오)' },
            { id: 'phrase', label: '일상적으로 사용하는 구(예를 적으시오)' },
            { id: 'sentence', label: '문장(예를 적으시오)' },
          ],
        },
      ],
    },
    {
      key: 'emo',
      title: '정서 조절',
      questions: [
        {
          id: 'sp_er_1',
          type: 'text',
          q: '아동은 자신의 환경 내에 있는 사람과 사물에 대해 어떻게 반응하는가? 예를 들어, 다양한 상황에 흥미를 보이는지, 몇 가지에 대해서만 강한 흥미를 보이는지, 다양한 감정을 나타내는지, 혼자 지내는지, 상호작용을 위한 시도에 반응하거나 상호작용을 하기 위해 노력하는지 등을 기술하시오.',
        },
        { id: 'sp_er_2', type: 'text', q: '가장 재미있어 하거나 흥미를 보이는 활동 또는 상황은 무엇인가?' },
        { id: 'sp_er_3', type: 'text', q: '가장 힘들어하거나 지루해하는 활동 또는 상황은 무엇인가?' },
        {
          id: 'sp_er_4',
          type: 'text',
          q: '친숙한 활동을 하는 동안 집중과 흥미를 유지하기 위해서 또는 진정하거나 활동에 참여하기 위해서 전략을 사용하는가(예: 고무 젖꼭지 빨기, 담요 문지르기, 몸 흔들기, 발끝으로 걷기)? 만일 그렇다면, 그 전략을 구체적으로 기술하시오.',
        },
        {
          id: 'sp_er_5',
          type: 'text',
          q: '새롭고 변화된 상황이나 그 밖의 도전적인 상황에서 집중과 흥미를 유지하기 위해서 또는 진정하거나 활동에 참여하기 위해서 전략을 사용하는가? 만일 그렇다면, 그 전략을 구체적으로 기술하시오.',
        },
        {
          id: 'sp_er_6',
          type: 'emotionsRows',
          q: '다음의 감정을 표현하는가? 만일 그렇다면, 어떻게 표현하는지 기술하시오.',
          emotions: ['기쁨', '슬픔', '분노', '두려움'],
        },
        { id: 'sp_er_7', type: 'text', q: '다른 사람이 위로해 줄 때 반응하는가? 만일 그렇다면, 어떻게 반응하는가?' },
        { id: 'sp_er_8', type: 'text', q: '다른 사람이 선택하라고 요구할 때 반응하는가? 만일 그렇다면, 어떻게 반응하는가?' },
        { id: 'sp_er_9', type: 'text', q: '아동이 집중하고, 흥미를 갖고, 진정하고, 참여를 유지하도록 돕기 위해 어떤 전략을 사용하는가?' },
        { id: 'sp_er_10', type: 'text', q: '아동이 흥분하거나 화가 났다는 것을 어떻게 알 수 있는가? 아동은 어떤 신호를 보이는가?' },
        { id: 'sp_er_11', type: 'text', q: '아동이 지루해하거나 흥미가 없다는 것을 어떻게 알 수 있는가? 아동은 어떤 신호를 보이는가?' },
        {
          id: 'sp_er_12',
          type: 'recoveryPair',
          q: '아동은 매우 심하게 화가 나거나 괴로울 때',
          self: '어떻게 스스로 회복하는가? 보통 회복되기까지 얼마나 오래 걸리는가?',
          partner: '파트너가 어떻게 도움을 줄 때 회복되는가? 보통 회복되기까지 얼마나 오래 걸리는가?',
        },
      ],
    },
    {
      key: 'ts',
      title: '교류 지원',
      questions: [
        { id: 'sp_ts_1', type: 'text', q: '아동이 정기적으로(매일 또는 매주) 상호작용을 하거나 일상적으로 만나는 사람은 누구인가?' },
        { id: 'sp_ts_2', type: 'text', q: '아동이 정기적으로(매일 또는 매주) 가는 장소는 어디인가?' },
        {
          id: 'sp_ts_3',
          type: 'scale02List',
          q: '다음 중 쉽게 파악하거나 따르거나 반응할 수 있는 것은 모두 다음의 숫자로 표시하시오: 거의 또는 전혀 파악할 수 없거나 반응할 수 없다면 0, 가끔씩 파악하거나 반응할 수 있다면 1, 대부분의 경우 파악하거나 반응할 수 있다면 2.',
          items: [
            '아동이 관심을 갖는 대상', '아동이 의사소통하려고 하는 것',
            '아동의 감정 상태', '아동이 선호하는 속도(빠름 또는 느림)',
            '아동에게 휴식이 필요할 때', '아동이 흥미를 보이는지 여부',
            '아동이 좌절했는지 여부', '아동이 흥분했는지 여부',
          ],
        },
        { id: 'sp_ts_4', type: 'text', q: '아동이 의사소통을 시작하도록 격려하는 데에 가장 도움이 되는 전략은 무엇인가(예: 선택할 기회 제공하기, 아동을 기다리며 쳐다보기, 내 차례가 지난 후 기다리기)?' },
        { id: 'sp_ts_5', type: 'text', q: '아동이 때리거나 소리를 지르거나 깨무는 등 문제행동을 보일 때 당신은 보통 어떻게 반응하는가? 그러한 반응이 효과적인가?' },
        { id: 'sp_ts_6', type: 'text', q: '아동의 주의를 끄는 데에 가장 도움이 되는 전략은 무엇인가(예: 아동의 눈높이에 맞추기, 아동에게 가까이 다가가거나 멀리 떨어지기, 아동의 감정에 맞추기, 아동을 기다리고 따르기)?' },
        { id: 'sp_ts_7', type: 'text', q: '아동과의 상호작용을 유지하는 데에 가장 도움이 되는 전략은 무엇인가(예: 아동이 상호작용을 시작하게 하기, 아동이 휴식을 취한 후 계속하게 하기, 아동의 흥미를 따르기)?' },
        { id: 'sp_ts_8', type: 'text', q: '아동에게 전달한 메시지를 이해했는지 확인하기 위해서 아동에게 주로 어떻게 의사소통을 하는가?' },
        { id: 'sp_ts_9', type: 'text', q: '아동이 의사소통을 하고, 언어를 이해하고, 감정을 표현하고, 순조로운 일과를 진행하도록 도와주기 위해서 시각적 지원을 사용하는가? 만일 그렇다면, 어떤 지원을 사용하는가(예: 그림으로 과제의 단계 보여 주기, 전이용 사물, 선택용 그림, 수어)?' },
        { id: 'sp_ts_10', type: 'text', q: '아동이 참여를 유지하는 데 도움이 되는 물리적 또는 사회적 환경 특성은 무엇인가(예: 아동이 상호작용하는 사람의 수 제한하기, 배경 소음 또는 시각적인 혼잡함 줄이기, 움직임이나 리듬을 위한 기회 더 많이 주기, 특정 활동을 위해 특정 장소를 일관성 있게 사용하기)?' },
        { id: 'sp_ts_11', type: 'text', q: '아동이 의사소통을 더 잘 하도록 돕는 물리적 또는 사회적 환경 특성은 무엇인가(예: 아동이 좋아해서 동기를 유발할 수 있는 놀잇감이나 활동 이용하기, 좋아할 만한 또는 좋아하는 물건을 조금 멀리 두기)?' },
      ],
    },
    {
      key: 'extra',
      title: '추가 의견',
      questions: [
        { id: 'sp_ex_1', type: 'text', q: '아동에게서 관찰되는 가장 큰 강점이나 자산을 모두 나열하시오.' },
        { id: 'sp_ex_2', type: 'text', q: '아동의 발달에 있어서 우선적으로 걱정되는 부분을 나열하시오.' },
        { id: 'sp_ex_3', type: 'text', q: '아동의 프로그램을 계획하거나 수정할 때 가장 유용하다고 생각되는 정보는 무엇인가?' },
        { id: 'sp_ex_4', type: 'text', q: '아동에 대해 우리가 알아야 할 기타 중요한 정보가 있다면 기술하시오.' },
        { id: 'sp_ex_5', type: 'text', q: '질문이 있으면 적으시오.' },
        { id: 'sp_ex_6', type: 'text', q: '연락이 가능한 가장 적당한 시간과 방법을 알려 주십시오.' },
      ],
    },
  ],
};

// =====================================================================
// 언어 파트너 단계 질문지
// =====================================================================
const LP_INTERVIEW = {
  stage: 'language',
  intro: SP_INTERVIEW.intro,
  meta: SP_INTERVIEW.meta,
  sections: [
    {
      key: 'social',
      title: '사회 의사소통',
      questions: [
        { id: 'lp_sc_1', type: 'text', q: '다른 사람과 어떻게 상호작용하는지 기술하시오.' },
        { id: 'lp_sc_2', type: 'text', q: '상호작용을 하는 동안 시선을 어떻게 사용하는지 기술하시오.' },
        {
          id: 'lp_sc_3',
          type: 'checklist',
          q: '다음 중 아동이 의사소통할 때 일상적으로 사용하는 방법을 모두 골라서 표시하시오.',
          options: [
            '물건 보여 주기', '손 흔들기', '멀리 있는 것 가리키기',
            '손뼉 치기', '고개 젓기(거절 또는 거부하기 위해)',
            '고개 끄덕이기(수용하거나 \'예\'라고 표현하기 위해)',
          ],
        },
        {
          id: 'lp_sc_4',
          type: 'checklist',
          q: '아동이 의사소통할 때 일상적으로 사용하는 단어 형태(구어, 수어, 그림, 글자, 또는 기타 상징 체계)는 무엇인가? 다음 중 해당하는 것을 모두 표시하고 구체적인 예를 적으시오.',
          options: [
            '사물의 이름(예: 놀잇감, 음식, 신체부위)',
            '사람이나 애완동물의 이름',
            '"더" 또는 "또"의 의미를 나타내는 방법',
            '"아니" 또는 "없네(gone)"의 의미를 나타내는 방법',
            '인사말(예: "안녕" "바이바이" "또 만나")',
            '사물을 설명하는 수식어나 단어(예: "뜨거운" "큰" "냄새 나는")',
            '자발적인 단어 조합(예: "밖에 나가" "과자 없어")',
          ],
        },
        {
          id: 'lp_sc_5',
          type: 'checklist',
          q: '아동이 의사소통을 하는 이유는 무엇인가? 다음 중 해당되는 것에 표시하고 예를 적으시오.',
          options: [
            '원하는 물건을 요구하거나 도움 청하기', '원하지 않는 것 거절하기',
            '인사하기', '허락 구하기',
            '다른 사람이 알아주기를 원하는 무엇인가로 그 사람의 관심 끌기',
            '흥미로운 것에 대해 정보 요구하기',
          ],
        },
        {
          id: 'lp_sc_6', type: 'frequency',
          q: '상호작용할 때 얼마나 자주 의사소통을 시작하는가?',
          partners: ['친숙한 사람과 함께', '친숙하지 않은 사람과 함께', '소집단 내에서'],
        },
        { id: 'lp_sc_7', type: 'text', q: '아동의 요구를 알아채지 못할 때 어떤 일이 발생하는가? 아동은 어떻게 행동하는가?' },
        { id: 'lp_sc_8', type: 'text', q: '아동이 가장 좋아하는 놀잇감이나 활동은 무엇인가? 그것을 가지고 어떻게 놀이하는가?' },
        { id: 'lp_sc_9', type: 'text', q: '친숙한 성인/또래/형제가 놀이에 끼어들면 아동은 어떻게 반응하는가?' },
        {
          id: 'lp_sc_10', type: 'checklist',
          q: '다음 중 일관성 있게 이해하는 의미나 비구어 단서에 모두 표시하시오.',
          options: [
            '가리키기 외의 몸짓', '가리키기', '사진이나 그림',
            '얼굴 표정', '억양', '아동의 이름',
            '한 단어로 된 지시', '두 단어 이상의 지시',
            '상황 단서가 없을 때의 단일 명사',
          ],
          withText: [
            { id: 'verb', label: '상황 단서가 없을 때 동사나 수식어(예를 적으시오)' },
            { id: 'phrase', label: '상황 단서가 없을 때 구나 문장(예를 적으시오)' },
          ],
        },
      ],
    },
    {
      key: 'emo',
      title: '정서 조절',
      questions: [
        { id: 'lp_er_1', type: 'text', q: '아동은 자신의 환경 내에 있는 사람과 사물에 대해 어떻게 반응하는가?' },
        { id: 'lp_er_2', type: 'text', q: '가장 재미있어 하거나 흥미를 보이는 활동 또는 상황은 무엇인가?' },
        { id: 'lp_er_3', type: 'text', q: '가장 힘들어하거나 지루해하는 활동 또는 상황은 무엇인가?' },
        { id: 'lp_er_4', type: 'text', q: '친숙한 활동을 하는 동안 집중과 흥미를 유지하기 위해서 또는 진정하거나 활동에 참여하기 위해서 전략을 사용하는가(예: 양손을 꽉 쥐기, 담요 문지르기, 몸 흔들기, "끝나면 밖에 나가요?"라고 말하기)?' },
        { id: 'lp_er_5', type: 'text', q: '새롭고 변화된 상황이나 그 밖의 도전적인 상황에서 집중과 흥미를 유지하기 위해서 또는 진정하거나 활동에 참여하기 위해서 전략을 사용하는가(예: 활동이 바뀔 때 친숙한 노래 부르기, 두려움을 느낄 때 "걱정하지 마"라고 말하기)?' },
        {
          id: 'lp_er_6',
          type: 'emotionPairs',
          q: '다음의 긍정적인 감정과 부정적인 감정을 표현하는가? 만일 그렇다면, 어떻게 표현하는가?',
          pairs: [
            ['기쁨', '슬픔'],
            ['만족감', '분노 또는 좌절'],
            ['익살스러움', '두려움'],
          ],
        },
        { id: 'lp_er_7', type: 'text', q: '다른 사람이 위로해 줄 때 반응하는가? 만일 그렇다면, 어떻게 반응하는가?' },
        { id: 'lp_er_8', type: 'text', q: '다른 사람이 선택하라고 요구할 때 반응하는가? 만일 그렇다면, 어떻게 반응하는가?' },
        { id: 'lp_er_9', type: 'text', q: '아동이 집중하고, 흥미를 갖고, 진정하고, 참여를 유지하도록 돕기 위해 어떤 전략을 사용하는가?' },
        { id: 'lp_er_10', type: 'text', q: '아동이 흥분하거나 화가 났다는 것을 어떻게 알 수 있는가? 아동은 어떤 신호를 보이는가?' },
        { id: 'lp_er_11', type: 'text', q: '아동이 지루해하거나 흥미가 없다는 것을 어떻게 알 수 있는가?' },
        {
          id: 'lp_er_12', type: 'recoveryPair',
          q: '아동은 매우 심하게 화가 나거나 괴로울 때',
          self: '어떻게 스스로 회복하는가?',
          partner: '파트너가 어떻게 도움을 줄 때 회복되는가?',
        },
      ],
    },
    {
      key: 'ts',
      title: '교류 지원',
      questions: [
        { id: 'lp_ts_1', type: 'text', q: '아동이 정기적으로 상호작용을 하거나 일상적으로 만나는 사람은 누구인가?' },
        { id: 'lp_ts_2', type: 'text', q: '아동이 정기적으로 가는 장소는 어디인가?' },
        {
          id: 'lp_ts_3', type: 'scale02List',
          q: '다음 중 쉽게 파악하거나 따르거나 반응할 수 있는 것 (0/1/2)',
          items: [
            '아동이 관심을 갖는 대상', '아동이 의사소통하려고 하는 것',
            '아동의 감정 상태', '아동이 선호하는 속도(빠름 또는 느림)',
            '아동에게 휴식이 필요할 때', '아동이 흥미를 보이는지 여부',
            '아동이 좌절했는지 여부', '아동이 흥분했는지 여부',
          ],
        },
        { id: 'lp_ts_4', type: 'text', q: '아동이 의사소통을 시작하도록 격려하는 데에 가장 도움이 되는 전략은 무엇인가?' },
        { id: 'lp_ts_5', type: 'text', q: '문제행동을 보일 때 보통 어떻게 반응하는가? 그러한 반응이 효과적인가?' },
        { id: 'lp_ts_6', type: 'text', q: '아동의 주의를 끄는 데에 가장 도움이 되는 전략은 무엇인가?' },
        { id: 'lp_ts_7', type: 'text', q: '아동과의 상호작용을 유지하는 데에 가장 도움이 되는 전략은 무엇인가?' },
        { id: 'lp_ts_8', type: 'text', q: '아동에게 전달한 메시지를 이해했는지 확인하기 위해서 아동에게 주로 어떻게 의사소통을 하는가?' },
        { id: 'lp_ts_9', type: 'text', q: '시각적 지원을 사용하는가? 만일 그렇다면, 어떤 지원을 사용하는가?' },
        { id: 'lp_ts_10', type: 'text', q: '아동이 참여를 유지하는 데 도움이 되는 물리적 또는 사회적 환경 특성은 무엇인가?' },
        { id: 'lp_ts_11', type: 'text', q: '아동이 의사소통을 더 잘 하도록 돕는 물리적 또는 사회적 환경 특성은 무엇인가?' },
      ],
    },
    { ...SP_INTERVIEW.sections[3], questions: SP_INTERVIEW.sections[3].questions.map((q) => ({ ...q, id: q.id.replace('sp_', 'lp_') })) },
  ],
};

// =====================================================================
// 대화 파트너 단계 질문지
// =====================================================================
const CP_INTERVIEW = {
  stage: 'conversation',
  intro: SP_INTERVIEW.intro,
  meta: SP_INTERVIEW.meta,
  sections: [
    {
      key: 'social',
      title: '사회 의사소통',
      questions: [
        { id: 'cp_sc_1', type: 'text', q: '다른 사람과 어떻게 상호작용하는지 기술하시오. 청자/화자 역할을 바꾸며 대화를 주고받는가?' },
        { id: 'cp_sc_2', type: 'text', q: '상호작용 중 시선/얼굴표정/몸짓을 어떻게 사용하는지 기술하시오.' },
        {
          id: 'cp_sc_3', type: 'checklist',
          q: '다음 중 아동이 일관성 있게 사용하는 의사소통 기능을 모두 표시하시오.',
          options: [
            '원하는 것 요구하기', '도움 청하기', '거절/거부하기',
            '인사하기', '허락 구하기', '경험 공유하기',
            '관심 끌기', '정보 요구하기', '정보 제공하기',
            '감정 표현하기', '의견 또는 생각 공유하기', '농담/유머 사용하기',
          ],
        },
        {
          id: 'cp_sc_4', type: 'checklist',
          q: '다음 중 아동이 일관성 있게 사용하는 언어 형태를 모두 표시하시오.',
          options: [
            '단일 명사', '동사', '서술어/형용사', '대명사',
            '시제(현재, 과거, 미래)', '단어 조합(2~3어 조합)',
            '간단한 문장(주어+동사+목적어)', '복문(접속사 사용)',
            '의문문', '부정문',
          ],
          withText: [
            { id: 'time', label: '시간을 나타내는 단어(예: 전에, 지금, 나중에, 언제)' },
            { id: 'place', label: '장소를 나타내는 단어' },
            { id: 'attribute', label: '속성/수식 단어' },
          ],
        },
        {
          id: 'cp_sc_5', type: 'frequency',
          q: '상호작용할 때 얼마나 자주 의사소통/대화를 시작하는가?',
          partners: ['친숙한 성인과 함께', '친숙한 또래와 함께', '친숙하지 않은 사람과 함께', '소집단 내에서', '대집단 내에서'],
        },
        { id: 'cp_sc_6', type: 'text', q: '대화가 잘못되거나 의사소통이 실패할 때 아동은 어떻게 행동하는가? 명료화를 요구하는가?' },
        { id: 'cp_sc_7', type: 'text', q: '관심 있는 주제나 대화 시 주제를 어떻게 유지하는가? 한 주제에 머무는 시간은 얼마나 되는가?' },
        { id: 'cp_sc_8', type: 'text', q: '또래와의 우정 관계를 어떻게 맺고 유지하는가?' },
        { id: 'cp_sc_9', type: 'text', q: '유머, 농담, 비유 표현, 놀림 등을 이해하고 사용하는가?' },
        {
          id: 'cp_sc_10', type: 'checklist',
          q: '다음 중 일관성 있게 이해하는 의미나 비구어 단서에 모두 표시하시오.',
          options: [
            '얼굴 표정', '억양', '몸짓 단서',
            '청자의 지식에 따른 정보 조절', '청자의 관심에 따른 주제 조절',
            '대화 차례 주고받기 단서', '주제 전환 단서',
            '관심 초점 변화 단서',
            '유머/비유 표현의 비문자적 의미', '놀림/비꼬는 말의 비문자적 의미',
          ],
        },
      ],
    },
    {
      key: 'emo',
      title: '정서 조절',
      questions: [
        { id: 'cp_er_1', type: 'text', q: '아동은 자신의 환경 내에 있는 사람과 사물에 어떻게 반응하는가?' },
        { id: 'cp_er_2', type: 'text', q: '가장 흥미를 보이는 활동은 무엇인가?' },
        { id: 'cp_er_3', type: 'text', q: '가장 힘들어하는 활동 또는 상황은 무엇인가?' },
        { id: 'cp_er_4', type: 'text', q: '익숙한 활동에서 자기조절을 위해 사용하는 행동/언어/초인지 전략을 기술하시오.' },
        { id: 'cp_er_5', type: 'text', q: '새롭고 변화된 상황에서 사용하는 자기조절 전략을 기술하시오.' },
        {
          id: 'cp_er_6',
          type: 'emotionPairs',
          q: '구어 또는 비구어 수단으로 긍정적인 감정과 부정적인 감정을 표현하는가? 만일 그렇다면, 어떻게 표현하는가?',
          pairs: [
            ['기쁨', '슬픔'],
            ['만족감', '분노 또는 좌절'],
            ['익살스러움', '두려움'],
            ['자부심/성취감', '실망감/창피함'],
            ['놀라움', '걱정/불안'],
          ],
        },
        { id: 'cp_er_7', type: 'text', q: '단계적인 정서(예: 짜증→화남→격분)를 이해하거나 사용하는가?' },
        { id: 'cp_er_8', type: 'text', q: '자신/타인의 정서에 대한 원인을 설명하거나 이해하는가?' },
        { id: 'cp_er_9', type: 'text', q: '아동이 집중하고, 흥미를 갖고, 진정하고, 참여를 유지하도록 돕기 위해 어떤 전략을 사용하는가?' },
        { id: 'cp_er_10', type: 'text', q: '아동이 흥분하거나 화가 났다는 것을 어떻게 알 수 있는가?' },
        { id: 'cp_er_11', type: 'text', q: '갈등이나 문제 해결 상황에서 어떻게 반응하는가? 타협하거나 협력할 수 있는가?' },
        {
          id: 'cp_er_12', type: 'recoveryPair',
          q: '아동은 매우 심하게 화가 나거나 괴로울 때',
          self: '어떻게 스스로 회복하는가?',
          partner: '파트너가 어떻게 도움을 줄 때 회복되는가?',
        },
      ],
    },
    {
      key: 'ts',
      title: '교류 지원',
      questions: [
        { id: 'cp_ts_1', type: 'text', q: '아동이 정기적으로(매일 또는 매주) 상호작용을 하거나 일상적으로 만나는 사람은 누구인가?' },
        { id: 'cp_ts_2', type: 'text', q: '아동이 정기적으로(매일 또는 매주) 가는 장소는 어디인가?' },
        {
          id: 'cp_ts_3', type: 'scale02List',
          q: '다음 중 쉽게 파악하거나 따르거나 반응할 수 있는 것 (0/1/2)',
          items: [
            '아동이 관심을 갖는 대상', '아동이 의사소통하려고 하는 것',
            '아동의 감정 상태', '아동이 선호하는 속도',
            '아동에게 휴식이 필요할 때', '아동이 흥미를 보이는지 여부',
            '아동이 좌절/흥분했는지 여부', '아동의 내적 사고/정신적 계획',
          ],
        },
        { id: 'cp_ts_4', type: 'text', q: '아동이 의사소통/대화를 시작하도록 격려하는 가장 도움이 되는 전략은?' },
        { id: 'cp_ts_5', type: 'text', q: '문제행동을 보일 때 보통 어떻게 반응하는가?' },
        { id: 'cp_ts_6', type: 'text', q: '아동의 주의를 끄는 데에 가장 도움이 되는 전략은?' },
        { id: 'cp_ts_7', type: 'text', q: '아동과의 대화를 유지하는 데에 가장 도움이 되는 전략은?' },
        { id: 'cp_ts_8', type: 'text', q: '아동에게 전달한 메시지를 이해했는지 확인하기 위해 주로 어떻게 의사소통하는가?' },
        { id: 'cp_ts_9', type: 'text', q: '시각적 지원/조직화 지원을 사용하는가? 만일 그렇다면, 어떤 지원을 사용하는가?' },
        { id: 'cp_ts_10', type: 'text', q: '아동이 참여를 유지하는 데 도움이 되는 물리적 또는 사회적 환경 특성은 무엇인가(예: 아동이 상호작용하는 사람의 수 제한하기, 배경 소음 또는 시각적인 혼잡함 줄이기, 움직임이나 리듬을 위한 기회 더 많이 주기, 특정 활동을 위해 특정 장소를 일관성 있게 사용하기)?' },
        { id: 'cp_ts_11', type: 'text', q: '아동이 의사소통/대화를 더 잘 하도록 돕는 환경 특성은 무엇인가?' },
        { id: 'cp_ts_12', type: 'text', q: '또래와의 상호작용/우정 관계를 지원하기 위해 사용하는 전략은?' },
      ],
    },
    { ...SP_INTERVIEW.sections[3], questions: SP_INTERVIEW.sections[3].questions.map((q) => ({ ...q, id: q.id.replace('sp_', 'cp_') })) },
  ],
};

const INTERVIEWS = {
  social: SP_INTERVIEW,
  language: LP_INTERVIEW,
  conversation: CP_INTERVIEW,
};

// =====================================================================
// 부모용 질문지 HTML 생성 — 카톡 전송용 독립 파일
//   부모가 폰/PC 브라우저에서 작성 → "답안 복사" → 카톡으로 선생님께 →
//   선생님이 앱에 붙여넣으면 자동 채움.
// =====================================================================
function buildParentQuestionnaireHTML(stage, childName, answers) {
  const interview = INTERVIEWS[stage];
  if (!interview) return null;
  const stageLabel = stage === 'social' ? '사회적 파트너 단계'
    : stage === 'language' ? '언어 파트너 단계' : '대화 파트너 단계';

  // 질문 데이터를 안전하게 JSON 문자열로 (HTML 안에 삽입)
  const dataJson = JSON.stringify({
    stage, childName: childName || '',
    intro: interview.intro,
    answers: answers || {},
    sections: interview.sections.map((sec) => ({
      key: sec.key, title: sec.title,
      questions: sec.questions.map((q) => ({
        id: q.id, type: q.type, q: q.q,
        options: q.options || null,
        withText: q.withText || null,
        partners: q.partners || null,
      })),
    })),
  }).replace(/</g, '\\u003c').replace(/>/g, '\\u003e').replace(/&/g, '\\u0026');

  return `<!DOCTYPE html>
<html lang="ko">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SCERTS 질문지 - ${childName || '아동'}</title>
<link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Sans+KR:wght@400;500;600;700&display=swap" rel="stylesheet">
<style>
  * { box-sizing: border-box; }
  body { margin:0; font-family:'IBM Plex Sans KR',sans-serif; background:#f4efe4; color:#2a2419; line-height:1.6; }
  .wrap { max-width:760px; margin:0 auto; padding:20px 16px 120px; }
  .head { background:#2d4a3e; color:#f4efe4; padding:22px 20px; border-radius:14px; margin-bottom:18px; }
  .head h1 { margin:0 0 6px; font-size:20px; }
  .head .sub { font-size:13px; opacity:.85; }
  .intro { background:#fff7e6; border:1px solid #eecf9e; border-radius:10px; padding:14px 16px; font-size:13.5px; color:#5a4a20; margin-bottom:20px; }
  .sec-title { font-size:17px; font-weight:700; color:#2d4a3e; margin:26px 0 12px; padding-bottom:6px; border-bottom:2px solid #c19a3a; }
  .q { background:#fff; border:1px solid #e4dcc8; border-radius:10px; padding:14px 16px; margin-bottom:12px; }
  .q-text { font-size:14.5px; font-weight:500; margin-bottom:10px; }
  .q-idx { color:#c19a3a; font-weight:700; margin-right:4px; }
  textarea { width:100%; min-height:64px; padding:9px 11px; border:1px solid #d9d1bd; border-radius:8px; font-family:inherit; font-size:14px; resize:vertical; }
  .opt { display:flex; align-items:flex-start; gap:8px; padding:5px 0; font-size:14px; }
  .opt input { margin-top:4px; }
  .extra { width:100%; margin-top:4px; padding:7px 10px; border:1px solid #e0d8c4; border-radius:7px; font-size:13px; font-family:inherit; }
  .freq { width:100%; border-collapse:collapse; margin-top:6px; font-size:13px; }
  .freq th, .freq td { border:1px solid #e0d8c4; padding:7px; text-align:center; }
  .freq td:first-child { text-align:left; }
  .bar { position:fixed; bottom:0; left:0; right:0; background:#fff; border-top:1px solid #ddd; padding:14px 16px; text-align:center; box-shadow:0 -2px 12px rgba(0,0,0,.08); }
  .btn { background:#2d4a3e; color:#fff; border:none; border-radius:10px; padding:13px 26px; font-size:15px; font-weight:700; font-family:inherit; cursor:pointer; }
  .btn:active { opacity:.85; }
  .done-box { display:none; max-width:728px; margin:10px auto 0; background:#eef6ef; border:1px solid #bcdcc6; border-radius:10px; padding:14px; }
  .done-box textarea { min-height:80px; font-size:11px; color:#555; background:#fafafa; }
  .done-msg { font-size:13px; color:#2d7a4f; font-weight:600; margin-bottom:8px; }
  .name-field { background:#fff; border:1px solid #e4dcc8; border-radius:10px; padding:14px 16px; margin-bottom:18px; }
  .name-field label { font-size:13px; font-weight:600; display:block; margin-bottom:6px; }
  .name-field input { width:100%; padding:9px 11px; border:1px solid #d9d1bd; border-radius:8px; font-size:14px; font-family:inherit; }
</style>
</head>
<body>
<div class="wrap">
  <div class="head">
    <h1>SCERTS 질문지</h1>
    <div class="sub">${stageLabel}${childName ? ' · ' + childName : ''}</div>
  </div>
  <div class="intro" id="introBox"></div>
  <div class="name-field">
    <label>작성자 (성함) / 아동과의 관계</label>
    <input id="writerName" type="text" placeholder="예: 김영희 / 어머니">
  </div>
  <div id="form"></div>
</div>
<div class="bar">
  <button class="btn" onclick="finish()">✅ 작성 완료 — 답안 복사하기</button>
  <div class="done-box" id="doneBox">
    <div class="done-msg">✅ 복사됐어요! 이 내용을 카카오톡으로 선생님께 보내주세요.<br>(복사가 안 되면 아래 칸을 길게 눌러 전체 선택 후 복사하세요)</div>
    <textarea id="codeOut" readonly onclick="this.select()"></textarea>
  </div>
</div>
<script id="payload" type="application/json">${dataJson}</script>
<script>
  var DATA = JSON.parse(document.getElementById('payload').textContent);
  var ans = DATA.answers || {};
  document.getElementById('introBox').textContent = DATA.intro || '';
  document.getElementById('writerName').value = (ans.__writer || '');

  var form = document.getElementById('form');
  DATA.sections.forEach(function(sec){
    var h = document.createElement('div'); h.className='sec-title'; h.textContent=sec.title; form.appendChild(h);
    sec.questions.forEach(function(q, qi){
      var box = document.createElement('div'); box.className='q';
      var qt = document.createElement('div'); qt.className='q-text';
      qt.innerHTML = '<span class="q-idx">'+(qi+1)+'.</span> ' + escapeHtml(q.q);
      box.appendChild(qt);
      if (q.type === 'checklist') {
        (q.options||[]).forEach(function(opt){
          var lab=document.createElement('label'); lab.className='opt';
          var cb=document.createElement('input'); cb.type='checkbox'; cb.dataset.qid=q.id; cb.dataset.opt=opt;
          if (ans[q.id] && ans[q.id].checked && ans[q.id].checked[opt]) cb.checked=true;
          var sp=document.createElement('span'); sp.textContent=opt;
          lab.appendChild(cb); lab.appendChild(sp); box.appendChild(lab);
        });
        (q.withText||[]).forEach(function(wt){
          var lab=document.createElement('label'); lab.className='opt';
          var cb=document.createElement('input'); cb.type='checkbox'; cb.dataset.qid=q.id; cb.dataset.opt=wt.id;
          if (ans[q.id] && ans[q.id].checked && ans[q.id].checked[wt.id]) cb.checked=true;
          var sp=document.createElement('span'); sp.textContent=wt.label;
          lab.appendChild(cb); lab.appendChild(sp); box.appendChild(lab);
          var ex=document.createElement('input'); ex.type='text'; ex.className='extra'; ex.placeholder='구체적인 예';
          ex.dataset.qid=q.id; ex.dataset.txt=wt.id;
          if (ans[q.id] && ans[q.id].texts && ans[q.id].texts[wt.id]) ex.value=ans[q.id].texts[wt.id];
          box.appendChild(ex);
        });
      } else if (q.type === 'frequency') {
        var cols=['거의/전혀','가끔','자주'];
        var tbl=document.createElement('table'); tbl.className='freq';
        var thead='<tr><th></th>'+cols.map(function(c){return '<th>'+c+'</th>';}).join('')+'</tr>';
        var body='';
        (q.partners||[]).forEach(function(p,ri){
          body+='<tr><td>'+escapeHtml(p)+'</td>';
          cols.forEach(function(c,ci){
            var ck=(ans[q.id]&&ans[q.id][ri]===ci)?'checked':'';
            body+='<td><input type="radio" name="'+q.id+'_'+ri+'" data-qid="'+q.id+'" data-row="'+ri+'" data-col="'+ci+'" '+ck+'></td>';
          });
          body+='</tr>';
        });
        tbl.innerHTML='<thead>'+thead+'</thead><tbody>'+body+'</tbody>';
        box.appendChild(tbl);
      } else {
        // text 및 기타 모든 타입 → 자유 서술 textarea
        var ta=document.createElement('textarea'); ta.dataset.qid=q.id; ta.placeholder='여기에 답변을 입력하세요';
        if (typeof ans[q.id]==='string') ta.value=ans[q.id];
        box.appendChild(ta);
      }
      form.appendChild(box);
    });
  });

  function escapeHtml(s){ return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }

  function collect(){
    var out={};
    out.__writer=document.getElementById('writerName').value||'';
    // textarea (text 등)
    form.querySelectorAll('textarea[data-qid]').forEach(function(ta){
      if (ta.value.trim()) out[ta.dataset.qid]=ta.value;
    });
    // checklist
    form.querySelectorAll('input[type=checkbox][data-qid]').forEach(function(cb){
      if (cb.checked){ var id=cb.dataset.qid; out[id]=out[id]||{checked:{},texts:{}}; out[id].checked[cb.dataset.opt]=true; }
    });
    form.querySelectorAll('input.extra[data-qid]').forEach(function(ex){
      if (ex.value.trim()){ var id=ex.dataset.qid; out[id]=out[id]||{checked:{},texts:{}}; out[id].texts[ex.dataset.txt]=ex.value; }
    });
    // frequency
    form.querySelectorAll('input[type=radio][data-qid]:checked').forEach(function(r){
      var id=r.dataset.qid; out[id]=out[id]||{}; out[id][r.dataset.row]=parseInt(r.dataset.col,10);
    });
    return out;
  }

  function finish(){
    var payload={ v:1, stage:DATA.stage, childName:DATA.childName, answers:collect() };
    var code='SCERTS::'+btoa(unescape(encodeURIComponent(JSON.stringify(payload))));
    var box=document.getElementById('doneBox'); var out=document.getElementById('codeOut');
    out.value=code; box.style.display='block';
    try { navigator.clipboard.writeText(code); } catch(e){}
    out.focus(); out.select();
    box.scrollIntoView({behavior:'smooth'});
  }
</script>
</body>
</html>`;
}

// 부모 답안 코드를 디코딩 → { stage, childName, answers } 또는 null
function decodeParentAnswers(code) {
  try {
    var trimmed = (code || '').trim();
    var idx = trimmed.indexOf('SCERTS::');
    if (idx < 0) return null;
    var b64 = trimmed.slice(idx + 8).trim();
    var json = decodeURIComponent(escape(atob(b64)));
    var obj = JSON.parse(json);
    if (!obj || !obj.answers) return null;
    return obj;
  } catch (e) { return null; }
}


// =====================================================================
// 부모용 "링크" 방식 (로그인 없이 부모가 링크로 작성 → 자동 수집)
//   BIP Maker와 동일한 shared_store 테이블 사용 (anon 접근).
//   scerts_data(RLS 보호)와 분리 — 부모는 로그인 없이 접근하므로.
//   키 규칙: scerts::submit::{childId}::{제출id}
// =====================================================================
const SHARED_SKEY = (k) => `scerts::${k}`;

// shared_store 읽기/쓰기 (anon key 직접 사용 — 로그인 불필요)
const scertsShared = {
  async set(key, value) {
    try {
      const payload = typeof value === 'string' ? value : JSON.stringify(value);
      const r = await fetch(`${SUPABASE_URL}/rest/v1/shared_store`, {
        method: 'POST',
        headers: {
          'apikey': SUPABASE_ANON_KEY,
          'Authorization': `Bearer ${SUPABASE_ANON_KEY}`,
          'Content-Type': 'application/json',
          'Prefer': 'resolution=merge-duplicates,return=minimal',
        },
        body: JSON.stringify({ key: SHARED_SKEY(key), value: payload, updated_at: new Date().toISOString() }),
      });
      if (!r.ok) return null;
      return { value };
    } catch (e) { return null; }
  },
  async listByPrefix(prefix) {
    try {
      const like = encodeURIComponent(SHARED_SKEY(prefix) + '%');
      const url = `${SUPABASE_URL}/rest/v1/shared_store?key=like.${like}&select=key,value`;
      const r = await fetch(url, {
        headers: { 'apikey': SUPABASE_ANON_KEY, 'Authorization': `Bearer ${SUPABASE_ANON_KEY}` },
      });
      if (!r.ok) return [];
      const rows = await r.json();
      return (rows || []).map((row) => {
        let v = row.value;
        for (let i = 0; i < 2 && typeof v === 'string'; i++) {
          const s = v.trim();
          if (s && (s[0] === '{' || s[0] === '[')) { try { v = JSON.parse(s); } catch (e) { break; } } else break;
        }
        return v;
      }).filter(Boolean);
    } catch (e) { return []; }
  },
  async del(key) {
    try {
      const url = `${SUPABASE_URL}/rest/v1/shared_store?key=eq.${encodeURIComponent(SHARED_SKEY(key))}`;
      await fetch(url, {
        method: 'DELETE',
        headers: { 'apikey': SUPABASE_ANON_KEY, 'Authorization': `Bearer ${SUPABASE_ANON_KEY}` },
      });
    } catch (e) { /* ignore */ }
  },
};

// 토큰 인코딩/디코딩 — 케이스 식별 정보를 링크에 담아 서버 조회 없이 작동
//   { cid: childId, cn: 아동이름, sc: 단계(social/language/conversation) }
function encodeScertsFillToken(obj) {
  try {
    const json = JSON.stringify(obj);
    const b64 = btoa(unescape(encodeURIComponent(json)));
    return b64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  } catch (e) { return ''; }
}
function decodeScertsFillToken(token) {
  try {
    let b64 = token.replace(/-/g, '+').replace(/_/g, '/');
    while (b64.length % 4) b64 += '=';
    const json = decodeURIComponent(escape(atob(b64)));
    return JSON.parse(json);
  } catch (e) { return null; }
}

// 외부(부모) 제출 저장 — 제출 1건 = scerts::submit::{childId}::{제출id}
//   fixedSid를 넘기면 그 id로 덮어쓰기(같은 폰 재제출), 없으면 새로 생성
async function saveScertsSubmission(childId, submission, fixedSid) {
  const sid = fixedSid || `${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
  const key = `submit::${childId}::${sid}`;
  return await scertsShared.set(key, { ...submission, sid, submittedAt: new Date().toISOString() });
}
// 특정 아동의 부모 제출 목록 조회
async function listScertsSubmissions(childId) {
  const rows = await scertsShared.listByPrefix(`submit::${childId}::`);
  rows.sort((a, b) => String(b.submittedAt || '').localeCompare(String(a.submittedAt || '')));
  return rows;
}
// 제출 삭제
async function deleteScertsSubmission(childId, sid) {
  await scertsShared.del(`submit::${childId}::${sid}`);
}


// =====================================================================
// 관찰 계획을 위한 SCERTS 진단 지도
// =====================================================================
const OBSERVATION_MAP = {
  title: '관찰 계획을 위한 SCERTS 진단 지도',
  intro: '관찰 #(최소 2개 이상)을 계획하기 위한 양식입니다.',
  rows: [
    {
      id: 'place',
      label: '관찰 장소',
      note: '※ 최소 2개 이상의 자연스러운 상황 포함(예: 가정, 학교, 지역사회)',
      type: 'text',
    },
    {
      id: 'time',
      label: '관찰 시간',
      note: '※ 총 관찰 시간: 사회적 파트너 - 최소 2시간 / 언어 파트너 - 최소 2시간 / 대화 파트너 - 3∼4시간',
      type: 'datetime',
      fields: ['날짜/시간', '관찰 소요 시간'],
    },
    {
      id: 'team',
      label: '팀/파트너',
      note: '※ 최소 2개 이상의 집단 크기(일대일, 소집단, 대집단) ※ 언어 및 대화 파트너의 경우 친숙한 파트너와 친숙하지 않은 파트너 포함',
      type: 'text',
      fields: ['팀 구성원', '파트너 및 집단 크기'],
    },
    {
      id: 'activity',
      label: '활동/변인',
      note: '※ 최소 4개 변인에 따른 4개 활동',
      type: 'variants',
      variants: [
        ['1a) 구조화된', '1b) 비구조화된'],
        ['2a) 의무적인', '2b) 재미있는'],
        ['3a) 성인 주도의', '3b) 아동 주도의'],
        ['4a) 동적인', '4b) 정적인'],
        ['5a) 익숙한', '5b) 익숙하지 않은'],
        ['6a) 선호하는', '6b) 선호하지 않는'],
        ['7a) 쉬운', '7b) 어려운'],
        ['8a) 언어 중심의', '8b) 비언어적인'],
        ['9a) 사회적인', '9b) 혼자 하는'],
        ['10a) 붐비는', '10b) 차분한'],
      ],
    },
    {
      id: 'transition',
      label: '전이',
      note: '※ 활동, 환경, 장소 또는 파트너의 의미 있는 변화를 포함하는 최소 3개 이상의 전이 상황',
      type: 'list',
      count: 3,
    },
  ],
};

// =====================================================================
// SCERTS 활동 일지 I (개별 활동 기록)
// =====================================================================
const ACTIVITY_LOG_I = {
  title: 'SCERTS 활동 일지 I',
  subtitle: '활동 1회기에 대한 기록',
  fields: [
    { id: 'name', label: '이름' },
    { id: 'commStage', label: '의사소통 단계' },
    { id: 'date', label: '날짜' },
    { id: 'activity', label: '활동' },
    { id: 'team', label: '팀 구성원/파트너' },
    { id: 'setting', label: '환경/장소' },
  ],
  sections: [
    {
      title: '아동의 사회 의사소통 목표',
      type: 'goals',
      rows: 6,
      cols: ['목표', '관찰된 행동/예', '도달 여부 (-, +/-, +)'],
    },
    {
      title: '아동의 정서 조절 목표',
      type: 'goals',
      rows: 4,
      cols: ['목표', '관찰된 행동/예', '도달 여부 (-, +/-, +)'],
    },
    {
      title: '파트너의 교류 지원 목표',
      type: 'goals',
      rows: 6,
      cols: ['목표', '사용한 전략/예', '효과 (-, +/-, +)'],
    },
    {
      title: '활동 후 관찰 메모',
      type: 'text',
      placeholder: '추가 관찰 내용, 다음 회기에 반영할 사항 등',
    },
  ],
};

// =====================================================================
// SCERTS 활동 일지 II (주간 집계)
// =====================================================================
const ACTIVITY_LOG_II = {
  title: 'SCERTS 활동 일지 II',
  subtitle: '한 주 동안의 활동 종합 기록',
  fields: [
    { id: 'name', label: '이름' },
    { id: 'commStage', label: '의사소통 단계' },
    { id: 'weekOf', label: '주차/기간' },
  ],
  sections: [
    {
      title: '주간 활동 요약',
      type: 'weeklyGrid',
      rows: ['월', '화', '수', '목', '금', '토/일'],
      cols: ['활동/환경', '주요 목표', '진전/관찰'],
    },
    {
      title: '주간 진전 요약',
      type: 'text',
    },
  ],
};

// =====================================================================
// SCERTS 주간 기록지
// =====================================================================
const WEEKLY_RECORD = {
  title: 'SCERTS 주간 기록지',
  fields: [
    { id: 'name', label: '이름' },
    { id: 'commStage', label: '의사소통 단계' },
    { id: 'weekOf', label: '주차/기간' },
  ],
  sections: [
    {
      title: '주간 사회 의사소통 진전',
      type: 'text',
    },
    {
      title: '주간 정서 조절 진전',
      type: 'text',
    },
    {
      title: '주간 교류 지원 (파트너 지원 효과)',
      type: 'text',
    },
    {
      title: '다음 주 조정 사항',
      type: 'text',
    },
  ],
};

// =====================================================================
// SCERTS 활동 계획서
// =====================================================================
const ACTIVITY_PLAN = {
  title: 'SCERTS 활동 계획서',
  fields: [
    { id: 'name', label: '이름' },
    { id: 'date', label: '계획 날짜' },
    { id: 'planner', label: '작성자' },
    { id: 'commStage', label: '의사소통 단계' },
  ],
  sections: [
    {
      title: '활동 정보',
      type: 'gridFields',
      items: [
        { id: 'activityName', label: '활동명' },
        { id: 'duration', label: '소요 시간' },
        { id: 'setting', label: '장소/환경' },
        { id: 'team', label: '팀/파트너' },
        { id: 'materials', label: '준비물/교재' },
        { id: 'variant', label: '활동 변인 (구조화/주도성/감각 등)' },
      ],
    },
    {
      title: '활동 단계 및 흐름',
      type: 'steps',
      placeholder: '단계별 흐름을 순서대로 기재 (시작 → 본 활동 → 마무리)',
    },
    {
      title: '아동 목표 (사회 의사소통)',
      type: 'goalList',
      count: 4,
    },
    {
      title: '아동 목표 (정서 조절)',
      type: 'goalList',
      count: 3,
    },
    {
      title: '파트너 교류 지원 전략',
      type: 'goalList',
      count: 4,
    },
    {
      title: '예상되는 어려움 및 대응 전략',
      type: 'text',
    },
  ],
};




// =====================================================================
// SCERTS 자동화 프로그램 (검단ABA언어행동연구소)
// Tabs: 단계 결정 → 진단 → IEP → 중간보고서 → 보관함
// 자동 저장(localStorage) + JSON export/import
// =====================================================================

const LS_KEY = 'scerts_workspace_v1';
const LS_ARCHIVE = 'scerts_archive_v1';
const LS_STATE = 'scerts_state_v2';  // 다중 아동 통합 상태
const LS_BACKUPS = 'scerts_backups_v1';  // 회전 백업 슬롯
const LS_TEMPLATES = 'scerts_templates_v1';  // 회기 템플릿 (전역, 모든 아동 공유)
const MAX_BACKUPS = 10;

// 회기 템플릿 로드/저장
function loadTemplates() {
  try {
    const raw = localStorage.getItem(LS_TEMPLATES);
    return raw ? JSON.parse(raw) : [];
  } catch (e) { return []; }
}
function saveTemplates(list) {
  try {
    localStorage.setItem(LS_TEMPLATES, JSON.stringify(list));
  } catch (e) {}
}
const BACKUP_INTERVAL_MS = 5 * 60 * 1000;  // 5분 이상 간격으로만 백업

// 회전 백업 저장 (마지막 백업 후 5분 지난 경우만)
function saveBackup(state) {
  try {
    const raw = localStorage.getItem(LS_BACKUPS);
    const list = raw ? JSON.parse(raw) : [];
    const now = Date.now();
    // 마지막 백업이 너무 최근이면 스킵
    if (list.length > 0 && (now - list[0].timestamp) < BACKUP_INTERVAL_MS) return;

    const backup = {
      id: 'bk_' + now,
      timestamp: now,
      savedAt: new Date(now).toISOString(),
      childCount: state.children?.length || 0,
      activeChildName: state.children?.find((c) => c.id === state.activeChildId)?.meta?.childName || '',
      data: JSON.stringify(state),
    };
    list.unshift(backup);
    while (list.length > MAX_BACKUPS) list.pop();
    localStorage.setItem(LS_BACKUPS, JSON.stringify(list));
  } catch (e) {}
}

function loadBackups() {
  try {
    const raw = localStorage.getItem(LS_BACKUPS);
    return raw ? JSON.parse(raw) : [];
  } catch (e) {
    return [];
  }
}

function removeBackup(id) {
  try {
    const raw = localStorage.getItem(LS_BACKUPS);
    if (!raw) return;
    const list = JSON.parse(raw).filter((b) => b.id !== id);
    localStorage.setItem(LS_BACKUPS, JSON.stringify(list));
  } catch (e) {}
}

// 빈 진단 세션 (분기별 채점 기록)
const blankSession = (label = '', quarter = 1) => ({
  id: 's_' + Date.now() + '_' + Math.random().toString(36).slice(2, 6),
  label: label || `${new Date().getFullYear()}-${quarter}Q`,
  date: new Date().toISOString().slice(0, 10),
  quarter,
  scores: {},
  ses: {},
  notes: '',
  designation: null,  // 'pre' | 'post' | null
});

// 빈 진단 데이터 초기화 (legacy 호환)
const blankAssessment = () => ({
  quarter: 1,                  // 분기 1~4
  scores: {},                  // {itemId: 0|1|2}
  ses: {},                     // {indicatorId: 0~10}
  notes: '',
});

// 빈 아동 데이터
const blankChild = (name = '') => {
  const firstSession = blankSession('초기 진단', 1);
  return {
    id: 'c_' + Date.now() + '_' + Math.random().toString(36).slice(2, 6),
    meta: {
      childName: name,
      birthDate: '',
      className: 'SCERTS 프로그램',
      therapist: '민 다 혜',
      startDate: '',
      reportDate: new Date().toISOString().slice(0, 10),
      stage: null,
    },
    decision: { q1: {}, q2: {} },
    interview: {
      meta: { name: name, age: '', date: '', reporter: '', relation: '' },
      answers: {},
    },
    observation: {
      plans: [{ id: 1 }, { id: 2 }],
      data: {},
    },
    sessions: [firstSession],
    activeSessionId: firstSession.id,
    familyPriorities: {
      profileAccurate: '',
      additionalInfo: '',
      focusOne: '',
      focusGoalIds: [],
      threeMonthHope: '',
    },
    iep: {
      reportDate: '',  // 보고서별 작성일 (비우면 홈 작성일 사용)
      annualGoals: { sc: '', er: '', ts: '' },
      shortGoals:  { sc: '', er: '', ts: '' },
      strategies:  { sc: '', er: '', ts: '' },
      measures:    { sc: '', er: '', ts: '' },
      currentLevel:{ sc: '', er: '', ts: '' },
      selectedGoals: [],
      partnerGoals: [],
    },
    interim: {
      reportType: 'interim',   // 'interim'(중간) | 'closing'(종결)
      reportDate: '',          // 보고서별 작성일 (비우면 홈 작성일 사용)
      period: '',
      summary: '',
      domainSummary: {},
      observations: '',
      direction: '',
      closingReason: '',       // 종결 모드: 종결 사유
      closingReasonDetail: '', // 종결 모드: 사유 상세
      goalAchievement: [],     // 종결 모드: 목표 달성도 [{goal,status,note}]
      recommendation: '',      // 종결 모드: 향후 권고
      familySuggestions: [
        '가정 내 감정 단어 노출 및 대화 확장 연습',
        '시각적 예고 및 감정 온도계 활용한 자기조절 지원',
        '질문 응답, 이야기 이어 말하기 활동을 통한 언어 사고력 자극',
      ],
    },
    closing: {
      period: '',           // 치료 시작~종결 기간
      reason: '',           // 종결 사유 (선택지에서)
      reasonDetail: '',     // 종결 사유 상세
      overallProgress: '',  // 사전→사후 종합 성과 서술
      domainProgress: {},   // 영역별(SC/ER/TS) 성과 { sc:{pre,post,note}, ... }
      goalAchievement: [],  // 목표 달성도 [{ goal, status, note }]
      summary: '',          // 종합 소견
      recommendation: '',   // 향후 권고 (전이 지원)
    },
    activities: {
      logI: [],
      logII: { weekOf: '', daily: {}, summary: '', social: '', emo: '', ts: '', adjust: '' },
      weekly: { weekOf: '', social: '', emo: '', ts: '', adjust: '' },
      plan: { fields: {}, steps: '', goalsSocial: [], goalsEmo: [], partnerGoals: [], challenges: '' },
    },
    familySupport: {
      meta: { weekOf: '', meetingDate: '', participants: '' },
      currentConcerns: '',
      childStrengths: '',
      familyGoals: ['', '', ''],
      homeStrategies: [
        { area: '의사소통', strategy: '', whenToUse: '', resourcesNeeded: '' },
        { area: '정서 조절', strategy: '', whenToUse: '', resourcesNeeded: '' },
        { area: '일상 활동', strategy: '', whenToUse: '', resourcesNeeded: '' },
      ],
      educationTopics: [],
      followUp: '',
      nextMeeting: '',
    },
    profSupport: {
      meta: { weekOf: '', meetingDate: '', teamMembers: '' },
      sharedObservations: '',
      currentChallenges: '',
      collaborativeGoals: ['', '', ''],
      roleResponsibilities: [
        { role: '주 치료사', name: '', responsibilities: '' },
        { role: '담임 교사', name: '', responsibilities: '' },
        { role: '부모', name: '', responsibilities: '' },
      ],
      communicationPlan: '',
      caseConferenceNotes: '',
      nextReview: '',
    },
    communicationSchedule: {
      meta: { observedBy: '', observedAt: '', setting: '' },
      activities: [
        // 기본 일과 템플릿 - 임상가가 자유 편집
        { id: 'a_arrival', time: '08:30-09:00', name: '등원', opportunities: '', currentBehavior: '', supports: '', goals: '' },
        { id: 'a_circle', time: '09:00-09:30', name: '오전 모임', opportunities: '', currentBehavior: '', supports: '', goals: '' },
        { id: 'a_free', time: '09:30-10:30', name: '자유 놀이', opportunities: '', currentBehavior: '', supports: '', goals: '' },
        { id: 'a_snack', time: '10:30-11:00', name: '간식', opportunities: '', currentBehavior: '', supports: '', goals: '' },
        { id: 'a_outdoor', time: '11:00-12:00', name: '실외 활동', opportunities: '', currentBehavior: '', supports: '', goals: '' },
        { id: 'a_lunch', time: '12:00-13:00', name: '점심 / 휴식', opportunities: '', currentBehavior: '', supports: '', goals: '' },
        { id: 'a_dismiss', time: '13:00-13:30', name: '하원 준비', opportunities: '', currentBehavior: '', supports: '', goals: '' },
      ],
      summary: '',
      keyOpportunities: '',
    },
    fba: {
      meta: { observedBy: '', observedAt: '', setting: '' },
      behavior: {
        operationalDefinition: '',
        intensity: '',  // 1-5 강도
        frequency: '',  // 빈도
        duration: '',   // 지속시간
        impact: '',     // 영향
      },
      abc: [
        // ABC 사례 (최소 3개 사례 권장)
        { id: 'abc1', date: '', setting: '', antecedent: '', behavior: '', consequence: '', notes: '' },
        { id: 'abc2', date: '', setting: '', antecedent: '', behavior: '', consequence: '', notes: '' },
        { id: 'abc3', date: '', setting: '', antecedent: '', behavior: '', consequence: '', notes: '' },
      ],
      functions: {
        // 행동의 기능 (4가지 주요 기능 + 정서조절)
        escape: false,        // 회피
        attention: false,     // 관심 얻기
        tangible: false,      // 사물 얻기
        sensory: false,       // 감각 자극
        regulation: false,    // 정서 조절
        communication: false, // 의사소통 대체
        notes: '',
      },
      emotionalContext: {
        arousalLevel: '',    // 각성 수준 (낮음/적정/높음)
        triggers: '',        // 트리거
        protectiveFactors: '', // 보호 요인
      },
      replacement: {
        replacementBehavior: '',  // 대체 행동
        teachingStrategy: '',     // 교수 전략
        reinforcement: '',        // 강화 계획
        environmentalChanges: '', // 환경 변경
      },
      preventionPlan: '',
      crisisPlan: '',
      monitoringPlan: '',
    },
  };
};

// =====================================================================
// 샘플 아동 — 기능 확인용 (민준호, 언어 파트너 단계, 모든 데이터 채움)
// =====================================================================
function makeSampleChild() {
  const c = blankChild('민준호');
  c.meta.birthDate = '2022-04-15';
  c.meta.startDate = '2026-01-10';
  c.meta.stage = 'language';
  c.meta.className = 'SCERTS 프로그램 햇살반';

  // 1) 단계 결정 (언어 파트너로 귀결되는 응답)
  c.decision = {
    q1: { a1: true, a2: true, a3: true },
    q2: { b1: true, b2: true },
  };

  // 2) 질문지(보호자 면담) — 모든 문항 빠짐없이 채움
  c.interview.meta = { name: '민준호', age: '만 4세 1개월', date: '2026-01-12', reporter: '김영희', relation: '어머니' };
  c.interview.answers = {
    // ── 사회 의사소통 ──
    lp_sc_1: '눈맞춤은 잘하고 원하는 것을 단어로 표현하지만, 먼저 대화를 시작하는 일은 드뭅니다. 친숙한 사람과는 적극적으로 상호작용합니다.',
    lp_sc_2: '원하는 것이 있을 때 사람과 사물을 번갈아 쳐다보며, 이름을 부르면 눈을 맞춥니다.',
    lp_sc_3: { checked: { '물건 보여 주기': true, '멀리 있는 것 가리키기': true, '고개 젓기(거절 또는 거부하기 위해)': true, '고개 끄덕이기(수용하거나 \'예\'라고 표현하기 위해)': true }, texts: {} },
    lp_sc_4: { checked: { '사물의 이름(예: 놀잇감, 음식, 신체부위)': true, '사람이나 애완동물의 이름': true, '"더" 또는 "또"의 의미를 나타내는 방법': true, '인사말(예: "안녕" "바이바이" "또 만나")': true }, texts: {} },
    lp_sc_5: { checked: { '원하는 물건을 요구하거나 도움 청하기': true, '원하지 않는 것 거절하기': true, '인사하기': true, '다른 사람이 알아주기를 원하는 무엇인가로 그 사람의 관심 끌기': true }, texts: {} },
    lp_sc_6: { 0: 2, 1: 1, 2: 1 }, // 친숙한 사람과 자주, 친숙하지 않은/소집단은 가끔
    lp_sc_7: '요구를 알아채지 못하면 같은 단어를 더 크게 반복하거나, 손을 잡아끌어 원하는 것으로 데려갑니다.',
    lp_sc_8: '블록과 자동차를 가장 좋아합니다. 블록은 높이 쌓았다가 무너뜨리기를 반복하고, 자동차는 일렬로 줄 세우기를 즐깁니다.',
    lp_sc_9: '친숙한 어른이 끼어들면 잘 받아들이고 함께 놀지만, 또래가 끼어들면 처음엔 경계하다가 점차 곁을 내어줍니다.',
    lp_sc_10: { checked: { '가리키기': true, '얼굴 표정': true, '아동의 이름': true, '한 단어로 된 지시': true, '두 단어 이상의 지시': true }, texts: { verb: '"빨리", "크게" 등 익숙한 수식어는 이해함', phrase: '"신발 신고 나가자" 같은 익숙한 구는 이해함' } },
    // ── 정서 조절 ──
    lp_er_1: '관심 있는 사물에는 적극적으로 다가가 탐색하고, 사람에 대해서는 친숙도에 따라 반응 차이가 큽니다.',
    lp_er_2: '블록 쌓기, 자동차 놀이, 그림책 보기',
    lp_er_3: '놀이를 끝내고 다른 활동으로 바꿀 때, 시끄럽고 사람이 많은 환경',
    lp_er_4: '좋아하는 자동차를 손에 쥐고 있으면 안정되며, "끝나면 또 할 거야"라고 말해주면 기다립니다.',
    lp_er_5: '새로운 장소에서는 엄마 손을 꼭 잡고, 익숙한 노래를 흥얼거리며 진정하려 합니다.',
    lp_er_6: { '기쁨': '활짝 웃고 손뼉을 치며 폴짝 뜀', '슬픔': '입을 삐죽이고 고개를 숙임', '만족감': '"좋아"라고 말하며 미소', '분노 또는 좌절': '소리를 지르거나 물건을 밀침', '익살스러움': '일부러 웃긴 표정을 짓고 까르르 웃음', '두려움': '몸이 굳고 엄마에게 안김' },
    lp_er_7: '위로해 주면 처음엔 밀어내다가 곧 안기며 진정합니다.',
    lp_er_8: '두 가지 중 선택하라고 하면 원하는 쪽을 손가락으로 가리키거나 단어로 답합니다.',
    lp_er_9: '좋아하는 자동차 장난감을 주거나, 안아서 토닥여주면 진정합니다. 시각 일정표도 효과적입니다.',
    lp_er_10: '얼굴이 빨개지고 목소리가 커지며, 발을 구르거나 물건을 던지려 합니다.',
    lp_er_11: '시선이 다른 곳을 향하고 몸을 비틀거나 자리를 뜨려 합니다.',
    lp_er_12: { self: '잠시 혼자 좋아하는 장난감을 만지작거리며 스스로 가라앉히려 함', partner: '조용한 곳으로 데려가 안아주고 감정을 말로 짚어주면 회복됨' },
    // ── 교류 지원 ──
    lp_ts_1: '엄마, 아빠, 할머니, 어린이집 담임 선생님, 치료실 선생님',
    lp_ts_2: '집, 어린이집, 치료실, 주말에 가는 할머니 댁과 놀이터',
    lp_ts_3: { '아동이 관심을 갖는 대상': 2, '아동이 의사소통하려고 하는 것': 1, '아동의 감정 상태': 2, '아동이 선호하는 속도(빠름 또는 느림)': 1, '아동에게 휴식이 필요할 때': 1, '아동이 흥미를 보이는지 여부': 2, '아동이 좌절했는지 여부': 2, '아동이 흥분했는지 여부': 1 },
    lp_ts_4: '아동이 좋아하는 활동을 잠시 멈추고 기다려 주면, 스스로 "더"라고 요구하며 의사소통을 시작합니다.',
    lp_ts_5: '문제행동을 보이면 감정을 말로 대신 표현해 주고 차분히 기다립니다. 대체로 효과적입니다.',
    lp_ts_6: '이름을 부른 뒤 좋아하는 사물을 눈높이에서 보여주면 주의를 잘 끕니다.',
    lp_ts_7: '아동의 놀이를 따라 하며 함께 하면 상호작용이 오래 유지됩니다.',
    lp_ts_8: '짧고 명확한 단어와 몸짓, 그림 카드를 함께 사용해 전달합니다.',
    lp_ts_9: '네, 그림 일정표와 선택판(PECS 유사)을 사용합니다.',
    lp_ts_10: '조용하고 정돈된 공간, 익숙한 사람이 곁에 있을 때 참여가 잘 유지됩니다.',
    lp_ts_11: '시각 자료가 함께 제시되고, 한 번에 한 가지 지시가 주어질 때 의사소통이 더 잘 됩니다.',
  };

  // 3) 진단 — 사전 세션 + 사후 세션 (진전 보이게)
  const preScores = {
    'JA1.1':1,'JA1.2':1,'JA1.3':1,'JA2.1':1,'JA2.2':1,'JA2.3':1,'JA2.4':0,
    'JA3.1':1,'JA3.2':1,'JA4.1':2,'JA4.2':1,'JA4.3':1,'JA5.1':1,'JA5.2':1,'JA5.3':1,'JA5.4':1,
    'SU1.1':1,'SU1.2':1,'SU1.3':0,'SU2.1':1,'SU2.2':1,'SU3.1':0,'SU3.2':0,'SU4.1':1,'SU5.1':0,'SU5.2':0,'SU6.1':1,
    'MR1.1':1,'MR1.2':1,'MR2.1':1,'MR2.3':1,'MR3.1':0,'MR3.2':0,
    'SR1.1':1,'SR2.1':0,'SR3.1':0,'SR4.1':0,
    'IS1.1':2,'IS2.1':1,'IS6.1':1,'IS7.1':1,'LS1.1':1,'LS2.1':1,'LS3.1':1,'LS4.1':1,
  };
  const postScores = {
    'JA1.1':2,'JA1.2':2,'JA1.3':1,'JA2.1':2,'JA2.2':1,'JA2.3':1,'JA2.4':1,
    'JA3.1':2,'JA3.2':1,'JA4.1':2,'JA4.2':2,'JA4.3':1,'JA5.1':2,'JA5.2':1,'JA5.3':2,'JA5.4':1,
    'SU1.1':2,'SU1.2':1,'SU1.3':1,'SU2.1':2,'SU2.2':1,'SU3.1':1,'SU3.2':1,'SU4.1':2,'SU5.1':1,'SU5.2':1,'SU6.1':2,
    'MR1.1':2,'MR1.2':1,'MR2.1':1,'MR2.3':2,'MR3.1':1,'MR3.2':1,
    'SR1.1':1,'SR2.1':1,'SR3.1':1,'SR4.1':1,
    'IS1.1':2,'IS2.1':2,'IS6.1':1,'IS7.1':2,'LS1.1':2,'LS2.1':1,'LS3.1':2,'LS4.1':1,
  };
  const preSes = { happiness: 7, selfAwareness: 5, otherAwareness: 5, independence: 4, belonging: 4 };
  const postSes = { happiness: 8, selfAwareness: 7, otherAwareness: 6, independence: 6, belonging: 6 };

  const preSession = {
    id: 's_sample_pre', label: '사전 진단 (1월)', date: '2026-01-15', quarter: 1,
    scores: preScores, ses: preSes, notes: '치료 시작 시점 기초선 평가', designation: 'pre',
  };
  const postSession = {
    id: 's_sample_post', label: '사후 진단 (5월)', date: '2026-05-15', quarter: 2,
    scores: postScores, ses: postSes, notes: '1차 중재 후 재평가', designation: 'post',
  };
  c.sessions = [preSession, postSession];
  c.activeSessionId = postSession.id;

  // 4) 가족 우선순위
  c.familyPriorities = {
    profileAccurate: 'yes',
    additionalInfo: '가정에서도 단어 표현이 늘고 있으며, 또래에 대한 관심이 생기기 시작했습니다.',
    focusOne: '또래와의 상호작용 시작하기',
    focusGoalIds: [],
    threeMonthHope: '친구들과 어울려 놀고, 자기 기분을 말로 표현하기',
  };

  // 5) 활동 일지 (회기 기록)
  c.activities.logI = [
    { id: 'log1', date: '2026-03-12', fields: { activity: '블록 쌓기 놀이' },
      goalsSocial: [{ goal: '차례 주고받기', observed: '블록을 가리키며 "더 줘"라고 요청', rating: '독립 수행' }],
      goalsEmo: [], notes: '활동 시작 시 집중도가 높았고 차례 주고받기 3회 성공' },
    { id: 'log2', date: '2026-03-19', fields: { activity: '그림책 함께 보기' },
      goalsSocial: [{ goal: '사물 명명', observed: '그림을 보고 "강아지", "공"이라고 명명', rating: '부분 보조' }],
      goalsEmo: [{ goal: '기다리기', observed: '책장을 넘기고 싶을 때 떼쓰지 않고 기다림', rating: '언어 촉진' }],
      notes: '' },
    { id: 'log3', date: '2026-03-26', fields: { activity: '자동차 역할놀이' },
      goalsSocial: [],
      goalsEmo: [{ goal: '진정하기', observed: '자동차를 뺏기자 화났지만 교사가 감정을 말로 짚어주자 진정', rating: '파트너 도움' }],
      notes: '전환 시점에 시각 일정표 제시하니 저항이 줄어듦' },
  ];

  // 8) 가족 지원 계획서 (SCERTS 권장)
  c.familySupport = {
    meta: { weekOf: '2026-02', meetingDate: '2026-02-08', participants: '어머니, 아버지, 민다혜 (BCBA)' },
    currentConcerns: '가정에서도 단어 표현이 늘었지만, 또래와의 상호작용에서 먼저 다가가지 못해 부모님이 걱정하고 계심. 형제(누나)와의 놀이 갈등 상황에서 떼쓰기·울음으로 표현하는 경우가 잦음.',
    childStrengths: '눈맞춤이 좋고 친숙한 어른과의 상호작용을 즐김. 좋아하는 활동(블록, 자동차)에서 집중력이 높고, 새로운 단어를 듣고 모방하려는 시도가 늘어남.',
    familyGoals: [
      '식사 시간과 책 읽기 시간에 의사소통 기회 5회 이상 만들기',
      '전이 상황(놀이→정리 등)에서 시각 일정표 일관되게 사용하기',
      '주말에 또래와 만나는 기회 주 1회 만들기 (놀이터, 친척 집)',
    ],
    homeStrategies: [
      { area: '의사소통', strategy: '준호가 원하는 것을 바로 주지 않고 잠시 기다려 단어 요청을 유도', whenToUse: '간식·놀이·외출 준비 시', resourcesNeeded: '좋아하는 사물·간식을 시야에 두기' },
      { area: '정서 조절', strategy: '좌절 시 부모가 감정을 먼저 언어로 짚어주고("화났구나") 진정 후 대안 제시', whenToUse: '장난감 갈등, 전이 거부 상황', resourcesNeeded: '감정 카드(기쁨/슬픔/화남), 좋아하는 진정 사물' },
      { area: '일상 활동', strategy: '하루 일과를 그림 일정표로 미리 보여주고, 활동 전환 5분 전 예고', whenToUse: '아침 등원·하원·취침 전', resourcesNeeded: '그림 일정표, 타이머' },
    ],
    educationTopics: [
      { topic: 'SCERTS 언어 파트너 단계 이해', notes: '책 「우리 아이의 언어 발달」 챕터 3-4 안내함' },
      { topic: '시각 일정표 가정 사용법', notes: '시범 영상 제공 + 다음 미팅에 실제 사용 사례 공유' },
    ],
    followUp: '2주 후 가정 영상(놀이 5분, 식사 5분) 공유 받아 전략 적용도 점검 예정.',
    nextMeeting: '2026-02-22',
  };

  // 9) 전문가 지원 계획서 (팀 협력)
  c.profSupport = {
    meta: { weekOf: '2026-02', meetingDate: '2026-02-10', teamMembers: '민다혜(BCBA), 김OO(어린이집 담임), 이OO(언어치료사), 부모' },
    sharedObservations: '치료실에서는 차례 주고받기가 3회 이상 유지되나, 어린이집 소집단에서는 1-2회에 그침. 어린이집에서는 또래 주도 활동에서 위축되는 경향. 가정에서는 단어 표현이 매주 늘고 있음.',
    currentChallenges: '환경 간 일관성 부족(치료실에서 되는 행동이 어린이집에선 안 됨). 어린이집 일과 안에서 의사소통 기회 활용이 제한적임.',
    collaborativeGoals: [
      '치료실·어린이집·가정 세 환경에서 동일한 시각 지원 자료 사용',
      '어린이집 소집단 활동 중 준호의 차례 주고받기 기회 일 3회 이상 확보',
      '월 1회 팀 회의로 전략·진전 공유 및 조정',
    ],
    roleResponsibilities: [
      { role: '주 치료사', name: '민다혜 (BCBA)', responsibilities: '진단·IEP 수립, 월간 진전 분석, 팀 회의 주관, 부모 코칭' },
      { role: '담임 교사', name: '김OO (어린이집)', responsibilities: '일과 중 의사소통 기회 제공, 시각 일정표 일관 사용, 또래 매개 전략 적용' },
      { role: '부모', name: '김영희 (어머니)', responsibilities: '가정 전략 실행, 주 1회 영상 기록, 월간 가족 미팅 참여' },
    ],
    communicationPlan: '주 1회 알림장으로 환경별 관찰 공유, 카카오톡 그룹방 운영(긴급 사안). 월 1회 정기 회의(2시간).',
    caseConferenceNotes: '2026-02-10 회의 결정사항: ① 시각 일정표 어린이집 도입 ② 또래 매개 활동 주 2회 시도 ③ 다음 회의 시 영상 사례 공유.',
    nextReview: '2026-03-10',
  };

  // 10) 의사소통 일정표 (일과 분석)
  c.communicationSchedule = {
    meta: { observedBy: '민다혜', observedAt: '2026-02-15', setting: '어린이집 일과 + 가정 일과' },
    activities: [
      { id: 'a_arrival', time: '08:30-09:00', name: '등원', opportunities: '인사하기, 신발/외투 도움 요청', currentBehavior: '시선 회피, 비언어적 인사', supports: '"안녕" 시범 + 5초 대기, 신발 잠시 도와주지 않고 기다려 도움 요청 유도', goals: '먼저 "안녕" 단어 인사 1일 1회 이상' },
      { id: 'a_circle', time: '09:00-09:30', name: '오전 모임', opportunities: '이름 부르면 반응, 노래 함께 부르기', currentBehavior: '이름 호명에 시선 맞춤, 노래 일부 따라함', supports: '준호 좋아하는 노래로 시작, 짧고 익숙한 후렴 강조', goals: '모임 중 자발적 발화 2회 이상' },
      { id: 'a_free', time: '09:30-10:30', name: '자유 놀이', opportunities: '장난감 요청, 또래에게 보여주기, 차례 주고받기', currentBehavior: '혼자 블록 놀이 선호, 또래 접근 시 위축', supports: '관심 있는 또래 옆에 자리 배치, "같이 하자" 시범', goals: '또래와 차례 주고받기 3회 이상' },
      { id: 'a_snack', time: '10:30-11:00', name: '간식', opportunities: '간식 요청, 더 달라 표현, 친구에게 권하기', currentBehavior: '"더"는 가능, 친구에게 권하기는 어려움', supports: '간식을 작게 나눠 여러 번 요청 기회 제공', goals: '간식 요청 자발 발화 3회 이상' },
      { id: 'a_outdoor', time: '11:00-12:00', name: '실외 활동', opportunities: '미끄럼틀 차례 기다리기, 그네 밀어달라 요청', currentBehavior: '좋아하는 활동(미끄럼틀)에서 적극적', supports: '"밀어줘" 시범 후 기다려 요청 유도', goals: '실외 활동 중 요청 발화 5회 이상' },
      { id: 'a_lunch', time: '12:00-13:00', name: '점심 / 휴식', opportunities: '음식 선호 표현, 식사 도움 요청', currentBehavior: '편식 경향, 거부 시 밀어내기', supports: '두 가지 선택 제공("밥? 국?"), 거부도 단어로 표현 유도', goals: '음식 선택 표현 식사당 2회 이상' },
      { id: 'a_dismiss', time: '13:00-13:30', name: '하원 준비', opportunities: '"엄마" 호명, "안녕" 인사, 가방 정리 도움 요청', currentBehavior: '엄마 보면 환하게 웃음, "엄마" 단어 사용', supports: '하원 5분 전 시각 예고, 인사 시범', goals: '선생님·친구에게 "안녕" 자발 인사 1일 1회 이상' },
    ],
    summary: '준호는 익숙하고 좋아하는 활동(자유 놀이, 실외, 하원)에서 의사소통 빈도가 높고, 새로운 사회적 상황(오전 모임, 점심)에서 위축되는 경향을 보임. 환경별 강점 활동을 의사소통 학습 기회로 활용하고, 어려운 상황엔 시각 지원과 짧은 대기 시간을 추가하는 전략이 효과적임.',
    keyOpportunities: '① 등원·하원 인사 ② 자유 놀이 차례 주고받기 ③ 간식·실외 활동 요청 표현 — 일관성 있게 모든 환경(가정·치료실·어린이집)에서 동일 전략 적용 권장.',
  };

  // 11) 행동 기능 평가 (FBA) — 떼쓰기 행동
  c.fba = {
    meta: { observedBy: '민다혜 (BCBA)', observedAt: '2026-02-01 ~ 2026-02-14', setting: '가정 + 어린이집' },
    behavior: {
      operationalDefinition: '활동 전환 또는 원하지 않는 요구 시 30초 이상 큰 소리로 울거나, 바닥에 눕거나, 물건을 밀치는 행동.',
      intensity: '3',
      frequency: '하루 평균 2-3회',
      duration: '평균 3-5분 (최대 15분)',
      impact: '일과 진행 지연, 또래와의 상호작용 방해, 가족 스트레스 증가.',
    },
    abc: [
      { id: 'abc1', date: '2026-02-03', setting: '가정 거실', antecedent: '블록 놀이 중 어머니가 "이제 정리하자" 안내', behavior: '"싫어!" 외치며 블록을 바닥에 던지고 누워서 울음', consequence: '어머니가 5분 더 놀이 허용', notes: '시각 일정표 미사용 상황' },
      { id: 'abc2', date: '2026-02-07', setting: '어린이집 점심 시간', antecedent: '싫어하는 반찬(나물)이 식판에 놓임', behavior: '식판 밀치며 큰 소리로 울음', consequence: '담임이 나물 치워주고 다른 반찬 더 제공', notes: '거부 단어 사용 못함' },
      { id: 'abc3', date: '2026-02-12', setting: '치료실 종료 시간', antecedent: '자동차 놀이 종료 안내, 시각 일정표 제시', behavior: '잠시 입을 삐죽이다가 1분 만에 차분히 정리 참여', consequence: '"잘 정리했어" 칭찬, 좋아하는 스티커 제공', notes: '시각 지원 + 사전 예고 → 떼쓰기 감소 확인' },
    ],
    functions: {
      escape: true,
      attention: false,
      tangible: true,
      sensory: false,
      regulation: true,
      communication: true,
      notes: '주 기능은 ① 회피(원하지 않는 활동/음식) ② 사물 유지(좋아하는 놀이 지속) ③ 정서 조절 미숙. 의사소통 대체 행동(거부 단어, 도움 요청)이 미발달하여 떼쓰기로 표현됨.',
    },
    emotionalContext: {
      arousalLevel: '높음 (전환 직전 각성 급상승)',
      triggers: '예고 없는 활동 전환, 좋아하지 않는 음식·요구, 시끄러운 환경, 피곤할 때',
      protectiveFactors: '시각 일정표, 친숙한 파트너의 차분한 언어, 좋아하는 사물(자동차 미니어처), 충분한 수면',
    },
    replacement: {
      replacementBehavior: '거부 단어 사용("싫어", "안 해"), 도움 요청 단어("도와줘"), 정서 단어("화났어", "속상해")',
      teachingStrategy: '① 떼쓰기 전조 신호 포착 시 즉시 단어 시범 제공 ② 단어 사용 시 즉각적 인정·반응 ③ 점진적으로 단어 → 짧은 구로 확장',
      reinforcement: '대체 행동 사용 시: 즉각적 사회적 강화(미소, 칭찬, 짧은 토닥임) + 요구 부분 수용. 떼쓰기 시: 차분히 기다리고 관심 줄이되 안전 확보.',
      environmentalChanges: '하루 일과를 시각 일정표로 항상 제시, 활동 전환 5분/2분/지금 3단계 예고, 어려운 활동 전에 좋아하는 활동 배치.',
    },
    preventionPlan: '① 일과 예측 가능성 ② 선택권 제공(둘 중 하나) ③ 어려운 활동은 짧게 + 즉각 강화 ④ 피곤·배고픔 등 생리적 요인 사전 점검.',
    crisisPlan: '떼쓰기 발생 시: 1) 안전 확보 2) 차분한 어조로 감정 짚기("화났구나") 3) 진정될 때까지 옆에 머무름 4) 진정 후 대체 행동 시범 + 부분 요구 수용.',
    monitoringPlan: '주 1회 ABC 기록(가정·어린이집·치료실 각 1건 이상), 월 1회 빈도·강도·지속시간 그래프 작성, 분기별 BIP 효과성 검토.',
  };

  // 12) 활동 일지 II (주간 종합 기록)
  c.activities.logII = {
    weekOf: '2026-03-23',
    daily: {},
    summary: '이번 주 준호는 차례 주고받기와 단어 명명에서 안정적 진전을 보였다. 특히 그림책 읽기에서 자발 명명이 늘었고, 떼쓰기는 시각 일정표 사용 이후 빈도가 줄었다.',
    social: '블록 쌓기와 그림책 읽기에서 차례 주고받기 3-4회 유지. 또래에게 먼저 사물 보여주기 시도 2회 관찰.',
    emo: '전이 상황에서 시각 일정표 사용 시 떼쓰기 빈도 50% 감소. 좌절 시 "싫어" 단어 사용 3회 관찰.',
    ts: '시각 지원(일정표·선택판)의 일관된 사용이 효과적. 어린이집·가정 간 자료 통일 필요.',
    adjust: '다음 주: ① 또래 매개 활동 1회 추가 ② "도와줘" 단어 사용 기회 확대 ③ 어린이집에 시각 일정표 사본 제공.',
  };
  c.activities.weekly = {
    weekOf: '2026-03-23',
    social: '차례 주고받기 안정화. 또래 시도 증가.',
    emo: '시각 일정표 효과 확인. 거부 단어 출현.',
    ts: '환경 간 자료 일관성 필요.',
    adjust: '또래 매개 활동 추가, 도움 요청 단어 집중.',
  };

  c._isSample = true; // 샘플 표시

  // 관찰 계획 (관찰 1: 가정 / 관찰 2: 치료실)
  // text 타입은 {value:'...'}, datetime은 {필드명:'...'}, variants는 {variants:{idx:'...'}}
  c.observation.data = {
    1: {
      place: { value: '가정 (거실, 놀이방). 자연스러운 일과 안에서 자유 놀이와 식사/전이 상황을 함께 관찰함.' },
      time: { '날짜/시간': '2026-01-13 오전 10시 ~ 11시', '관찰 소요 시간': '약 1시간 (자유 놀이 30분 + 일과 30분)' },
      team: { value: '팀 구성원: 어머니, 치료사 / 파트너 및 집단 크기: 일대일 (친숙한 파트너)' },
      activity: { variants: {
        0: '자유 놀이 (블록, 자동차) — 비구조화/아동 주도/재미있는',
        1: '간식 시간 — 구조화/성인 주도/익숙한',
        2: '그림책 읽기 — 정적/언어 중심/선호하는',
        3: '정리 및 전이 상황 — 의무적/사회적/어려운',
      } },
      transition: { value: '1) 놀이 → 간식 전이\n2) 간식 → 책 읽기 전이\n3) 책 → 정리/외출 전이' },
    },
    2: {
      place: { value: '치료실 + 어린이집 소집단 활동실. 친숙하지 않은 파트너와 새 환경에서의 반응 관찰.' },
      time: { '날짜/시간': '2026-01-15 오후 2시 ~ 3시', '관찰 소요 시간': '약 1시간 (치료실 30분 + 어린이집 30분)' },
      team: { value: '팀 구성원: 치료사, 어린이집 담임, 또래 2명 / 파트너 및 집단 크기: 소집단 (친숙하지 않은 파트너 포함)' },
      activity: { variants: {
        0: '구조화된 학습 활동 — 구조화/성인 주도/언어 중심',
        1: '또래와 함께하는 놀이 — 사회적/아동 주도/익숙하지 않은',
        2: '노래·율동 시간 — 동적/사회적/재미있는',
        3: '새로운 장난감 탐색 — 비구조화/익숙하지 않은/어려운',
      } },
      transition: { value: '1) 치료실 → 어린이집 활동실 전이\n2) 개별 활동 → 소집단 활동 전이\n3) 소집단 → 자유 시간 전이' },
    },
  };

  // 6) IEP — 현행수준·목표·주간목표 미리 채움 (불러오면 STEP4 완료로 표시)
  c.iep.reportDate = '2026-02-10';  // IEP 작성일 (홈 작성일과 다르게)
  c.iep.currentLevel = {
    sc: '준호는 사회 의사소통 영역 진단에서 21/40점(53%)을 받았다. 보호자 보고에 따르면 눈맞춤은 잘하고 원하는 것을 단어로 표현하지만, 먼저 대화를 시작하는 일은 드뭅니다. 언어 파트너 단계 수준에서 공동관심은 55%, 상징 사용은 50%로 나타났다. 점수가 낮은 항목을 IEP 목표로 선정하였다.',
    er: '준호는 정서 조절 영역 진단에서 14/40점(35%)을 받았다. 상호조절 44%, 자기조절 32%로, "파트너 의존형" 패턴에 해당한다. 준호가 다른 사람의 도움으로는 정서를 잘 조절하지만, 혼자서는 조절 전략을 사용하기 어려운 상태다. 흥미를 보이는 활동은 블록 쌓기, 자동차 놀이, 그림책 보기이며, 어려움을 보이는 상황은 놀이를 끝내고 다른 활동으로 바꿀 때, 시끄럽고 사람이 많은 환경이다.',
    ts: '준호는 교류 지원 영역 진단에서 양호한 수준을 보인다. 파트너의 반응성과 시각 지원 사용에서 강점이 있으며, 시작행동 촉진과 또래 상호작용 지원이 교실과 가정 간 일관성 확보의 우선 과제이다.',
  };
  c.iep.annualGoals = {
    sc: '준호는 일상적인 놀이 및 과제 상황에서 기능적인 의사소통 수단을 사용하여 관계어·서술어 확장을 목표로 한다. (가족 희망: 친구들과 어울려 놀고, 자기 기분을 말로 표현하기)',
    er: '준호는 감정 변화 상황에서 파트너의 도움을 받아 조절 전략을 사용하여 활동에 재참여한다.',
    ts: '파트너는 준호의 의사소통 및 정서 신호를 일관성 있게 인식하고 반응하며, 예측 가능한 환경과 시각 지원을 제공한다.',
  };
  c.iep.shortGoals = {
    sc: '원하는 활동 또는 물건을 요청 시 자발적으로 단어 이상 수준의 의사소통을 1일 2회 이상 사용한다.',
    er: '파트너가 사용하던 진정 전략을 준호 스스로 따라 할 수 있도록 시범 보이기',
    ts: '시각일과표를 보며 다음 활동을 예측하고, 준비 행동을 3회 중 2회 이상 수행한다.',
  };
  c.iep.strategies = {
    sc: '관심 있는 사물·활동을 활용해 의사소통 동기를 유발하고, 단어를 시범 보인 뒤 모방을 기다린다. 선택 기회(둘 중 하나 고르기)를 자주 제공하여 자발적 표현을 촉진한다.',
    er: '활동 전환 전 시각 일정표와 예고를 제공하고, 좌절 시 파트너가 감정을 언어로 짚어준 뒤 진정 전략(심호흡, 좋아하는 사물)을 함께 사용해 시범을 보인다.',
    ts: '파트너는 반응 속도를 늦추고 기다려 주어 시작행동을 촉진하며, 짧고 명확한 언어와 시각 지원(그림카드·일정표)을 일관되게 사용한다.',
  };
  c.iep.measures = {
    sc: '회기별 활동 일지에 자발적 의사소통 발생 빈도를 기록하고, 주 1회 집계하여 목표(1일 2회) 달성 여부를 점검한다.',
    er: '전환·좌절 상황에서의 진정 소요 시간과 파트너 도움 수준(독립/언어촉진/신체보조)을 회기마다 기록한다.',
    ts: '시각일과표 활용 시 준비 행동 성공률(3회 중 성공 횟수)을 회기별로 체크리스트에 기록한다.',
  };
  c.iep.selectedGoals = [
    { id: 'JA5.3', label: '차례 주고받기', domain: 'joinAttention', customGoal: '' },
    { id: 'JA8.1', label: '경험 공유를 위해 관심/정서/의도 조절하기', domain: 'joinAttention', customGoal: '' },
    { id: 'SU5.1', label: '관계어·서술어 사용하기', domain: 'symbolUse', customGoal: '' },
    { id: 'SR3.1', label: '언어 전략을 통한 자기조절', domain: 'selfReg', customGoal: '' },
  ];

  // 7) 중간보고서 — 미리 채움 (STEP5는 사전/사후로 이미 완료, 내용도 채워둠)
  c.interim.reportType = 'interim';
  c.interim.reportDate = '2026-05-20';  // 중간보고서 작성일 (IEP·홈과 다르게)
  c.interim.period = '2026년 1월 ~ 5월 (1차 중재 기간)';
  c.interim.summary = '준호는 언어 파트너 단계(상징적 의사소통의 확장) 수준에 해당한다. 이번 평가 기간 동안 SCERTS 세 영역(사회 의사소통, 정서 조절, 교류 지원)을 중심으로 중재를 진행하였다. 진단 총점은 사전 25점에서 사후 36점으로 11점 상승하였다. 이 단계의 핵심 발달 과제는 단일 단어에서 2~3어 조합으로 확장, 다양한 의사소통 기능 출현이며, 해당 과제를 중심으로 지원하였다.';
  c.interim.observations = '회기별 활동 일지 3건 중 주요 관찰 사례는 다음과 같다.\n\n▸ 2026-03-12 - 블록 쌓기 놀이\n  · 블록을 가리키며 "더 줘"라고 요청 (독립 수행)\n  메모: 활동 시작 시 집중도가 높았고 차례 주고받기 3회 성공\n\n▸ 2026-03-19 - 그림책 함께 보기\n  · 그림을 보고 "강아지", "공"이라고 명명 (부분 보조)\n\n▸ 2026-03-26 - 자동차 역할놀이\n  · 자동차를 뺏기자 화났지만 교사가 감정을 말로 짚어주자 진정 (파트너 도움)';
  c.interim.direction = '정서 조절 영역의 현재 프로파일은 상호조절 44%, 자기조절 32%로 "파트너 의존형" 패턴에 해당한다.\n\n준호가 다른 사람의 도움으로는 정서를 잘 조절하지만, 혼자서는 조절 전략을 사용하기 어려운 상태다.\n\n다음 기간에는 다음 전략을 중점적으로 적용한다.\n1. 파트너가 사용하던 진정 전략을 준호 스스로 따라 할 수 있도록 시범 보이기\n2. 감정 단어(화남, 속상함, 좋아)를 일상에서 반복 노출\n3. 전환 상황에 시각적 일정표를 일관되게 사용';

  return c;
}

// =====================================================================
// 샘플: 사회적 파트너 단계 (김서아, 2세 8개월)
// =====================================================================
function makeSampleChildSP() {
  const c = blankChild('김서아');
  c.meta.birthDate = '2023-09-20';
  c.meta.startDate = '2026-02-01';
  c.meta.stage = 'social';
  c.meta.className = 'SCERTS 프로그램 새싹반';

  c.decision = { q1: { a1: false, a2: false }, q2: { b1: true, b2: false } };

  c.interview.meta = { name: '김서아', age: '만 2세 8개월', date: '2026-02-03', reporter: '박미영', relation: '어머니' };
  c.interview.answers = {
    sp_sc_1: '아직 단어는 거의 사용하지 않으며, 원하는 것이 있을 때 손을 끌어서 보여줍니다. 눈맞춤은 짧게 가능합니다.',
    sp_sc_2: '주로 사람을 도구처럼 사용하여 원하는 것을 얻으려 합니다. 가리키기는 아직 일관되지 않습니다.',
    sp_sc_3: { checked: { '사람을 도구처럼 끌기': true, '소리·울음': true, '몸짓(손 뻗기)': true }, texts: {} },
    sp_sc_4: { checked: { '"엄마"': true, '"맘마"': true }, texts: { vocal: '"음", "어어" 같은 발성 자주 사용' } },
    sp_sc_5: { checked: { '원하는 것 요구하기': true, '거부하기(고개 흔들기)': true }, texts: {} },
    sp_sc_6: { 0: 1, 1: 0, 2: 0 },
    sp_sc_7: '못 알아채면 더 크게 울거나 손을 잡아 끌고 갑니다.',
    sp_sc_8: '비눗방울, 흔들리는 인형, 까꿍 놀이를 가장 좋아합니다.',
    sp_sc_9: '친숙한 어른이 다가오면 미소 짓고 짧게 눈맞춤하나, 또래에는 거의 반응 없음.',
    sp_sc_10: { checked: { '엄마의 얼굴 표정': true, '"안 돼"': true, '"이리 와"': true }, texts: {} },
    sp_er_1: '낯선 자극에 위축되며 엄마를 찾습니다. 친숙한 자극에는 미소나 발성을 보입니다.',
    sp_er_2: '비눗방울, 음악, 까꿍 놀이',
    sp_er_3: '낯선 사람, 큰 소음, 옷 갈아입기',
    sp_er_4: '엄마가 안아주거나 좋아하는 인형을 쥐어주면 진정됩니다.',
    sp_er_5: '새로운 상황에서는 엄마 다리에 매달려 진정하려 합니다.',
    sp_er_6: { '기쁨': '소리내며 웃고 손뼉을 침', '슬픔': '울음', '만족감': '미소', '분노 또는 좌절': '큰 울음과 발버둥', '익살스러움': '아직 잘 나타나지 않음', '두려움': '엄마에게 매달림' },
    sp_er_7: '안아주면 1-2분 안에 진정됩니다.',
    sp_er_8: '선택지를 손으로 가리키기는 아직 어렵고, 좋아하는 쪽을 향해 손 뻗습니다.',
    sp_er_9: '안아주기, 좋아하는 인형, 익숙한 노래.',
    sp_er_10: '얼굴이 빨개지고 몸을 비틀며 큰 소리로 웁니다.',
    sp_er_11: '시선을 돌리거나 몸을 돌립니다.',
    sp_er_12: { self: '좋아하는 인형을 쥐고 흔들며 스스로 진정 시도', partner: '엄마가 안아주고 등을 토닥이면 회복됨' },
    sp_ex_1: '아직 의도적 표현은 발달 중입니다. 손 뻗기와 발성으로 의사를 보입니다.',
    sp_ex_2: '비눗방울을 더 원할 때 빈 통을 가져옵니다.',
    sp_ex_3: '싫은 음식은 입을 다물고 고개를 돌립니다.',
    sp_ex_4: '엄마와 눈맞추며 미소로 인사합니다.',
    sp_ex_5: '아직 사물을 가리켜 보여주는 행동은 드물지만, 좋아하는 인형을 들고 엄마에게 다가오기는 합니다.',
    sp_ex_6: '"안녕"에 손을 흔들거나, "맘마"에 식탁으로 갑니다.',
    sp_ts_1: '엄마, 아빠, 할머니, 어린이집 담임 선생님',
    sp_ts_2: '집, 어린이집, 할머니 댁',
    sp_ts_3: { '아동이 관심을 갖는 대상': 2, '아동이 의사소통하려고 하는 것': 1, '아동의 감정 상태': 2, '아동이 선호하는 속도': 1, '아동에게 휴식이 필요할 때': 1, '아동이 흥미를 보이는지 여부': 2, '아동이 좌절했는지 여부': 2, '아동이 흥분했는지 여부': 1 },
    sp_ts_4: '서아의 발성과 손짓을 의사소통으로 인정하고 따라 반응합니다.',
    sp_ts_5: '울음 시 안아주고 감정을 짧은 단어로 말해줍니다 ("속상해").',
    sp_ts_6: '이름을 부르고 눈높이에서 좋아하는 사물을 보여줍니다.',
    sp_ts_7: '서아가 좋아하는 활동을 함께 하며 발성·동작을 따라 합니다.',
    sp_ts_8: '짧고 명확한 단어와 몸짓, 시각 자료를 함께 사용합니다.',
    sp_ts_9: '아직 그림 일정표는 사용 전. 간단한 사물 일정표는 도입 검토 중.',
    sp_ts_10: '조용한 가정 환경, 익숙한 사람이 있을 때 참여가 잘 유지됩니다.',
    sp_ts_11: '시각 자료가 함께 제시될 때 더 잘 이해합니다.',
  };

  // SP 단계 진단 점수 (전반적으로 낮음 — 초기 발달 단계)
  const preScores = {
    'JA1.1':1,'JA1.2':1,'JA2.1':0,'JA2.2':0,'JA3.1':1,'JA4.1':1,'JA4.2':0,'JA5.1':1,
    'SU1.1':0,'SU1.2':0,'SU2.1':1,'SU2.2':0,'SU3.1':0,'SU4.1':1,
    'MR1.1':1,'MR2.1':1,'MR2.2':0,'MR3.1':0,
    'SR1.1':1,'SR2.1':0,'SR3.1':0,
    'IS1.1':2,'IS2.1':1,'IS3.1':1,'IS4.1':1,'IS5.1':1,'IS6.1':1,'IS7.1':1,
  };
  const postScores = {
    'JA1.1':2,'JA1.2':1,'JA2.1':1,'JA2.2':1,'JA3.1':1,'JA4.1':2,'JA4.2':1,'JA5.1':1,
    'SU1.1':1,'SU1.2':1,'SU2.1':1,'SU2.2':1,'SU3.1':1,'SU4.1':2,
    'MR1.1':2,'MR2.1':1,'MR2.2':1,'MR3.1':1,
    'SR1.1':1,'SR2.1':1,'SR3.1':0,
    'IS1.1':2,'IS2.1':2,'IS3.1':2,'IS4.1':1,'IS5.1':1,'IS6.1':1,'IS7.1':2,
  };
  const preSes = { happiness: 6, selfAwareness: 4, otherAwareness: 4, independence: 3, belonging: 4 };
  const postSes = { happiness: 7, selfAwareness: 5, otherAwareness: 5, independence: 4, belonging: 5 };
  c.sessions = [
    { id: 's_sp_pre', label: '사전 진단 (2월)', date: '2026-02-05', quarter: 1, scores: preScores, ses: preSes, notes: '치료 시작 시점', designation: 'pre' },
    { id: 's_sp_post', label: '사후 진단 (6월)', date: '2026-06-05', quarter: 2, scores: postScores, ses: postSes, notes: '1차 중재 후', designation: 'post' },
  ];
  c.activeSessionId = 's_sp_post';

  c.familyPriorities = {
    profileAccurate: 'yes',
    additionalInfo: '발성과 손짓은 점점 늘고 있으며, 엄마와의 애착이 강합니다.',
    focusOne: '의도적 의사소통 시도 늘리기',
    focusGoalIds: [],
    threeMonthHope: '"엄마", "맘마" 같은 첫 단어를 일관되게 사용하기',
  };

  c.activities.logI = [
    { id: 'log1', date: '2026-03-05', fields: { activity: '비눗방울 놀이' },
      goalsSocial: [{ goal: '시선 맞추기', observed: '비눗방울을 더 원할 때 엄마와 눈맞춤 3회', rating: '부분 보조' }],
      goalsEmo: [], notes: '5초간 시선 유지 가능' },
    { id: 'log2', date: '2026-03-12', fields: { activity: '까꿍 놀이' },
      goalsSocial: [{ goal: '주고받기', observed: '"까꿍" 발성에 미소로 반응', rating: '독립 수행' }],
      goalsEmo: [{ goal: '기다리기', observed: '엄마가 잠시 멈추자 발성으로 요청', rating: '언어 촉진' }],
      notes: '' },
  ];

  c._isSample = true;
  c.iep.reportDate = '2026-02-25';
  c.iep.currentLevel = {
    sc: '서아는 사회 의사소통 영역에서 사회적 파트너 단계 초기 수준이다. 보호자 보고에 따르면 아직 단어는 거의 사용하지 않으며 손 끌기와 발성으로 의사를 보인다. 공동관심은 발달 중이며, 가리키기와 시선 맞추기가 일관되지 않다.',
    er: '서아는 정서 조절 영역에서 파트너 의존이 높은 양상이다. 낯선 자극에 위축되며 엄마의 도움으로 진정한다. 흥미를 보이는 활동은 비눗방울·음악·까꿍 놀이이며, 어려움을 보이는 상황은 낯선 사람·큰 소음·옷 갈아입기이다.',
    ts: '서아는 친숙한 파트너와의 상호작용에서 강점을 보인다. 파트너의 반응성·기다림·시각 지원 사용에서 일관성을 높이는 것이 우선 과제이다.',
  };
  c.iep.annualGoals = {
    sc: '서아는 일상 활동에서 의도적 의사소통(가리키기·발성·시선)을 사용하여 요구·거부·관심 공유를 표현한다.',
    er: '서아는 정서 변화 상황에서 파트너의 도움으로 진정 전략을 사용하여 활동에 재참여한다.',
    ts: '파트너는 서아의 비언어적 의사소통 신호를 일관성 있게 인식·반응하며, 예측 가능한 환경을 제공한다.',
  };
  c.iep.shortGoals = {
    sc: '원하는 활동·물건에 대해 발성 또는 가리키기로 1일 3회 이상 요청한다.',
    er: '파트너의 진정 시범(토닥임·노래)을 받아들이고 1분 내 진정한다.',
    ts: '시각 일정표(사물 일정표)를 도입하여 일과 예측 가능성을 높인다.',
  };
  c.iep.strategies = {
    sc: '관심 사물을 손이 닿지 않는 위치에 두어 요청 동기 유발, 사물 시범 후 발성·가리키기 대기.',
    er: '좌절 신호 포착 시 파트너가 감정을 짧게 짚고("속상해") 진정 시범 보이기. 좋아하는 진정 사물 가까이 두기.',
    ts: '파트너는 5초 이상 기다려 시작행동 유도, 짧고 명확한 단어와 시각 자료 함께 제시.',
  };
  c.iep.measures = {
    sc: '회기별 의도적 의사소통 빈도 기록, 주간 집계.',
    er: '진정 소요 시간 + 파트너 도움 수준 회기별 기록.',
    ts: '시각 일정표 사용 여부와 효과를 주 1회 점검.',
  };
  c.iep.selectedGoals = [
    { id: 'JA1.1', label: '가리키기', domain: 'joinAttention', customGoal: '' },
    { id: 'JA4.1', label: '시선 공유', domain: 'joinAttention', customGoal: '' },
    { id: 'SU2.1', label: '발성으로 표현하기', domain: 'symbolUse', customGoal: '' },
    { id: 'MR1.1', label: '파트너의 위로 수용', domain: 'mutualReg', customGoal: '' },
  ];

  c.interim.reportType = 'interim';
  c.interim.reportDate = '2026-06-10';
  c.interim.period = '2026년 2월 ~ 6월 (1차 중재 기간)';
  c.interim.summary = '서아는 사회적 파트너 단계(전 상징적 의사소통)에 해당한다. 이번 평가 기간 동안 의도적 의사소통 시도가 늘었으며, 발성과 가리키기 사용 빈도가 증가하였다. 진단 총점은 사전에서 사후로 향상되었다.';
  c.interim.observations = '관찰 사례:\n▸ 2026-03-05 비눗방울 놀이 — 비눗방울을 더 원할 때 엄마와 눈맞춤 3회 (부분 보조)\n▸ 2026-03-12 까꿍 놀이 — "까꿍" 발성에 미소로 반응 (독립 수행), 멈춤 시 발성으로 요청 (언어 촉진)';
  c.interim.direction = '정서 조절 영역에서 파트너 의존이 높은 양상이다. 서아가 다른 사람의 도움으로는 정서를 조절하지만 혼자서 조절 전략을 사용하기 어렵다.\n\n다음 기간 전략:\n1. 파트너의 진정 시범을 서아가 모방하도록 단계적 시범\n2. 좋아하는 사물·노래를 진정 도구로 일관되게 제공\n3. 가정·치료실에서 동일한 사물 일정표 사용';

  // 관찰 계획
  c.observation.data = {
    1: {
      place: { value: '가정 (거실, 식탁). 익숙한 환경에서 자연스러운 일과를 관찰함.' },
      time: { '날짜/시간': '2026-02-04 오전 9시 ~ 10시', '관찰 소요 시간': '약 1시간' },
      team: { value: '팀 구성원: 어머니, 치료사 / 친숙한 파트너 일대일' },
      activity: { variants: {
        0: '자유 놀이 (인형, 비눗방울) — 비구조화/아동 주도/재미있는',
        1: '간식 시간 — 구조화/성인 주도/익숙한',
        2: '까꿍 놀이 — 정적/사회적/선호하는',
        3: '옷 갈아입기 — 의무적/어려운',
      } },
      transition: { value: '1) 놀이 → 간식 전이\n2) 간식 → 외출 준비 전이' },
    },
    2: {
      place: { value: '치료실. 새로운 자극에 대한 반응과 친숙하지 않은 파트너와의 상호작용 관찰.' },
      time: { '날짜/시간': '2026-02-06 오후 2시 ~ 2시 50분', '관찰 소요 시간': '약 50분' },
      team: { value: '팀 구성원: 치료사 1명, 보조 1명 / 친숙하지 않은 파트너 포함' },
      activity: { variants: {
        0: '비눗방울 활동 — 선호하는/재미있는',
        1: '새 장난감 탐색 — 비구조화/익숙하지 않은',
        2: '노래·율동 — 동적/사회적',
        3: '정리 시간 — 의무적/어려운',
      } },
      transition: { value: '1) 도착 → 활동 시작 전이\n2) 활동 종료 → 귀가 전이' },
    },
  };

  // 활동 일지 II (주간 종합)
  c.activities.logII = {
    weekOf: '2026-03-09',
    daily: {},
    summary: '서아는 이번 주 발성 빈도와 가리키기 시도가 늘었다. 비눗방울 활동에서 의도적 요청이 관찰되었고, 진정 시간이 단축되었다.',
    social: '비눗방울 더 원할 때 빈 통 가져오기 3회, 가리키기 시도 5회 관찰.',
    emo: '진정 소요 시간 평균 3분 → 1.5분으로 감소. 좋아하는 인형 사용 시 효과적.',
    ts: '엄마와 치료사 모두 5초 대기 전략을 일관되게 사용. 사물 일정표 도입 검토 중.',
    adjust: '다음 주: ① 가리키기 모델링 빈도 늘리기 ② 사물 일정표 시범 도입 ③ 또래 노출 기회 만들기.',
  };
  c.activities.weekly = {
    weekOf: '2026-03-09',
    social: '가리키기·발성 빈도 증가.',
    emo: '진정 시간 단축. 인형 효과 확인.',
    ts: '5초 대기 전략 일관성 확보.',
    adjust: '사물 일정표 시범 도입, 또래 노출 기회.',
  };

  // 가족 지원 계획서
  c.familySupport = {
    meta: { weekOf: '2026-02', meetingDate: '2026-02-12', participants: '어머니, 아버지, 민다혜 (BCBA)' },
    currentConcerns: '아직 단어 표현이 거의 없어 부모님이 걱정하고 계심. 외출 시 옷 갈아입기에서 강한 거부가 자주 발생.',
    childStrengths: '엄마와의 애착이 강하고 친숙한 어른과의 상호작용을 즐김. 비눗방울·까꿍 놀이에서 미소와 발성을 보임.',
    familyGoals: [
      '하루 일과에 의사소통 기회 10회 이상 만들기 (식사·놀이·외출)',
      '옷 갈아입기 등 어려운 활동 전 좋아하는 사물·노래 활용',
      '주 1회 새로운 또래 환경 (놀이터, 친척 집) 노출',
    ],
    homeStrategies: [
      { area: '의사소통', strategy: '원하는 사물을 손이 닿지 않는 위치에 두어 발성·가리키기 유도', whenToUse: '간식·놀이·외출 준비 시', resourcesNeeded: '좋아하는 사물·간식 시야에 두기' },
      { area: '정서 조절', strategy: '좌절 직전 신호 포착 시 안아주고 짧은 단어로 감정 짚기 ("속상해")', whenToUse: '옷 갈아입기·낯선 자극 노출 시', resourcesNeeded: '좋아하는 인형, 익숙한 노래' },
      { area: '일상 활동', strategy: '어려운 활동 전 좋아하는 활동을 짧게 배치, 진행 순서를 사물로 보여주기', whenToUse: '외출 준비·취침 전', resourcesNeeded: '사물 일정표(신발·옷·가방)' },
    ],
    educationTopics: [
      { topic: 'SCERTS 사회적 파트너 단계 이해', notes: '책 「우리 아이의 의사소통 시작」 챕터 1-2 안내함' },
      { topic: '5초 기다리기 전략', notes: '시범 영상 제공' },
    ],
    followUp: '2주 후 가정 영상(놀이 5분, 간식 5분) 공유 받아 전략 적용도 점검 예정.',
    nextMeeting: '2026-02-26',
  };

  // 전문가 협력
  c.profSupport = {
    meta: { weekOf: '2026-02', meetingDate: '2026-02-14', teamMembers: '민다혜(BCBA), 김OO(어린이집 담임), 부모' },
    sharedObservations: '치료실에서는 친숙해진 후 발성과 미소 증가. 어린이집에서는 아직 위축되어 있고 또래 접근 시 회피.',
    currentChallenges: '환경 간 적응 시간이 길어 어린이집에서 의사소통 기회 활용이 제한적임.',
    collaborativeGoals: [
      '어린이집에서 친숙한 파트너 1명 확보 (담임 또는 보조)',
      '치료실·어린이집·가정에서 동일한 사물 일정표 사용',
      '월 1회 팀 회의로 진전·전략 공유',
    ],
    roleResponsibilities: [
      { role: '주 치료사', name: '민다혜 (BCBA)', responsibilities: '진단·IEP 수립, 부모 코칭, 팀 회의 주관' },
      { role: '담임 교사', name: '김OO (어린이집)', responsibilities: '서아와 일대일 적응 시간 확보, 사물 일정표 사용' },
      { role: '부모', name: '박미영 (어머니)', responsibilities: '가정 전략 실행, 주 1회 영상 기록' },
    ],
    communicationPlan: '주 1회 알림장, 카카오톡 그룹방. 월 1회 정기 회의(1.5시간).',
    caseConferenceNotes: '2026-02-14 회의 결정: ① 사물 일정표 어린이집 도입 ② 친숙한 또래 1명 매칭 시도 ③ 다음 회의 영상 사례 공유.',
    nextReview: '2026-03-14',
  };

  // 의사소통 일정표
  c.communicationSchedule = {
    meta: { observedBy: '민다혜', observedAt: '2026-02-20', setting: '가정 일과 + 어린이집' },
    activities: [
      { id: 'a_morning', time: '07:30-08:30', name: '기상·아침 식사', opportunities: '아침 인사, 음식 요구, 컵 요청', currentBehavior: '엄마 보면 미소, 음식은 손 끌기로 요구', supports: '"맘마" 시범 + 5초 대기, 선택 제시 ("우유? 물?")', goals: '음식 요구 시 발성 1회 이상' },
      { id: 'a_arrival', time: '09:00-09:30', name: '등원', opportunities: '선생님 인사, 신발 도움 요청', currentBehavior: '엄마와 분리 시 위축, 짧은 울음', supports: '"안녕" 시범 + 좋아하는 인형 동행', goals: '담임 보면 짧은 시선 맞춤' },
      { id: 'a_free', time: '09:30-10:30', name: '자유 놀이', opportunities: '장난감 선택, 또래 옆에서 놀기', currentBehavior: '혼자 비눗방울·인형 놀이 선호', supports: '관심 있는 또래 옆 자리 배치, 함께 놀이 시도', goals: '또래 1명 옆에서 5분 이상 머무름' },
      { id: 'a_snack', time: '10:30-11:00', name: '간식', opportunities: '간식 요구, 더 달라 표현', currentBehavior: '"맘마" 발성 가능', supports: '잘게 나눠 여러 번 요청 기회 제공', goals: '간식 요구 발화 3회 이상' },
      { id: 'a_outdoor', time: '11:00-11:30', name: '실외 활동', opportunities: '미끄럼틀·그네 요청', currentBehavior: '좋아하는 활동에 적극적', supports: '"더" 시범 후 기다리기', goals: '실외 활동 중 발성·가리키기 5회 이상' },
      { id: 'a_dismiss', time: '13:00-13:30', name: '하원', opportunities: '엄마 호명, 인사', currentBehavior: '엄마 보면 환하게 웃음', supports: '하원 5분 전 시각 예고, 인사 시범', goals: '엄마 호명 "엄마" 1회 이상' },
    ],
    summary: '서아는 익숙한 활동(아침 식사·실외 활동·하원)에서 의사소통 빈도가 높고, 사회적 상황(등원·자유 놀이)에서 위축됨. 친숙한 파트너와의 일대일 시간 확보가 핵심.',
    keyOpportunities: '① 식사·간식 시간 요구 표현 ② 좋아하는 실외 활동에서 발성·가리키기 ③ 하원 시 가족 호명 — 모든 환경에서 5초 대기 전략 일관 적용.',
  };

  // 행동 기능 평가 (FBA) — 옷 갈아입기 거부
  c.fba = {
    meta: { observedBy: '민다혜 (BCBA)', observedAt: '2026-02-01 ~ 2026-02-14', setting: '가정 + 어린이집' },
    behavior: {
      operationalDefinition: '옷 갈아입기 등 신체 접촉이 필요한 일과 요구 시 1분 이상 큰 소리로 울거나, 몸을 비틀거나, 옷을 잡아당기는 행동.',
      intensity: '3',
      frequency: '하루 평균 2-3회 (옷 갈아입기, 외출 준비, 목욕)',
      duration: '평균 2-4분',
      impact: '아침 등원 지연, 가족 스트레스, 외출 회피.',
    },
    abc: [
      { id: 'abc1', date: '2026-02-03', setting: '가정 (아침)', antecedent: '엄마가 외출복으로 갈아입히려 함', behavior: '몸을 비틀며 큰 소리로 울음', consequence: '엄마가 좋아하는 인형을 쥐어줌 → 진정 후 갈아입음', notes: '인형 활용이 효과적' },
      { id: 'abc2', date: '2026-02-08', setting: '어린이집 (낮잠 시간)', antecedent: '담임이 잠옷으로 갈아입히려 함', behavior: '옷을 잡아당기며 울음', consequence: '담임이 잠시 멈추고 좋아하는 노래 부르며 진정 후 진행', notes: '예고와 노래가 도움됨' },
      { id: 'abc3', date: '2026-02-12', setting: '가정 (목욕 후)', antecedent: '잠옷 갈아입기, 시각 예고 없음', behavior: '울음 + 도망', consequence: '엄마가 5분 후 다시 시도, 좋아하는 인형 옆에 둠 → 진정 후 갈아입음', notes: '시각 예고 미사용 상황' },
    ],
    functions: {
      escape: true,
      attention: false,
      tangible: false,
      sensory: true,
      regulation: true,
      communication: true,
      notes: '주 기능: ① 회피(불편한 신체 접촉) ② 감각(옷 갈아입을 때 촉각 자극) ③ 정서 조절 미숙. 거부 의사를 단어로 표현 못해 울음으로 대체됨.',
    },
    emotionalContext: {
      arousalLevel: '높음 (촉각 자극 시 급상승)',
      triggers: '예고 없는 신체 접촉, 새 옷·낯선 질감, 피곤·졸린 상태',
      protectiveFactors: '좋아하는 인형, 친숙한 노래, 사물 일정표, 충분한 수면',
    },
    replacement: {
      replacementBehavior: '"싫어" 발성, 거부 신호 (고개 흔들기), 도움 요청 (손 뻗기)',
      teachingStrategy: '① 거부 신호 포착 시 "싫어"·"안 해" 단어 시범 ② 단어·신호 사용 시 즉각 인정·반응 ③ 점진적 노출로 신체 접촉 적응',
      reinforcement: '대체 행동 사용 시: 즉각적 사회적 강화(미소, 토닥임) + 짧은 휴식. 떼쓰기 시: 차분히 옆에 머무름.',
      environmentalChanges: '옷 갈아입기 5분 전 사물 일정표로 예고, 좋아하는 인형 옆에 두기, 익숙한 노래 부르며 진행.',
    },
    preventionPlan: '① 활동 예측 가능성 확보 ② 감각 친화적 옷감 선택 ③ 피곤·배고픔 사전 점검 ④ 짧고 분명한 단어로 안내.',
    crisisPlan: '울음 발생 시: 1) 안전 확보 2) 차분한 어조로 "속상해" 짚기 3) 잠시 멈춤 + 진정 후 재시도 4) 진정 시 좋아하는 활동으로 보상.',
    monitoringPlan: '주 1회 ABC 기록(가정·어린이집 각 1건), 월 1회 빈도·강도 그래프 작성.',
  };

  return c;
}

// =====================================================================
// 샘플: 대화 파트너 단계 (이지훈, 6세 3개월)
// =====================================================================
function makeSampleChildCP() {
  const c = blankChild('이지훈');
  c.meta.birthDate = '2019-12-10';
  c.meta.startDate = '2026-01-15';
  c.meta.stage = 'conversation';
  c.meta.className = 'SCERTS 프로그램 푸른반';

  c.decision = { q1: { a1: true, a2: true, a3: true }, q2: { b1: true, b2: true, b3: true } };

  c.interview.meta = { name: '이지훈', age: '만 6세 3개월', date: '2026-01-17', reporter: '최수정', relation: '어머니' };
  c.interview.answers = {
    cp_sc_1: '문장으로 자기 생각을 표현할 수 있으나, 대화 주제를 유지하거나 상대 의도를 파악하는 데 어려움이 있습니다.',
    cp_sc_2: '관심 있는 주제(공룡, 지하철 노선)에 대해서는 길게 말하지만, 듣는 사람의 반응을 잘 살피지 못합니다.',
    cp_sc_3: { checked: { '문장 사용': true, '질문하기': true, '경험 이야기하기': true }, texts: {} },
    cp_sc_4: '"왜?", "어디?", "뭐 해?" 등 질문을 자주 사용하고, 자신의 경험을 시간 순서로 이야기할 수 있습니다.',
    cp_sc_5: { checked: { '정보 요구': true, '경험 공유': true, '의견 말하기': true, '협상하기': true }, texts: {} },
    cp_sc_6: { 0: 2, 1: 2, 2: 1 },
    cp_sc_7: '관심 있는 주제로 돌아가거나, 말이 통하지 않으면 짜증을 냅니다.',
    cp_sc_8: '공룡 책 읽기, 지하철 노선도 보기, 블록으로 건물 만들기.',
    cp_sc_9: '친숙한 어른과는 대화를 잘 이어가지만, 또래와는 자기 주제만 고집해 갈등이 생깁니다.',
    cp_sc_10: { checked: { '간접 표현': true, '암시': true, '농담': true }, texts: { detail: '농담의 의도는 이해하지 못하고 글자 그대로 받아들임' } },
    cp_er_1: '관심사에는 적극적이나, 예상과 다른 상황에서 강한 정서 변화를 보입니다.',
    cp_er_2: '공룡 박물관 가기, 지하철 타기, 블록 건축',
    cp_er_3: '계획 변경, 친구와의 의견 충돌, 시끄러운 환경',
    cp_er_4: '"5분 더 하고 끝내자"고 미리 약속하면 협상이 가능합니다.',
    cp_er_5: '심호흡을 시범 보이면 따라 합니다. 자기 자리로 가서 책을 보며 진정합니다.',
    cp_er_6: { '기쁨': '뛰며 큰 소리로 좋아한다고 말함', '슬픔': '"속상해"라고 말하며 풀이 죽음', '만족감': '"좋아"라고 말하며 미소', '분노 또는 좌절': '"싫어!"라고 외치고 발을 구름', '익살스러움': '농담을 시도하지만 또래가 이해 못해 좌절', '두려움': '"안 할래"라고 말하며 회피' },
    cp_er_7: '위로의 말에 반응하나, 감정이 진정되기까지 시간이 좀 걸립니다.',
    cp_er_8: '"A 할까 B 할까?"에 명확히 선택을 말로 표현합니다.',
    cp_er_9: '심호흡, 좋아하는 책 보기, 혼잣말로 상황 정리하기.',
    cp_er_10: '얼굴이 빨개지고 목소리가 커지며 같은 말을 반복합니다.',
    cp_er_11: '주제 전환, 농담 시도, 회피 행동.',
    cp_er_12: { self: '자기 자리로 가서 책을 보거나 혼잣말로 상황을 정리함', partner: '감정을 짚어주고 대안을 함께 찾으면 회복됨' },
    cp_ts_1: '엄마, 아빠, 누나, 담임 선생님, 친구 2명',
    cp_ts_2: '집, 학교, 공룡 박물관, 지하철역',
    cp_ts_3: { '아동이 관심을 갖는 대상': 2, '아동이 의사소통하려고 하는 것': 2, '아동의 감정 상태': 1, '아동이 선호하는 속도': 2, '아동에게 휴식이 필요할 때': 1, '아동이 흥미를 보이는지 여부': 2, '아동이 좌절했는지 여부': 1, '아동이 흥분했는지 여부': 1 },
    cp_ts_4: '관심 주제로 대화를 시작해 점차 새 주제로 확장합니다.',
    cp_ts_5: '감정을 언어로 짚어주고 대안을 함께 찾습니다.',
    cp_ts_6: '눈높이에서 이름을 부르고 짧고 명확하게 요점을 전달합니다.',
    cp_ts_7: '관심 주제를 활용해 대화를 길게 이어갑니다.',
    cp_ts_8: '구체적 언어와 시각 자료(그림, 도식)를 함께 사용합니다.',
    cp_ts_9: '주간 일정표와 활동 순서표를 사용합니다.',
    cp_ts_10: '구조화된 환경, 예측 가능한 일정, 익숙한 또래가 있을 때 잘 참여합니다.',
    cp_ts_11: '시각 자료가 함께 제시되고 한 번에 한 가지 활동이 주어질 때 효과적입니다.',
    cp_ts_12: '또래 간 갈등 시 중재자가 감정을 짚어주고 협상을 도와줍니다.',
  };

  // CP 단계 진단 점수 (전반적으로 높음 — 대화 가능 단계)
  const preScores = {
    'JA1.1':2,'JA2.1':2,'JA3.1':1,'JA4.1':2,'JA5.1':2,'JA6.1':1,'JA7.1':1,'JA8.1':1,
    'SU1.1':2,'SU2.1':2,'SU3.1':2,'SU4.1':1,'SU5.1':2,'SU5.2':1,'SU6.1':1,
    'MR1.1':2,'MR2.1':1,'MR2.3':2,'MR3.1':1,
    'SR1.1':2,'SR2.1':1,'SR3.1':1,'SR4.1':1,
    'IS1.1':2,'IS2.1':2,'IS6.1':1,'LS1.1':2,'LS2.1':1,'LS3.1':1,
  };
  const postScores = {
    'JA1.1':2,'JA2.1':2,'JA3.1':2,'JA4.1':2,'JA5.1':2,'JA6.1':2,'JA7.1':2,'JA8.1':2,
    'SU1.1':2,'SU2.1':2,'SU3.1':2,'SU4.1':2,'SU5.1':2,'SU5.2':2,'SU6.1':2,
    'MR1.1':2,'MR2.1':2,'MR2.3':2,'MR3.1':2,
    'SR1.1':2,'SR2.1':2,'SR3.1':2,'SR4.1':1,
    'IS1.1':2,'IS2.1':2,'IS6.1':2,'LS1.1':2,'LS2.1':2,'LS3.1':2,
  };
  const preSes = { happiness: 7, selfAwareness: 7, otherAwareness: 6, independence: 7, belonging: 5 };
  const postSes = { happiness: 8, selfAwareness: 8, otherAwareness: 7, independence: 8, belonging: 7 };
  c.sessions = [
    { id: 's_cp_pre', label: '사전 진단 (1월)', date: '2026-01-20', quarter: 1, scores: preScores, ses: preSes, notes: '치료 시작 시점', designation: 'pre' },
    { id: 's_cp_post', label: '사후 진단 (5월)', date: '2026-05-20', quarter: 2, scores: postScores, ses: postSes, notes: '1차 중재 후', designation: 'post' },
  ];
  c.activeSessionId = 's_cp_post';

  c.familyPriorities = {
    profileAccurate: 'yes',
    additionalInfo: '학교 입학 후 또래와의 상호작용이 가장 큰 과제입니다.',
    focusOne: '또래와 협력 놀이 및 갈등 해결',
    focusGoalIds: [],
    threeMonthHope: '학교에서 친구 1-2명과 안정적으로 놀기, 갈등 시 감정 조절하기',
  };

  c.activities.logI = [
    { id: 'log1', date: '2026-03-10', fields: { activity: '협력 보드게임' },
      goalsSocial: [{ goal: '차례 협상', observed: '"내 차례야"라고 말로 표현, 친구 차례 기다리기 4회 성공', rating: '독립 수행' }],
      goalsEmo: [{ goal: '져도 진정 유지', observed: '게임에서 졌을 때 잠시 한숨 쉬고 "다시 하자"고 제안', rating: '부분 보조' }],
      notes: '' },
    { id: 'log2', date: '2026-03-17', fields: { activity: '주제 대화 (좋아하는 영화)' },
      goalsSocial: [{ goal: '주제 유지', observed: '상대 의견 듣고 5회 차례 주고받기', rating: '언어 촉진' }],
      goalsEmo: [], notes: '관심 외 주제로도 1분간 대화 가능' },
  ];

  c._isSample = true;
  c.iep.reportDate = '2026-02-05';
  c.iep.currentLevel = {
    sc: '지훈이는 사회 의사소통 영역에서 대화 파트너 단계 중간 수준이다. 문장으로 자기 생각을 표현할 수 있으나, 보호자 보고에 따르면 대화 주제를 유지하거나 상대 의도를 파악하는 데 어려움이 있다.',
    er: '지훈이는 정서 조절 영역에서 자기조절 전략(심호흡, 혼잣말, 책 보기)을 사용할 수 있으나, 예상과 다른 상황(계획 변경, 의견 충돌)에서 강한 정서 변화를 보인다.',
    ts: '지훈이는 구조화된 환경과 예측 가능한 일정에서 강점을 보인다. 또래 매개 전략과 갈등 중재 지원이 우선 과제이다.',
  };
  c.iep.annualGoals = {
    sc: '지훈이는 또래와의 대화에서 주제 유지·차례 주고받기·관점 수용을 통해 협력적 상호작용을 한다. (가족 희망: 학교에서 친구와 안정적으로 놀기)',
    er: '지훈이는 예상치 못한 상황에서 자기조절 전략을 자발적으로 사용하여 활동에 재참여한다.',
    ts: '파트너는 지훈이의 또래 갈등 시 중재자 역할을 하며, 협상 언어와 시각적 갈등 해결 도구를 제공한다.',
  };
  c.iep.shortGoals = {
    sc: '또래와 5회 이상 차례를 주고받으며 주제를 유지한다.',
    er: '예상치 못한 상황에서 자기조절 전략을 1주일에 5회 이상 자발적으로 사용한다.',
    ts: '주간 일정표와 갈등 해결 카드를 일관되게 사용한다.',
  };
  c.iep.strategies = {
    sc: '관심 주제로 대화를 시작해 점차 또래 관심으로 확장. 협력 보드게임으로 차례 주고받기 연습.',
    er: '예상 가능한 변화는 미리 예고하고, 발생 시 감정 짚기 + 대안 함께 찾기. 자기조절 전략 시각 카드 제공.',
    ts: '또래와의 갈등 발생 시 중재자가 양쪽 감정 짚어주고 협상 언어 시범. 갈등 해결 단계 카드 활용.',
  };
  c.iep.measures = {
    sc: '회기별 또래와의 차례 주고받기 횟수 기록, 주제 유지 시간 측정.',
    er: '자기조절 전략 사용 빈도와 자발성 수준(자발/촉진) 기록.',
    ts: '갈등 해결 단계 카드 사용 효과 주 1회 점검.',
  };
  c.iep.selectedGoals = [
    { id: 'JA7.1', label: '또래와 대화 차례 주고받기', domain: 'joinAttention', customGoal: '' },
    { id: 'JA8.1', label: '관점 수용 및 협력', domain: 'joinAttention', customGoal: '' },
    { id: 'SR3.1', label: '자기조절 전략 자발적 사용', domain: 'selfReg', customGoal: '' },
    { id: 'SR4.1', label: '예상치 못한 상황 대처', domain: 'selfReg', customGoal: '' },
  ];

  c.interim.reportType = 'interim';
  c.interim.reportDate = '2026-05-25';
  c.interim.period = '2026년 1월 ~ 5월 (1차 중재 기간)';
  c.interim.summary = '지훈이는 대화 파트너 단계(상위 수준) 수준에 해당한다. 이번 평가 기간 동안 또래와의 차례 주고받기와 자기조절 전략 사용에서 안정적 진전을 보였다.';
  c.interim.observations = '관찰 사례:\n▸ 2026-03-10 협력 보드게임 — "내 차례야"라고 표현, 친구 차례 기다리기 4회 성공 (독립 수행), 게임 패배 시 "다시 하자" 제안 (부분 보조)\n▸ 2026-03-17 주제 대화 — 상대 의견 듣고 5회 차례 주고받기 (언어 촉진)';
  c.interim.direction = '자기조절 영역에서는 안정적이나, 예상치 못한 상황에서의 자발적 전략 사용은 더 강화가 필요하다.\n\n다음 기간 전략:\n1. 자기조절 전략 카드를 환경마다 비치하여 자발 사용 촉진\n2. 또래 매개 활동을 주 2회로 확대\n3. 갈등 해결 단계 카드를 학교·가정에 동일하게 도입';

  // 관찰 계획
  c.observation.data = {
    1: {
      place: { value: '치료실 + 학교 통합학급. 또래와의 사회적 상호작용 관찰에 초점.' },
      time: { '날짜/시간': '2026-01-22 오후 3시 ~ 4시', '관찰 소요 시간': '약 1시간' },
      team: { value: '팀 구성원: 치료사, 또래 2명 / 친숙한·친숙하지 않은 파트너 혼합 (소집단)' },
      activity: { variants: {
        0: '협력 보드게임 — 구조화/사회적/도전적',
        1: '주제 대화 (좋아하는 영화) — 정적/언어 중심/선호하는',
        2: '미술 활동 — 비구조화/창의적',
        3: '갈등 상황 시뮬레이션 — 사회적/어려운',
      } },
      transition: { value: '1) 개별 활동 → 협력 활동 전이\n2) 의견 충돌 → 협상 전이' },
    },
    2: {
      place: { value: '가정. 형제·부모와의 일상적 상호작용과 갈등 상황 관찰.' },
      time: { '날짜/시간': '2026-01-25 오후 6시 ~ 7시', '관찰 소요 시간': '약 1시간' },
      team: { value: '팀 구성원: 부모, 누나(8세) / 가족 일대다' },
      activity: { variants: {
        0: '저녁 식사 대화 — 사회적/익숙한',
        1: '누나와 보드게임 — 구조화/도전적',
        2: '취미 활동 (블록·공룡책) — 정적/선호하는',
        3: '취침 준비 — 의무적/익숙한',
      } },
      transition: { value: '1) 놀이 → 식사 전이\n2) TV 시청 → 취침 준비 전이' },
    },
  };

  // 활동 일지 II (주간 종합)
  c.activities.logII = {
    weekOf: '2026-03-16',
    daily: {},
    summary: '지훈이는 이번 주 또래와의 차례 주고받기와 자기조절 전략 사용에서 진전을 보였다. 보드게임에서 협력적 자세를 유지했고, 좌절 시 심호흡 전략을 자발적으로 사용한 사례가 관찰되었다.',
    social: '또래와 차례 주고받기 5회 이상 유지. 친구 의견에 "그래" 동의 표현 3회.',
    emo: '게임 패배 시 "다시 하자" 제안 (자기조절 전략 자발 사용). 심호흡 카드 3회 자발 활용.',
    ts: '자기조절 카드 환경별 비치 효과 확인. 또래 매개 전략 추가 시도 필요.',
    adjust: '다음 주: ① 또래 매개 활동 주 2회로 확대 ② 갈등 해결 단계 카드 학교 도입 ③ 누나와의 협력 놀이 시간 확보.',
  };
  c.activities.weekly = {
    weekOf: '2026-03-16',
    social: '또래 차례 주고받기 안정화.',
    emo: '자기조절 전략 자발 사용 증가.',
    ts: '환경별 시각 카드 효과 확인.',
    adjust: '또래 매개 확대, 갈등 해결 카드 도입.',
  };

  // 가족 지원 계획서
  c.familySupport = {
    meta: { weekOf: '2026-02', meetingDate: '2026-02-07', participants: '어머니, 아버지, 민다혜 (BCBA)' },
    currentConcerns: '학교 입학 후 또래와의 갈등이 잦아지고, 특히 자기 관심 주제(공룡, 지하철)만 고집해 친구 관계 형성이 어려움. 누나와의 게임에서도 패배 수용 어려움.',
    childStrengths: '문장 표현이 풍부하고 자기조절 전략(심호흡·혼잣말)을 알고 사용함. 친숙한 어른과의 대화는 길게 이어감.',
    familyGoals: [
      '학교에서 친구 1-2명과 안정적으로 놀기',
      '관심 외 주제로도 5분 이상 대화 유지',
      '갈등·패배 상황에서 자기조절 전략 자발 사용',
    ],
    homeStrategies: [
      { area: '의사소통', strategy: '가정에서도 지훈이 관심 주제 외 다른 주제로 5분 이상 대화 시도', whenToUse: '식사 시간·이동 시간', resourcesNeeded: '오늘의 주제 카드' },
      { area: '정서 조절', strategy: '게임 시작 전 "이길 수도 지을 수도 있어" 약속, 패배 시 심호흡 시범', whenToUse: '누나와 게임할 때', resourcesNeeded: '심호흡 카드, 자기조절 전략 도구' },
      { area: '또래 관계', strategy: '주말에 친구 1명 초대해 구조화된 활동 (보드게임·블록) 1시간', whenToUse: '주말 오후', resourcesNeeded: '협력 보드게임, 갈등 해결 카드' },
    ],
    educationTopics: [
      { topic: 'SCERTS 대화 파트너 단계 이해', notes: '책 「대화의 기술 키우기」 챕터 4-5 안내함' },
      { topic: '관심사 융통성 키우기 전략', notes: '시범 영상 + 가정 실습 자료 제공' },
    ],
    followUp: '2주 후 가정 갈등 사례 (영상 또는 일지) 공유. 적용도 점검.',
    nextMeeting: '2026-02-21',
  };

  // 전문가 협력
  c.profSupport = {
    meta: { weekOf: '2026-02', meetingDate: '2026-02-09', teamMembers: '민다혜(BCBA), 박OO(통합학급 담임), 이OO(특수교사), 부모' },
    sharedObservations: '학교에서 자기 관심 주제로 친구에게 일방적으로 말함. 친구 의견 듣기 어려움. 가정에서도 누나와 게임 시 갈등 잦음. 자기조절 전략은 알고 있으나 자발성 부족.',
    currentChallenges: '관심 외 주제 수용·대화 차례 주고받기·갈등 상황 자기조절 자발성이 핵심 과제.',
    collaborativeGoals: [
      '학교·가정·치료실에서 동일한 자기조절 전략 카드 사용',
      '학교 통합학급에서 또래 매개 활동 주 2회 확보',
      '갈등 해결 단계 카드 학교·가정 동시 도입',
    ],
    roleResponsibilities: [
      { role: '주 치료사', name: '민다혜 (BCBA)', responsibilities: '진단·IEP, 갈등 해결 카드 제작, 부모 코칭' },
      { role: '통합학급 담임', name: '박OO', responsibilities: '학급 내 또래 매개 활동 운영, 갈등 시 중재' },
      { role: '특수교사', name: '이OO', responsibilities: '주 1회 사회성 그룹 운영, 자기조절 카드 사용 지도' },
      { role: '부모', name: '최수정 (어머니)', responsibilities: '가정 전략 실행, 주말 또래 초대 운영' },
    ],
    communicationPlan: '주 1회 알림장, 카카오톡 그룹방. 월 1회 정기 회의(2시간).',
    caseConferenceNotes: '2026-02-09 회의 결정: ① 자기조절 카드 학교·가정 동시 도입 ② 또래 매개 활동 주 2회 ③ 갈등 해결 단계 카드 다음 회의 전 완성.',
    nextReview: '2026-03-09',
  };

  // 의사소통 일정표
  c.communicationSchedule = {
    meta: { observedBy: '민다혜', observedAt: '2026-02-20', setting: '학교 일과 + 가정' },
    activities: [
      { id: 'a_arrival', time: '08:30-09:00', name: '등교', opportunities: '친구·교사 인사, 일과 확인', currentBehavior: '특정 친구에게는 인사하나 다른 친구 무관심', supports: '담임이 "오늘 누구에게 인사할까?" 짧게 안내', goals: '아침마다 다른 친구 1명에게 인사' },
      { id: 'a_class', time: '09:00-12:00', name: '수업 시간', opportunities: '발표·질문·또래 협력', currentBehavior: '관심 주제 발표는 적극, 그 외에는 위축', supports: '발표 차례 미리 예고, 짧고 명확한 질문 형태로 안내', goals: '관심 외 주제에서도 1일 1회 자발 발표' },
      { id: 'a_lunch', time: '12:00-13:00', name: '점심·자유 시간', opportunities: '또래와 대화·놀이', currentBehavior: '관심 주제(공룡·지하철)만 고집', supports: '"오늘은 친구가 좋아하는 것 물어보기" 미션 카드', goals: '또래 의견 듣기 5회 이상' },
      { id: 'a_pe', time: '13:00-14:00', name: '체육·예술', opportunities: '협력 활동, 차례 기다리기', currentBehavior: '규칙 있는 활동은 잘 따름', supports: '활동 순서 시각 안내, 갈등 시 카드 사용', goals: '갈등 발생 시 갈등 해결 카드 자발 사용 1회 이상' },
      { id: 'a_dismiss', time: '14:30-15:00', name: '하교', opportunities: '친구·교사 인사, 다음 약속', currentBehavior: '엄마 보면 환하게 웃음', supports: '하교 5분 전 다음 일정 시각 안내', goals: '담임·친구에게 작별 인사' },
      { id: 'a_dinner', time: '18:00-19:00', name: '가정 저녁 식사', opportunities: '하루 일과 공유, 가족 대화', currentBehavior: '오늘 있었던 일 잘 이야기함', supports: '"누나가 오늘 뭐했어?" 식의 타인 관점 질문', goals: '저녁 식사 중 타인 관점 질문 3회 이상' },
      { id: 'a_play', time: '19:00-20:00', name: '가족 놀이', opportunities: '누나와 협력 놀이, 차례 주고받기', currentBehavior: '관심 활동에는 적극, 갈등 시 자기 주장 강함', supports: '게임 시작 전 규칙 약속, 패배 시 심호흡 시범', goals: '게임 패배 1회 자기조절 전략 자발 사용' },
    ],
    summary: '지훈이는 익숙하고 좋아하는 활동에서 의사소통이 활발하나, 또래 관점 수용·갈등 상황 자기조절에서 어려움을 보임. 환경별 동일한 시각 카드와 또래 매개 전략이 효과적.',
    keyOpportunities: '① 점심·자유 시간 또래와의 대화 ② 갈등 발생 시 카드 사용 ③ 가족 식사 시간 타인 관점 질문 — 모든 환경에서 자기조절·관점 수용 전략 일관 적용.',
  };

  // 행동 기능 평가 (FBA) — 게임 패배 시 정서 폭발
  c.fba = {
    meta: { observedBy: '민다혜 (BCBA)', observedAt: '2026-01-20 ~ 2026-02-03', setting: '가정 + 학교' },
    behavior: {
      operationalDefinition: '게임·과제에서 패배·실수 시 30초 이상 큰 소리로 "싫어!"라고 외치거나, 게임판을 밀치거나, 자리를 박차고 떠나는 행동.',
      intensity: '3',
      frequency: '주 평균 4-5회 (가정 보드게임 2회, 학교 활동 2-3회)',
      duration: '평균 2-3분',
      impact: '또래 관계 형성 방해, 가족 갈등, 학습 활동 중단.',
    },
    abc: [
      { id: 'abc1', date: '2026-01-22', setting: '가정 (누나와 보드게임)', antecedent: '주사위에서 낮은 수가 나와 뒤처짐', behavior: '"싫어!" 외치고 게임판을 밀침', consequence: '누나가 화내고 자리 떠남 → 5분 뒤 엄마 중재로 사과', notes: '시작 전 규칙 약속 없음' },
      { id: 'abc2', date: '2026-01-28', setting: '학교 (수학 시간)', antecedent: '문제를 틀림, 친구는 맞춤', behavior: '"안 해!" 외치고 책상에 엎드림', consequence: '담임이 잠시 쉬게 허용 → 3분 뒤 다시 참여', notes: '자기조절 카드 미사용' },
      { id: 'abc3', date: '2026-02-02', setting: '치료실 (협력 게임)', antecedent: '게임 시작 전 "이길 수도 지을 수도 있어" 약속, 카드 비치. 게임에서 짐', behavior: '잠시 입을 삐죽이다 심호흡 카드 보며 진정', consequence: '"다시 하자" 제안', notes: '사전 약속 + 카드 효과 확인' },
    ],
    functions: {
      escape: true,
      attention: true,
      tangible: false,
      sensory: false,
      regulation: true,
      communication: false,
      notes: '주 기능: ① 회피(실패 상황) ② 관심 끌기(좌절 표현) ③ 정서 조절 미숙(자발 전략 사용 부족). 대체 행동(전략 카드 사용·"다시 하자" 제안)이 가능하나 자발성이 부족함.',
    },
    emotionalContext: {
      arousalLevel: '높음 (패배·실수 직후 급상승)',
      triggers: '패배·실수, 친구가 더 잘함, 예고 없는 규칙 변경, 피곤한 상태',
      protectiveFactors: '심호흡 카드, 사전 규칙 약속, 좋아하는 진정 활동(공룡책), 충분한 수면',
    },
    replacement: {
      replacementBehavior: '심호흡 카드 자발 사용, "다시 하자" 제안, "괜찮아"라는 자기 격려',
      teachingStrategy: '① 게임 시작 전 카드 위치·사용법 확인 ② 좌절 신호 포착 시 카드 시범 ③ 자발 사용 시 즉각 칭찬·강화',
      reinforcement: '대체 행동 사용 시: 즉각적 인정·칭찬, 좋아하는 활동 짧게 제공. 폭발 시: 안전 확보 후 차분히 기다리고 진정 후 카드 시범.',
      environmentalChanges: '게임 시작 전 규칙 약속 + 카드 비치, 환경마다 (학교·가정·치료실) 동일한 카드 사용, 좋아하는 진정 활동 가까이 두기.',
    },
    preventionPlan: '① 활동 전 규칙 약속 ② 카드 시각적 비치 ③ 피곤·배고픔 사전 점검 ④ 짧은 휴식 기회 사전 제공.',
    crisisPlan: '폭발 시: 1) 안전 확보 2) 차분히 "속상해" 짚기 3) 진정 후 카드 시범 4) 사과·재시작 도움.',
    monitoringPlan: '주 1회 ABC 기록(가정·학교 각 1건), 월 1회 빈도·자발 사용률 그래프 작성.',
  };

  return c;
}

// legacy 단일 워크스페이스를 신규 아동 구조로 마이그레이션
function migrateLegacyWs(legacyWs) {
  if (!legacyWs) return null;
  const child = blankChild(legacyWs.meta?.childName || '');
  child.meta = { ...child.meta, ...(legacyWs.meta || {}) };
  child.decision = legacyWs.decision || child.decision;
  child.interview = legacyWs.interview || child.interview;
  child.observation = legacyWs.observation || child.observation;
  child.familyPriorities = legacyWs.familyPriorities || child.familyPriorities;
  child.iep = legacyWs.iep || child.iep;
  child.interim = legacyWs.interim || child.interim;
  child.activities = legacyWs.activities || child.activities;
  child.familySupport = legacyWs.familySupport || child.familySupport;
  child.profSupport = legacyWs.profSupport || child.profSupport;
  child.communicationSchedule = legacyWs.communicationSchedule || child.communicationSchedule;
  child.fba = legacyWs.fba || child.fba;

  // legacy assessment / pre / post 를 세션 배열로 변환
  child.sessions = [];
  const a = legacyWs.assessment;
  if (a && (Object.keys(a.scores || {}).length > 0 || Object.keys(a.ses || {}).length > 0)) {
    const s = blankSession(`현재 (${a.quarter}Q)`, a.quarter);
    s.scores = a.scores || {};
    s.ses = a.ses || {};
    s.notes = a.notes || '';
    child.sessions.push(s);
  }
  if (legacyWs.pre) {
    const s = blankSession('사전 진단', 1);
    s.scores = legacyWs.pre.scores || {};
    s.ses = legacyWs.pre.ses || {};
    s.designation = 'pre';
    child.sessions.push(s);
  }
  if (legacyWs.post) {
    const s = blankSession('사후 진단', 4);
    s.scores = legacyWs.post.scores || {};
    s.ses = legacyWs.post.ses || {};
    s.designation = 'post';
    child.sessions.push(s);
  }
  if (child.sessions.length === 0) {
    child.sessions = [blankSession('초기 진단', 1)];
  }
  child.activeSessionId = child.sessions[0].id;
  return child;
}

// 신규 상태 로드: legacy 단일 워크스페이스 또는 신규 다중 아동 구조
function loadState() {
  try {
    const raw = localStorage.getItem(LS_STATE);
    if (raw) {
      const parsed = JSON.parse(raw);
      // children 배열이 존재하면 그대로 존중 (사용자가 의도적으로 0명으로 비운 경우 포함)
      if (parsed.children && Array.isArray(parsed.children)) {
        if (parsed.children.length === 0) {
          return { children: [], activeChildId: null };
        }
        return parsed;
      }
    }
    // legacy 마이그레이션
    const legacy = localStorage.getItem(LS_KEY);
    if (legacy) {
      const ws = JSON.parse(legacy);
      const child = migrateLegacyWs(ws);
      if (child) return { children: [child], activeChildId: child.id };
    }
  } catch (e) {}
  // 첫 방문(저장 이력 없음): 아동 목록 비어있게 시작 (사용자가 "새 아동 추가"로 명시적으로 만들도록)
  return { children: [], activeChildId: null };
}

// 활성 아동/활성 세션을 기존 `ws` 인터페이스로 어댑팅
function getActiveWs(state) {
  const child = state.children.find((c) => c.id === state.activeChildId);
  if (!child) {
    // 아동이 0명일 때: 하위 코드가 깨지지 않도록 빈 더미 ws 반환 (_empty 플래그)
    const dummy = blankChild('');
    return {
      meta: dummy.meta, decision: dummy.decision, interview: dummy.interview,
      observation: dummy.observation, familyPriorities: dummy.familyPriorities,
      assessment: { quarter: '', scores: {}, ses: {}, notes: '' },
      pre: null, post: null,
      iep: dummy.iep, interim: dummy.interim, activities: dummy.activities,
      familySupport: dummy.familySupport, profSupport: dummy.profSupport,
      communicationSchedule: dummy.communicationSchedule, fba: dummy.fba,
      _childId: null, _sessionId: null, _allSessions: [], _preSession: null, _postSession: null,
      _empty: true,
    };
  }
  const session = (child.sessions || []).find((s) => s.id === child.activeSessionId)
                  || (child.sessions || [])[0]
                  || blankSession();
  const preSession = (child.sessions || []).find((s) => s.designation === 'pre');
  const postSession = (child.sessions || []).find((s) => s.designation === 'post');
  return {
    meta: child.meta,
    decision: child.decision,
    interview: child.interview,
    observation: child.observation,
    familyPriorities: child.familyPriorities,
    assessment: {
      quarter: session.quarter,
      scores: session.scores,
      ses: session.ses,
      notes: session.notes,
    },
    pre: preSession ? { scores: preSession.scores, ses: preSession.ses } : null,
    post: postSession ? { scores: postSession.scores, ses: postSession.ses } : null,
    iep: child.iep,
    interim: child.interim,
    activities: child.activities,
    familySupport: child.familySupport,
    profSupport: child.profSupport,
    communicationSchedule: child.communicationSchedule,
    fba: child.fba,
    // 다중 세션 메타 노출
    _childId: child.id,
    _viewingTeacher: state._viewingTeacher || null,
    _sessionId: session.id,
    _allSessions: child.sessions || [],
    _preSession: preSession,
    _postSession: postSession,
  };
}

// 활성 ws에 대한 setWs — child/session에 다시 매핑
function applyWsUpdate(state, updaterOrValue) {
  const oldWs = getActiveWs(state);
  if (!oldWs) return state;
  const newWs = typeof updaterOrValue === 'function' ? updaterOrValue(oldWs) : updaterOrValue;
  const childIdx = state.children.findIndex((c) => c.id === state.activeChildId);
  const child = state.children[childIdx];
  const sessionIdx = (child.sessions || []).findIndex((s) => s.id === child.activeSessionId);
  const updatedChild = {
    ...child,
    meta: newWs.meta,
    decision: newWs.decision,
    interview: newWs.interview,
    observation: newWs.observation,
    familyPriorities: newWs.familyPriorities,
    iep: newWs.iep,
    interim: newWs.interim,
    activities: newWs.activities,
    familySupport: newWs.familySupport,
    profSupport: newWs.profSupport,
    communicationSchedule: newWs.communicationSchedule,
    fba: newWs.fba,
    sessions: sessionIdx >= 0
      ? child.sessions.map((s, i) => i === sessionIdx ? {
          ...s,
          quarter: newWs.assessment.quarter,
          scores: newWs.assessment.scores,
          ses: newWs.assessment.ses,
          notes: newWs.assessment.notes,
        } : s)
      : child.sessions,
  };
  return {
    ...state,
    children: state.children.map((c, i) => i === childIdx ? updatedChild : c),
  };
}

const blankWorkspace = () => ({
  meta: {
    childName: '',
    birthDate: '',
    className: '',
    therapist: '민 다 혜',
    startDate: '',
    reportDate: new Date().toISOString().slice(0, 10),
    stage: null,                  // 'social' | 'language' | 'conversation' | null
  },
  decision: { q1: {}, q2: {} },   // 단계 결정 체크
  interview: {                    // 단계별 질문지 답변 {[questionId]: 답변}
    meta: { name: '', age: '', date: '', reporter: '', relation: '' },
    answers: {},
  },
  familyPriorities: {              // SCERTS 가족 견해 및 우선순위 (원전 p.20/42/67)
    profileAccurate: '',           // 프로파일이 자녀를 정확히 묘사하는가
    additionalInfo: '',            // 추가 정보 필요사항
    focusOne: '',                  // "한 가지에 집중한다면" 자유서술
    focusGoalIds: [],              // 가족이 우선 선택한 진단 항목 ID 목록 (가중치 보너스)
    threeMonthHope: '',            // 앞으로 3개월 내 바라는 기술
  },
  observation: {                  // 관찰 계획 (관찰 1, 관찰 2)
    plans: [{ id: 1 }, { id: 2 }],
    data: {},                     // {planId: {rowId: ...}}
  },
  assessment: blankAssessment(),
  pre: null,                       // 사전 진단 스냅샷
  post: null,                      // 사후 진단 스냅샷
  iep: {
    reportDate: '',
    annualGoals: { sc: '', er: '', ts: '' },
    shortGoals:  { sc: '', er: '', ts: '' },
    strategies:  { sc: '', er: '', ts: '' },
    measures:    { sc: '', er: '', ts: '' },
    currentLevel:{ sc: '', er: '', ts: '' },
    selectedGoals: [],          // 주간 우선순위 [{itemId, customGoal}]
    partnerGoals: [],
  },
  interim: {
    reportType: 'interim',
    reportDate: '',
    period: '',
    summary: '',
    domainSummary: {},           // {domain: progressText}
    observations: '',
    direction: '',
    closingReason: '',
    closingReasonDetail: '',
    goalAchievement: [],
    recommendation: '',
    familySuggestions: [
      '가정 내 감정 단어 노출 및 대화 확장 연습',
      '시각적 예고 및 감정 온도계 활용한 자기조절 지원',
      '질문 응답, 이야기 이어 말하기 활동을 통한 언어 사고력 자극',
    ],
  },
  closing: {
    period: '', reason: '', reasonDetail: '',
    overallProgress: '', domainProgress: {},
    goalAchievement: [], summary: '', recommendation: '',
  },
  activities: {                   // 활동 일지/주간기록/계획서
    logI: [],                     // 회기별 활동 일지 [{id, date, ...}]
    logII: { weekOf: '', daily: {}, summary: '' },
    weekly: { weekOf: '', social: '', emo: '', ts: '', adjust: '' },
    plan: { fields: {}, steps: '', goalsSocial: [], goalsEmo: [], partnerGoals: [], challenges: '' },
  },
});

// 저장/불러오기
function loadWorkspace() {
  try {
    const raw = localStorage.getItem(LS_KEY);
    if (!raw) return blankWorkspace();
    return { ...blankWorkspace(), ...JSON.parse(raw) };
  } catch (e) {
    return blankWorkspace();
  }
}

function loadArchive() {
  try {
    const raw = localStorage.getItem(LS_ARCHIVE);
    if (!raw) return [];
    return JSON.parse(raw);
  } catch (e) {
    return [];
  }
}

// =====================================================================
// 로그인 & 계정 관리 (Supabase Auth 기반)
// =====================================================================
const MAX_USERS = 10;
const DEVICE_ID_KEY = 'gd-aba-device-id';
// 데이터 저장 키 (user_id는 dataGet/dataSet이 자동 처리하므로 이름 접미사 불필요)
const STATE_PREFIX = 'gd-aba-state:';
const ARCHIVE_PREFIX = 'gd-aba-archive:';
// 이름을 안전한 키 문자열로 (공백/특수문자 제거)
const safeKeyName = (n) => (n || '_default').replace(/[\s/\\'"]/g, '_').substring(0, 50);
// 기기별 고유 ID (동시 편집 감지용)
function getDeviceId() {
  try {
    let id = localStorage.getItem(DEVICE_ID_KEY);
    if (!id) {
      id = 'd_' + Math.random().toString(36).slice(2, 10) + '_' + Date.now().toString(36);
      localStorage.setItem(DEVICE_ID_KEY, id);
    }
    return id;
  } catch (e) { return 'd_anon'; }
}

// =====================================================================
// 메인 App
// =====================================================================
export default function App() {
  // ── 해시 라우터: #/fill/{token} 이면 외부(부모) 작성 페이지 ──
  // (부모는 로그인하지 않으므로 세션/로그인 체크보다 먼저 처리)
  const [hash, setHash] = useState(typeof window !== 'undefined' ? window.location.hash : '');
  useEffect(() => {
    const onHash = () => setHash(window.location.hash);
    window.addEventListener('hashchange', onHash);
    return () => window.removeEventListener('hashchange', onHash);
  }, []);

  // ── 로그인 상태 ──
  // authUser: { id, email, name(display_name), role }
  const [authUser, setAuthUser] = useState(null);
  const [authLoading, setAuthLoading] = useState(true);
  const [loginEmail, setLoginEmail] = useState('');
  const [loginPw, setLoginPw] = useState('');
  const [loginError, setLoginError] = useState('');
  const [userList, setUserList] = useState([]); // 관리자용 전체 유저 목록

  // 앱 시작 시: Supabase Auth 세션 복원
  useEffect(() => {
    (async () => {
      try {
        const user = await getCurrentUser();
        if (user?.id) {
          const meta = user.user_metadata || {};
          setAuthUser({
            id: user.id,
            email: user.email,
            name: meta.display_name || user.email.split('@')[0],
            role: meta.role || 'therapist',
          });
        }
      } catch (e) {}
      setAuthLoading(false);
    })();
  }, []);

  // 관리자 로그인 시: 전체 유저 목록 로드
  useEffect(() => {
    if (authUser?.role === 'admin') {
      (async () => {
        const list = await adminListUsers();
        setUserList(list || []);
      })();
    } else {
      setUserList([]);
    }
  }, [authUser?.role]);

  const refreshUserList = async () => {
    if (authUser?.role !== 'admin') return;
    const list = await adminListUsers();
    setUserList(list || []);
  };

  const handleLogin = async () => {
    const email = loginEmail.trim();
    const pw = loginPw.trim();
    if (!email || !pw) { setLoginError('이메일과 비밀번호를 입력하세요.'); return; }
    setLoginError('');
    const result = await signInWithPassword(email, pw);
    if (result.error) {
      // Supabase의 영문 에러를 한국어로 순화
      const err = result.error.toLowerCase();
      if (err.includes('invalid') || err.includes('credential')) {
        setLoginError('이메일 또는 비밀번호가 일치하지 않습니다.');
      } else if (err.includes('not confirmed')) {
        setLoginError('이메일 확인이 필요합니다. 관리자에게 문의하세요.');
      } else {
        setLoginError(result.error);
      }
      return;
    }
    // 로그인 성공
    const user = result.user;
    const meta = user?.user_metadata || {};
    setAuthUser({
      id: user.id,
      email: user.email,
      name: meta.display_name || user.email.split('@')[0],
      role: meta.role || 'therapist',
    });
    setLoginEmail(''); setLoginPw(''); // 평문 비번 메모리에 안 남기기
  };

  const handleLogout = async () => {
    setAuthUser(null);
    setLoginEmail(''); setLoginPw(''); setLoginError('');
    await signOut();
  };

  // ── 계정 관리 (관리자 전용) ──
  const addUser = async (email, pw, displayName) => {
    const em = (email || '').trim().toLowerCase();
    const pwd = (pw || '').trim();
    const nm = (displayName || '').trim();
    if (!em) return { ok: false, msg: '이메일을 입력해주세요.' };
    if (!em.includes('@')) return { ok: false, msg: '올바른 이메일 형식이 아닙니다.' };
    if (!pwd) return { ok: false, msg: '비밀번호를 입력해주세요.' };
    if (pwd.length < 6) return { ok: false, msg: '비밀번호는 6자 이상이어야 합니다.' };
    if (!nm) return { ok: false, msg: '선생님 이름을 입력해주세요.' };
    if (userList.length >= MAX_USERS) return { ok: false, msg: `최대 ${MAX_USERS}명까지 등록 가능합니다.` };
    if (userList.some((u) => u.email === em)) return { ok: false, msg: '이미 등록된 이메일입니다.' };
    const result = await adminCreateUser(em, pwd, nm);
    if (result.error) return { ok: false, msg: result.error };
    await refreshUserList();
    return { ok: true };
  };

  const removeUser = async (userId) => {
    const result = await adminDeleteUser(userId);
    if (result.error) return { ok: false, msg: result.error };
    await refreshUserList();
    return { ok: true };
  };

  const changeUserPw = async (userId, newPw) => {
    const pwd = (newPw || '').trim();
    if (!pwd) return { ok: false, msg: '새 비밀번호를 입력하세요.' };
    if (pwd.length < 6) return { ok: false, msg: '비밀번호는 6자 이상이어야 합니다.' };
    const result = await adminUpdateUserPassword(userId, pwd);
    if (result.error) return { ok: false, msg: result.error };
    return { ok: true };
  };

  // 부모용 링크(#/fill/{token})면 로그인 없이 외부 작성 페이지 렌더
  const fillMatch = (hash || '').match(/^#\/fill\/(.+)$/);
  if (fillMatch) {
    const parts = fillMatch[1].split('/');
    const token = parts[parts.length - 1];
    return <ExternalFillPage token={token} />;
  }

  return <AppInner
    key={authUser?.id || '__none__'}
    authUser={authUser} authLoading={authLoading}
    loginEmail={loginEmail} setLoginEmail={setLoginEmail}
    loginPw={loginPw} setLoginPw={setLoginPw}
    loginError={loginError} handleLogin={handleLogin}
    handleLogout={handleLogout}
    userList={userList} refreshUserList={refreshUserList}
    addUser={addUser} removeUser={removeUser} changeUserPw={changeUserPw}
  />;
}

// 실제 앱 본체 (로그인 통과 후)
function AppInner({ authUser, authLoading, loginEmail, setLoginEmail, loginPw, setLoginPw, loginError, handleLogin, handleLogout, userList, refreshUserList, addUser, removeUser, changeUserPw }) {
  const [state, setStateRaw] = useState(loadState);
  const [archive, setArchive] = useState(loadArchive);
  const [showAccountPanel, setShowAccountPanel] = useState(false);
  const [showAdminDash, setShowAdminDash] = useState(false);
  const [showHelp, setShowHelp] = useState(false);
  const [showCopyright, setShowCopyright] = useState(false);
  const [lastSavedAt, setLastSavedAt] = useState(null);
  const lastSavedAtRef = useRef(null);
  const [concurrentEditor, setConcurrentEditor] = useState(null);

  // 동시편집 감지: 주기적으로 공유 저장소 확인해서 다른 기기가 더 최근에 저장했는지 점검
  useEffect(() => {
    if (!authUser?.name || !window.storage) return;
    let timer;
    const check = async () => {
      try {
        const r = await window.storage.get('gd-aba-state', true);
        if (r?.value) {
          const remote = JSON.parse(r.value);
          const remoteEditor = remote._lastEditor;
          const myId = getDeviceId();
          const mySaved = lastSavedAtRef.current;
          // "진짜 동시 편집"으로 판단하는 조건:
          //  1. 다른 기기가 저장한 기록이 있고
          //  2. 그 저장이 최근 2분 이내이며
          //  3. 내가 이 세션에서 적어도 한 번 저장한 적이 있고
          //  4. 다른 기기의 저장이 내 마지막 저장보다 최근일 때만
          const TWO_MINUTES = 2 * 60 * 1000;
          const now = Date.now();
          if (remoteEditor && remoteEditor.deviceId !== myId
              && (now - remoteEditor.at) < TWO_MINUTES
              && mySaved && remoteEditor.at > mySaved + 1000) {
            setConcurrentEditor({ at: new Date(remoteEditor.at).toLocaleString('ko-KR') });
          }
        }
      } catch (e) {}
      timer = setTimeout(check, 5000); // 5초마다
    };
    timer = setTimeout(check, 5000);
    return () => { if (timer) clearTimeout(timer); };
  }, [authUser?.name]);

  // 첫 방문 자동 안내 (기기별 1회)
  useEffect(() => {
    if (!authUser?.name) return;
    try {
      const k = 'gd-aba-help-seen';
      if (!localStorage.getItem(k)) {
        setShowHelp(true);
        localStorage.setItem(k, '1');
      }
    } catch (e) {}
  }, [authUser?.name]);
  const [allTeacherData, setAllTeacherData] = useState([]); // [{teacher, children:[{name, key, snapshot}]}]
  const [adminLoading, setAdminLoading] = useState(false);
  const sharedLoadedRef = useRef(false);
  const viewEditWarnedRef = useRef(false);

  // 관리자: 모든 선생님의 데이터를 RPC 함수로 수집
  const loadAllTeacherData = useCallback(async () => {
    setAdminLoading(true);
    try {
      // 1. 모든 유저 목록 조회 (admin_list_users) — 관리자도 포함
      const users = await adminListUsers();
      const teachers = users || [];
      const collected = [];
      // 2. 각 선생님의 데이터 조회 (admin_get_user_data)
      for (const t of teachers) {
        try {
          const rows = await adminGetUserData(t.user_id);
          // rows에서 'gd-aba-state' 키만 찾아 파싱
          const stateRow = (rows || []).find((r) => r.key === 'gd-aba-state');
          if (!stateRow?.value) {
            collected.push({ teacher: t.display_name || t.email, childCount: 0, children: [], snapshot: null });
            continue;
          }
          const st = JSON.parse(stateRow.value);
          const children = (st.children || []).map((c) => ({
            name: c.meta?.childName || '(이름 없음)',
            birth: c.meta?.birthDate || '',
            stage: c.meta?.stage || null,
            id: c.id,
          }));
          collected.push({
            teacher: t.display_name || t.email,
            teacherEmail: t.email,
            teacherId: t.user_id,
            childCount: children.length,
            children,
            snapshot: st,
          });
        } catch (e) {}
      }
      setAllTeacherData(collected);
    } catch (e) {
      setAllTeacherData([]);
    }
    setAdminLoading(false);
  }, []);

  // 로그인한 선생님의 데이터를 공유 저장소에서 불러온다 (게시 환경에서만)
  useEffect(() => {
    let cancelled = false;
    (async () => {
      if (!authUser?.name) return;
      if (!window.storage) {
        // 게시 안 된 환경: 공유 저장소 없음 → localStorage 그대로 사용
        sharedLoadedRef.current = true;
        return;
      }
      try {
        const key = 'gd-aba-state';
        const r = await window.storage.get(key, true);
        if (!cancelled && r?.value) {
          const loaded = JSON.parse(r.value);
          if (loaded && Array.isArray(loaded.children)) {
            setStateRaw(loaded);
          }
        }
      } catch (e) {}
      try {
        const akey = 'gd-aba-archive';
        const ar = await window.storage.get(akey, true);
        if (!cancelled && ar?.value) {
          const loadedArchive = JSON.parse(ar.value);
          if (Array.isArray(loadedArchive)) setArchive(loadedArchive);
        }
      } catch (e) {}
      if (!cancelled) sharedLoadedRef.current = true;
    })();
    return () => { cancelled = true; };
    // authUser.name이 바뀔 때(로그인/계정전환)마다 재로드
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [authUser?.name]);
  const [tab, setTab] = useState('home');
  const [toast, setToast] = useState(null);
  const [showBackupPanel, setShowBackupPanel] = useState(false);
  // 히스토리 가용 여부 (버튼 disabled용)
  const [historyVersion, setHistoryVersion] = useState({ canUndo: false, canRedo: false });

  // ── Undo/Redo 히스토리 ──
  const historyRef = useRef({ past: [], future: [], lastPushed: null });
  const MAX_HISTORY = 30;

  const pushHistory = useCallback((prevState) => {
    const h = historyRef.current;
    const serialized = JSON.stringify(prevState);
    if (h.lastPushed === serialized) return;
    h.past.push(serialized);
    if (h.past.length > MAX_HISTORY) h.past.shift();
    h.future = [];
    h.lastPushed = serialized;
    setHistoryVersion({ canUndo: h.past.length > 0, canRedo: false });
  }, []);

  const setState = useCallback((updaterOrValue) => {
    setStateRaw((prev) => {
      const next = typeof updaterOrValue === 'function' ? updaterOrValue(prev) : updaterOrValue;
      if (next !== prev) pushHistory(prev);
      return next;
    });
  }, [pushHistory]);

  const undo = useCallback(() => {
    const h = historyRef.current;
    if (h.past.length === 0) return false;
    setStateRaw((cur) => {
      const prevSerialized = h.past.pop();
      h.future.push(JSON.stringify(cur));
      h.lastPushed = prevSerialized;
      setHistoryVersion({ canUndo: h.past.length > 0, canRedo: h.future.length > 0 });
      return JSON.parse(prevSerialized);
    });
    return true;
  }, []);

  const redo = useCallback(() => {
    const h = historyRef.current;
    if (h.future.length === 0) return false;
    setStateRaw((cur) => {
      const nextSerialized = h.future.pop();
      h.past.push(JSON.stringify(cur));
      h.lastPushed = nextSerialized;
      setHistoryVersion({ canUndo: h.past.length > 0, canRedo: h.future.length > 0 });
      return JSON.parse(nextSerialized);
    });
    return true;
  }, []);

  // ── 키보드 단축키 (Cmd/Ctrl+Z, Cmd/Ctrl+Shift+Z) ──
  useEffect(() => {
    const handler = (e) => {
      const isMod = e.metaKey || e.ctrlKey;
      if (!isMod) return;
      // input/textarea 안에서는 native undo/redo 우선
      const tag = (e.target.tagName || '').toLowerCase();
      if (tag === 'input' || tag === 'textarea') return;

      if (e.key === 'z' && !e.shiftKey) {
        e.preventDefault();
        const ok = undo();
        if (ok) setToast('실행 취소됨');
      } else if ((e.key === 'z' && e.shiftKey) || e.key === 'y') {
        e.preventDefault();
        const ok = redo();
        if (ok) setToast('다시 실행됨');
      }
    };
    window.addEventListener('keydown', handler);
    return () => window.removeEventListener('keydown', handler);
  }, [undo, redo]);

  // 활성 아동의 ws 어댑터 (기존 컴포넌트 호환)
  const ws = useMemo(() => getActiveWs(state), [state]);
  const showToast = useCallback((msg) => {
    setToast(msg);
    setTimeout(() => setToast(null), 2200);
  }, []);

  const setWs = useCallback((updaterOrValue) => {
    setState((s) => {
      if (s._viewingTeacher) {
        // 조회 모드: 편집 차단 (관리자가 남의 데이터를 수정/저장하지 못하게)
        if (!viewEditWarnedRef.current) {
          viewEditWarnedRef.current = true;
          setTimeout(() => {
            showToast(`${s._viewingTeacher} 선생님 데이터는 읽기 전용입니다`);
            viewEditWarnedRef.current = false;
          }, 0);
        }
        return s;
      }
      return applyWsUpdate(s, updaterOrValue);
    });
  }, [setState, showToast]);

  // 자동 저장 (디바운스) + 회전 백업 + 동시편집 추적
  useEffect(() => {
    if (!sharedLoadedRef.current) return; // 공유 로드 완료 전엔 저장 안 함(빈 데이터 덮어쓰기 방지)
    if (state._viewingTeacher) return;     // 관리자가 다른 선생님 데이터 조회 중이면 저장 안 함(키 오염 방지)
    const t = setTimeout(() => {
      try {
        // 저장 시점에 이 기기의 흔적을 함께 기록 (동시편집 감지용)
        const stamped = {
          ...state,
          _lastEditor: { deviceId: getDeviceId(), at: Date.now() },
        };
        localStorage.setItem(LS_STATE, JSON.stringify(stamped));
        saveBackup(stamped);
        if (window.storage && authUser?.name) {
          window.storage.set('gd-aba-state', JSON.stringify(stamped), true).catch(() => {});
        }
        const now = Date.now();
        lastSavedAtRef.current = now;
        setLastSavedAt(now);
      } catch (e) {}
    }, 500);
    return () => clearTimeout(t);
  }, [state, authUser]);

  useEffect(() => {
    if (!sharedLoadedRef.current) return;
    if (state._viewingTeacher) return;  // 조회 모드에선 보관함도 저장 안 함
    try {
      localStorage.setItem(LS_ARCHIVE, JSON.stringify(archive));
      if (window.storage && authUser?.name) {
        window.storage.set('gd-aba-archive', JSON.stringify(archive), true).catch(() => {});
      }
    } catch (e) {}
  }, [archive, authUser, state._viewingTeacher]);

  // 인쇄 대비: textarea를 항상 내용 높이에 맞춰 펼쳐 두고, 보고서의 조상
  // 체인에 마커 클래스를 달아 둔다. 이벤트에 의존하지 않고 화면 상태
  // 자체를 늘 "인쇄 가능한" 모양으로 유지한다.
  useEffect(() => {
    const prep = () => { autosizeTextareas(); };

    // 입력할 때마다 해당 textarea 즉시 조정 (위임 방식)
    const onInput = (e) => {
      const ta = e.target;
      if (ta && ta.tagName === 'TEXTAREA') {
        ta.style.height = 'auto';
        const hasContent = ta.value && ta.value.trim().length > 0;
        ta.style.height = hasContent ? (ta.scrollHeight + 2) + 'px' : '1.7em';
      }
    };
    document.addEventListener('input', onInput, true);

    // 마운트/탭 전환 직후 한 번씩 일괄 준비 (레이아웃 안정 후)
    const t1 = setTimeout(prep, 0);
    const t2 = setTimeout(prep, 300);

    // beforeprint 보조 (지원 환경에서 한 번 더 준비)
    window.addEventListener('beforeprint', prep);

    return () => {
      document.removeEventListener('input', onInput, true);
      window.removeEventListener('beforeprint', prep);
      clearTimeout(t1);
      clearTimeout(t2);
    };
  });

  // 아동 관리
  const switchChild = useCallback((childId) => {
    setState((s) => ({ ...s, activeChildId: childId }));
    setTab('home');
  }, []);
  const addChild = useCallback((name) => {
    let blocked = false;
    setState((s) => {
      if (s._viewingTeacher) { blocked = true; return s; }
      const child = blankChild(name);
      return { ...s, children: [...s.children, child], activeChildId: child.id };
    });
    if (blocked) { showToast('조회 모드에서는 추가할 수 없습니다. 먼저 "내 데이터로 돌아가기"를 누르세요'); return; }
    setTab('home');
    showToast(`${name || '새 아동'}이(가) 추가되었습니다`);
  }, [showToast]);

  const loadSampleChild = useCallback((stage = 'language') => {
    let blocked = false;
    setState((s) => {
      if (s._viewingTeacher) { blocked = true; return s; }
      // 기존 샘플 아동(_isSample) 모두 제거 후 새로 추가 → 항상 최신 샘플로 교체
      const withoutSample = s.children.filter((c) => !c._isSample);
      const child = stage === 'social' ? makeSampleChildSP()
                  : stage === 'conversation' ? makeSampleChildCP()
                  : makeSampleChild();
      return { ...s, children: [...withoutSample, child], activeChildId: child.id };
    });
    if (blocked) { showToast('조회 모드에서는 불러올 수 없습니다'); return; }
    setTab('home');
    const label = stage === 'social' ? '사회적 파트너 (김서아)'
                : stage === 'conversation' ? '대화 파트너 (이지훈)'
                : '언어 파트너 (민준호)';
    showToast(`샘플 아동 ${label}을(를) 불러왔습니다`);
  }, [showToast]);
  const removeChild = useCallback((childId) => {
    setState((s) => {
      const filtered = s.children.filter((c) => c.id !== childId);
      // 0명이 되면 activeChildId를 null로 (빈 상태 화면 표시)
      const newActive = filtered.length === 0
        ? null
        : (s.activeChildId === childId ? filtered[0].id : s.activeChildId);
      return { ...s, children: filtered, activeChildId: newActive };
    });
  }, []);
  const renameChild = useCallback((childId, name) => {
    setState((s) => ({
      ...s,
      children: s.children.map((c) => c.id === childId ? { ...c, meta: { ...c.meta, childName: name } } : c),
    }));
  }, []);

  // 세션 관리
  const switchSession = useCallback((sessionId) => {
    setState((s) => ({
      ...s,
      children: s.children.map((c) => c.id === s.activeChildId ? { ...c, activeSessionId: sessionId } : c),
    }));
  }, []);
  const addSession = useCallback((label, quarter) => {
    const newSes = blankSession(label, quarter || 1);
    setState((s) => ({
      ...s,
      children: s.children.map((c) => c.id === s.activeChildId
        ? { ...c, sessions: [...(c.sessions || []), newSes], activeSessionId: newSes.id }
        : c),
    }));
    showToast(`새 진단 세션 "${newSes.label}"이(가) 추가되었습니다`);
  }, [showToast]);
  const removeSession = useCallback((sessionId) => {
    setState((s) => ({
      ...s,
      children: s.children.map((c) => {
        if (c.id !== s.activeChildId) return c;
        if ((c.sessions || []).length <= 1) return c;
        const filtered = c.sessions.filter((x) => x.id !== sessionId);
        const newActive = c.activeSessionId === sessionId ? filtered[0].id : c.activeSessionId;
        return { ...c, sessions: filtered, activeSessionId: newActive };
      }),
    }));
  }, []);
  const updateSessionMeta = useCallback((sessionId, patch) => {
    setState((s) => ({
      ...s,
      children: s.children.map((c) => c.id === s.activeChildId
        ? { ...c, sessions: c.sessions.map((x) => x.id === sessionId ? { ...x, ...patch } : x) }
        : c),
    }));
  }, []);
  const setSessionDesignation = useCallback((sessionId, designation) => {
    setState((s) => ({
      ...s,
      children: s.children.map((c) => {
        if (c.id !== s.activeChildId) return c;
        // 같은 designation 다른 세션은 해제
        return {
          ...c,
          sessions: c.sessions.map((x) => {
            if (x.id === sessionId) return { ...x, designation };
            if (designation && x.designation === designation) return { ...x, designation: null };
            return x;
          }),
        };
      }),
    }));
  }, []);

  const updateMeta = useCallback((patch) => {
    setWs((s) => ({ ...s, meta: { ...s.meta, ...patch } }));
  }, [setWs]);

  // 진단 점수 변경
  const updateScore = useCallback((itemId, score) => {
    setWs((s) => {
      const newScores = { ...s.assessment.scores, [itemId]: score };
      // 원전 "=" 동일 항목 자동 연동 (예: JA1.1 채점 → MR2.3도 동일 점수)
      const stage = s.meta.stage;
      const equivalents = getEquivalentItems(stage, itemId);
      equivalents.forEach((eqId) => {
        if (score === undefined) {
          delete newScores[eqId];
        } else {
          newScores[eqId] = score;
        }
      });
      return {
        ...s,
        assessment: { ...s.assessment, scores: newScores },
      };
    });
  }, [setWs]);

  const updateSes = useCallback((id, value) => {
    setWs((s) => ({
      ...s,
      assessment: {
        ...s.assessment,
        ses: { ...s.assessment.ses, [id]: value },
      },
    }));
  }, [setWs]);

  // 사전/사후 저장: 현재 활성 세션을 사전/사후로 지정
  const savePre = () => {
    if (!ws._sessionId) return;
    setSessionDesignation(ws._sessionId, 'pre');
    showToast('현재 세션이 "사전 진단"으로 지정되었습니다');
  };
  const savePost = () => {
    if (!ws._sessionId) return;
    setSessionDesignation(ws._sessionId, 'post');
    showToast('현재 세션이 "사후 진단"으로 지정되었습니다');
  };

  // 보관함
  const archiveCurrent = (kind) => {
    if (!ws.meta.childName) {
      showToast('아동명을 먼저 입력해 주세요');
      return;
    }
    const item = {
      id: 'a_' + Date.now(),
      savedAt: new Date().toISOString(),
      kind, // 'iep' | 'interim'
      reportType: kind === 'interim' ? (ws.interim?.reportType || 'interim') : undefined,
      childId: ws._childId,
      childName: ws.meta.childName,
      snapshot: JSON.parse(JSON.stringify(ws)),
    };
    setArchive((a) => [item, ...a]);
    const savedLabel = kind === 'iep' ? 'IEP'
      : (ws.interim?.reportType === 'closing' ? '종결보고서' : '중간보고서');
    showToast(`${savedLabel}이(가) 보관함에 저장되었습니다`);
  };

  const removeArchive = (id) => {
    setArchive((a) => a.filter((x) => x.id !== id));
  };

  // JSON export/import (다중 아동 전체 백업)
  // 전체 백업 (모든 아동 + 보관함)
  const exportJSON = () => {
    const data = { state, archive, exportedAt: new Date().toISOString(), version: 2 };
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    const date = new Date().toISOString().slice(0, 10);
    a.download = `SCERTS_전체백업_${date}.json`;
    a.click();
    URL.revokeObjectURL(url);
    showToast(`전체 백업 다운로드 완료 (${state.children.length}명)`);
  };

  // 현재 아동만 export
  const exportCurrentChild = async () => {
    const child = state.children.find((c) => c.id === state.activeChildId);
    if (!child) return;
    const childArchive = archive.filter((a) => a.childId === child.id);
    const data = {
      state: { children: [child], activeChildId: child.id },
      archive: childArchive,
      exportedAt: new Date().toISOString(),
      version: 2,
      _singleChild: true,
    };
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    const name = (child.meta.childName || 'scerts').replace(/[\\/:*?"<>|]/g, '_');
    const date = new Date().toISOString().slice(0, 10);
    a.download = `SCERTS_${name}_${date}.json`;
    a.click();
    URL.revokeObjectURL(url);
    showToast(`${child.meta.childName || '현재 아동'} 데이터 다운로드 완료`);
  };

  const importJSON = async (file) => {
    const reader = new FileReader();
    reader.onload = async () => {
      try {
        const data = JSON.parse(reader.result);
        // v2: 다중 아동 구조
        if (data.version === 2 && data.state && data.state.children) {
          // 단일 아동 파일은 머지, 전체 백업은 교체 확인
          if (data._singleChild && data.state.children.length === 1) {
            const importedChild = data.state.children[0];
            const existing = state.children.find((c) => c.id === importedChild.id);
            const action = existing
              ? await appConfirm(`"${importedChild.meta.childName}"이(가) 이미 존재합니다.\n\n확인: 기존 데이터를 덮어쓰기\n취소: 새 아동으로 추가 (사본)`)
                ? 'overwrite' : 'add_copy'
              : 'add';
            setState((s) => {
              if (action === 'overwrite') {
                return { ...s, children: s.children.map((c) => c.id === importedChild.id ? importedChild : c) };
              }
              // 새 ID 부여하고 추가
              const newChild = action === 'add_copy'
                ? { ...importedChild, id: 'c_' + Date.now() + '_' + Math.random().toString(36).slice(2, 6),
                    meta: { ...importedChild.meta, childName: `${importedChild.meta.childName} (사본)` } }
                : importedChild;
              return { ...s, children: [...s.children, newChild], activeChildId: newChild.id };
            });
            if (data.archive) setArchive((cur) => [...data.archive, ...cur.filter((a) => !data.archive.some((d) => d.id === a.id))]);
            showToast(`${importedChild.meta.childName} 데이터 가져오기 완료`);
          } else {
            // 전체 백업: 교체 확인
            if (state.children.length > 1 || state.children[0].meta.childName) {
              if (!await appConfirm(`전체 백업 파일입니다 (${data.state.children.length}명).\n현재 ${state.children.length}명의 데이터가 모두 교체됩니다.\n진행하시겠습니까?`)) return;
            }
            setState(data.state);
            if (data.archive) setArchive(data.archive);
            showToast(`${data.state.children.length}명의 아동 데이터를 불러왔습니다`);
          }
        }
        // v1 legacy: 단일 ws를 새 아동으로 추가
        else if (data.ws) {
          const child = migrateLegacyWs(data.ws);
          if (child) {
            setState((s) => {
              const first = s.children[0];
              const isEmptyFirst = !first.meta.childName && !first.meta.stage;
              return isEmptyFirst
                ? { children: [child, ...s.children.slice(1)], activeChildId: child.id }
                : { children: [...s.children, child], activeChildId: child.id };
            });
          }
          if (data.archive) setArchive(data.archive);
          showToast('가져오기 완료 (v1 → v2 마이그레이션)');
        } else {
          showToast('알 수 없는 파일 형식입니다');
        }
      } catch (e) {
        showToast('파일을 읽을 수 없습니다');
      }
    };
    reader.readAsText(file);
  };

  // 자동 백업 복원
  const restoreBackup = async (backup) => {
    if (!await appConfirm(`${new Date(backup.timestamp).toLocaleString('ko-KR')} 시점으로 복원하시겠습니까?\n\n현재 작업 내용은 백업 슬롯에 자동 저장됩니다.`)) return;
    try {
      const restored = JSON.parse(backup.data);
      // 현재 상태도 백업으로 추가 (안전망)
      saveBackup(state);
      setState(restored);
      showToast('복원 완료');
    } catch (e) {
      showToast('복원에 실패했습니다');
    }
  };

  // 단계 자동 판별
  const recommendedStage = useMemo(() => {
    const q1 = STAGE_DECISION.q1.items.every((it) => ws.decision.q1[it.id] === true);
    if (!q1) return 'social';
    const q2 = STAGE_DECISION.q2.items.every((it) => ws.decision.q2[it.id] === true);
    if (!q2) return 'language';
    return 'conversation';
  }, [ws.decision]);

  // 새로 만들기 (활성 아동만 초기화)
  const newWorkspace = async () => {
    if (await appConfirm('현재 활성 아동의 모든 데이터가 초기화됩니다. 계속하시겠습니까?\n(다른 아동들은 영향받지 않습니다)')) {
      const fresh = blankChild('');
      setState((s) => ({
        ...s,
        children: s.children.map((c) => c.id === s.activeChildId ? { ...fresh, id: c.id } : c),
      }));
      setTab('home');
      showToast('현재 아동의 작업이 초기화되었습니다');
    }
  };

  // ── 로그인 게이트 ──
  if (authLoading) {
    return <div className="login-loading"><Style /><div>불러오는 중…</div></div>;
  }
  if (!authUser) {
    return (
      <div className="login-screen">
        <Style />
        <div className="login-box">
          <div className="login-brand">
            <div className="login-brand-mark">S</div>
            <div>
              <div className="login-brand-title">SCERTS 자동화 시스템</div>
              <div className="login-brand-sub">검단ABA언어행동연구소</div>
            </div>
          </div>
          <div className="login-fields">
            {/* 브라우저 자동완성 차단용 미끼 필드 (화면에 보이지 않음) */}
            <input type="text" name="username" tabIndex={-1} aria-hidden="true" autoComplete="username" style={{ position: 'absolute', opacity: 0, height: 0, width: 0, pointerEvents: 'none', zIndex: -1 }} />
            <input type="password" name="password" tabIndex={-1} aria-hidden="true" autoComplete="current-password" style={{ position: 'absolute', opacity: 0, height: 0, width: 0, pointerEvents: 'none', zIndex: -1 }} />
            <label className="login-label">이메일</label>
            <input className="login-input" type="email" value={loginEmail}
              onChange={(e) => setLoginEmail(e.target.value)}
              onKeyDown={(e) => { if (e.key === 'Enter') handleLogin(); }}
              placeholder="example@email.com" autoFocus
              autoComplete="off"
              name={`scerts-login-email-${Math.random().toString(36).slice(2, 8)}`}
              spellCheck={false}
              autoCorrect="off"
              autoCapitalize="off" />
            <label className="login-label">비밀번호</label>
            <input className="login-input" type="password" value={loginPw}
              onChange={(e) => setLoginPw(e.target.value)}
              onKeyDown={(e) => { if (e.key === 'Enter') handleLogin(); }}
              placeholder="비밀번호"
              autoComplete="new-password"
              name={`scerts-login-pw-${Math.random().toString(36).slice(2, 8)}`} />
            {loginError && <div className="login-error">{loginError}</div>}
            <button className="login-btn" onClick={handleLogin}>로그인</button>
          </div>
          <div className="login-hint">
            관리자에게 발급받은 이메일과 비밀번호로 로그인하세요.<br />
            계정은 관리자가 발급합니다.
          </div>
          <button type="button" className="login-help-link" onClick={() => setShowHelp(true)}>
            📘 SCERTS와 앱 사용법 안내 보기
          </button>
        </div>
        <div className="login-copyright">
          © 검단ABA언어행동연구소 · 민다혜 (BCBA) ·{' '}
          <button type="button" className="login-copyright-more" onClick={() => setShowCopyright(true)}>
            저작권 및 출처 보기
          </button>
        </div>
        {showHelp && (
          <div className="app-dialog-overlay no-print" onClick={(e) => { if (e.target === e.currentTarget) setShowHelp(false); }}>
            <div className="app-dialog help-dialog" role="dialog" aria-modal="true">
              <HelpGuide onClose={() => setShowHelp(false)} />
            </div>
          </div>
        )}
        {showCopyright && (
          <div className="app-dialog-overlay no-print" onClick={(e) => { if (e.target === e.currentTarget) setShowCopyright(false); }}>
            <div className="app-dialog copyright-dialog" role="dialog" aria-modal="true">
              <h3 className="copyright-h2">📜 저작권 및 출처</h3>
              <div className="copyright-section">
                <div className="copyright-block-title">SCERTS® 모델 출처</div>
                <p className="copyright-cite">
                  Prizant, B. M., Wetherby, A. M., Rubin, E., Laurent, A. C., &amp; Rydell, P. J. (2006).<br />
                  <i>The SCERTS® Model: A Comprehensive Educational Approach for Children with Autism Spectrum Disorders.</i><br />
                  Paul H. Brookes Publishing Co.
                </p>
              </div>
              <div className="copyright-section">
                <div className="copyright-block-title">한국어판 참고</div>
                <p className="copyright-cite">SCERTS 모델 (학지사, 2019)</p>
              </div>
              <div className="copyright-section">
                <p className="copyright-disclaimer">
                  본 시스템에 포함된 진단 항목·발달 단계·중재 원리는 위 SCERTS® 매뉴얼에 근거하며, SCERTS®는 원저작권자의 등록상표입니다. 본 시스템은 SCERTS 원저자·출판사와 공식 제휴 관계가 아닌, 임상 현장에서 모델을 적용하기 위한 보조 도구입니다.
                </p>
              </div>
              <div className="copyright-divider" />
              <div className="copyright-section">
                <p className="copyright-owner">
                  <b>© 검단ABA언어행동연구소 · 민다혜 (BCBA)</b><br />
                  본 자료는 검단ABA언어행동연구소의 지적재산입니다.<br />
                  무단 복제·배포·재판매·온라인 게시를 엄격히 금지합니다.
                </p>
              </div>
              <div className="help-actions">
                <button className="btn-primary" onClick={() => setShowCopyright(false)}>확인</button>
              </div>
            </div>
          </div>
        )}
      </div>
    );
  }

  return (
    <div className="app-shell">
      <Style />
      <AppDialog />
      <Header
        ws={ws}
        tab={tab}
        setTab={setTab}
        onExport={exportJSON}
        onExportChild={exportCurrentChild}
        onImport={importJSON}
        onNew={newWorkspace}
        state={state}
        switchChild={switchChild}
        addChild={addChild}
        removeChild={removeChild}
        onShowBackups={() => setShowBackupPanel(true)}
        canUndo={historyVersion.canUndo}
        canRedo={historyVersion.canRedo}
        onUndo={() => { const ok = undo(); if (ok) showToast('실행 취소됨'); }}
        onRedo={() => { const ok = redo(); if (ok) showToast('다시 실행됨'); }}
        authUser={authUser}
        onLogout={handleLogout}
        onManageAccounts={() => setShowAccountPanel(true)}
        onAdminDash={async () => { setShowAdminDash(true); await loadAllTeacherData(); }}
        onLoadSample={loadSampleChild}
        onShowHelp={() => setShowHelp(true)}
        lastSavedAt={lastSavedAt}
        concurrentEditor={concurrentEditor}
        onDismissConcurrent={() => setConcurrentEditor(null)}
      />

      {showHelp && (
        <div className="app-dialog-overlay no-print" onClick={(e) => { if (e.target === e.currentTarget) setShowHelp(false); }}>
          <div className="app-dialog help-dialog" role="dialog" aria-modal="true">
            <HelpGuide onClose={() => setShowHelp(false)} />
          </div>
        </div>
      )}

      {showAdminDash && authUser?.role === 'admin' && (
        <AdminDashboard
          allTeacherData={allTeacherData}
          loading={adminLoading}
          onRefresh={loadAllTeacherData}
          onOpenChild={(teacher, snapshot, childId) => {
            const snap = JSON.parse(JSON.stringify(snapshot));
            snap.activeChildId = childId;
            snap._viewingTeacher = teacher;
            setState(snap);
            setShowAdminDash(false);
            setTab('home');
            showToast(`${teacher} 선생님의 아동 데이터를 불러왔습니다`);
          }}
          onClose={() => setShowAdminDash(false)}
        />
      )}

      {ws._viewingTeacher && (
        <div className="viewing-banner no-print">
          <span className="viewing-banner-text">
            👁️ <strong>{ws._viewingTeacher}</strong> 선생님의 데이터를 조회 중입니다 (읽기 전용 — 변경해도 저장되지 않습니다)
          </span>
          <button className="viewing-banner-btn" onClick={async () => {
            // 관리자 본인 데이터로 복귀
            sharedLoadedRef.current = false;
            if (window.storage && authUser?.name) {
              try {
                const r = await window.storage.get('gd-aba-state', true);
                if (r?.value) {
                  const mine = JSON.parse(r.value);
                  delete mine._viewingTeacher;
                  setState(mine);
                } else {
                  setState((s) => { const c = { ...s }; delete c._viewingTeacher; return c; });
                }
              } catch (e) {
                setState((s) => { const c = { ...s }; delete c._viewingTeacher; return c; });
              }
            } else {
              setState((s) => { const c = { ...s }; delete c._viewingTeacher; return c; });
            }
            setTimeout(() => { sharedLoadedRef.current = true; }, 100);
            showToast('내 데이터로 돌아왔습니다');
          }}>내 데이터로 돌아가기</button>
        </div>
      )}

      {showAccountPanel && authUser?.role === 'admin' && (
        <AccountPanel
          userList={userList}
          addUser={addUser}
          removeUser={removeUser}
          changeUserPw={changeUserPw}
          onClose={() => setShowAccountPanel(false)}
        />
      )}

      {showBackupPanel && (
        <BackupPanel onRestore={restoreBackup} onClose={() => setShowBackupPanel(false)} />
      )}

      <main className="main">
        {ws._empty ? (
          <div className="empty-state">
            <div className="empty-state-icon">👶</div>
            <h2 className="empty-state-title">담당 아동이 없습니다</h2>
            <p className="empty-state-desc">
              새 아동을 추가하면 단계 결정부터 보고서 작성까지 시작할 수 있습니다.
            </p>
            <button className="btn-primary empty-state-btn" onClick={async () => {
              const name = (await appPrompt('새 아동의 이름을 입력하세요:') || '').trim();
              if (name) addChild(name);
            }}>+ 새 아동 추가</button>
            <button className="btn-ghost empty-state-sample" onClick={loadSampleChild}>
              🧪 샘플 아동 불러와서 둘러보기
            </button>
            <p className="empty-state-hint">
              샘플 아동(민준호)은 질문지·진단·활동기록이 채워져 있어 IEP·중간보고서가 어떻게 나오는지 바로 볼 수 있습니다. 확인 후 삭제하세요.<br />
              또는 상단의 "가져오기"로 백업 파일을 불러올 수 있습니다.
            </p>
          </div>
        ) : (
        <>
        {tab === 'home' && (
          <Home ws={ws} setTab={setTab} updateMeta={updateMeta} archiveCount={archive.length}
                state={state} switchChild={switchChild} addChild={addChild}
                removeChild={removeChild} renameChild={renameChild} />
        )}
        {tab === 'decision' && (
          <DecisionTab
            ws={ws}
            setWs={setWs}
            recommendedStage={recommendedStage}
            onChosen={(s) => {
              updateMeta({ stage: s });
              setTab('interview');
              showToast(`${STAGE_LABELS[s]}로 설정되었습니다`);
            }}
          />
        )}
        {tab === 'interview' && (
          <InterviewTab ws={ws} setWs={setWs} showToast={showToast} />
        )}
        {tab === 'assess' && (
          <AssessmentTab
            ws={ws}
            updateScore={updateScore}
            updateSes={updateSes}
            setWs={setWs}
            onSavePre={savePre}
            onSavePost={savePost}
            addSession={addSession}
            switchSession={switchSession}
            removeSession={removeSession}
            updateSessionMeta={updateSessionMeta}
            setSessionDesignation={setSessionDesignation}
            showToast={showToast}
          />
        )}
        {tab === 'iep' && (
          <IEPTab ws={ws} setWs={setWs} onArchive={() => archiveCurrent('iep')} showToast={showToast} />
        )}
        {tab === 'interim' && (
          <InterimTab ws={ws} setWs={setWs} onArchive={() => archiveCurrent('interim')} showToast={showToast} />
        )}
        {tab === 'activity' && (
          <ActivityTab ws={ws} setWs={setWs} showToast={showToast} />
        )}
        {tab === 'sap' && (
          <div className="tab-content">
            <div className="card">
              <SapSummary ws={ws} />
            </div>
          </div>
        )}
        {tab === 'family' && (
          <div className="tab-content">
            <div className="card">
              <h2 className="section-title">가족 지원 계획</h2>
              <p className="hint">가족과 협업하여 가정 내 SCERTS 전략을 계획하고 기록합니다.</p>
              <FamilySupportForm ws={ws} setWs={setWs} />
            </div>
          </div>
        )}
        {tab === 'prof' && (
          <div className="tab-content">
            <div className="card">
              <h2 className="section-title">전문가 협력 계획</h2>
              <p className="hint">다학제 팀의 역할 분담과 환경 간 일관성 확보를 위한 계획서입니다.</p>
              <ProfSupportForm ws={ws} setWs={setWs} />
            </div>
          </div>
        )}
        {tab === 'commSchedule' && (
          <div className="tab-content">
            <div className="card">
              <h2 className="section-title">의사소통 일과 분석</h2>
              <p className="hint">하루 일과 중 자연스럽게 발생하는 의사소통 기회를 시간대별로 분석합니다.</p>
              <CommunicationScheduleForm ws={ws} setWs={setWs} showToast={showToast} />
            </div>
          </div>
        )}
        {tab === 'fba' && (
          <div className="tab-content">
            <div className="card">
              <h2 className="section-title">도전 행동 기능적 분석</h2>
              <p className="hint">행동의 기능과 정서 조절 맥락을 통합 분석하여 대체 행동 중재 계획을 수립합니다.</p>
              <FbaForm ws={ws} setWs={setWs} showToast={showToast} />
            </div>
          </div>
        )}
        {tab === 'archive' && (
          <ArchiveTab
            archive={archive}
            onLoad={(snap) => { setWs(snap); setTab('home'); showToast('불러오기 완료'); }}
            onRemove={removeArchive}
          />
        )}
        </>
        )}
      </main>

      {toast && <div className="toast" role="status">{toast}</div>}
      <Footer />
    </div>
  );
}

// =====================================================================
// HEADER
// =====================================================================
// =====================================================================
// 단계 안내 배너 — 각 탭에서 "지금 뭘 해야 하는지" 한 줄로 안내
//   kind: 'required'(필수) | 'auto'(자동) | 'optional'(선택)
//   done: 완료 여부 / todo: 할 일 안내문 / okMsg: 완료 시 문구
// =====================================================================
function StepBanner({ kind, done, todo, okMsg, writer }) {
  let cls, icon, label;
  if (kind === 'required' && !done) { cls = 'sb-need'; icon = '●'; label = '꼭 해야 함'; }
  else if (kind === 'required' && done) { cls = 'sb-done'; icon = '✓'; label = '완료'; }
  else if (kind === 'auto') { cls = 'sb-auto'; icon = '⚙'; label = '자동'; }
  else { cls = 'sb-opt'; icon = '○'; label = '선택'; }
  // writer: 'parent'(부모·양육자) | 'therapist'(치료사)
  let writerBadge = null;
  if (writer === 'parent') writerBadge = <span className="sb-writer sb-writer-parent">👤 부모·양육자 작성</span>;
  else if (writer === 'therapist') writerBadge = <span className="sb-writer sb-writer-therapist">🩺 치료사 작성</span>;
  return (
    <div className={`step-banner ${cls} no-print`}>
      <span className="sb-badge">{icon} {label}</span>
      <span className="sb-text">{done && okMsg ? okMsg : todo}</span>
      {writerBadge}
    </div>
  );
}

// =====================================================================
// 관리자 — 전체 선생님/아동 조회 대시보드
// =====================================================================
// =====================================================================
// 도움말 — SCERTS 모델 설명 + 앱 사용 안내 (로그인/홈/헤더 공용)
// =====================================================================
function HelpGuide({ onClose, compact }) {
  return (
    <div className={`help-guide ${compact ? 'compact' : ''}`}>
      <div className="help-section">
        <h3 className="help-h2">📘 SCERTS 자동화 시스템 안내</h3>
        <p className="help-intro">검단ABA언어행동연구소의 SCERTS 기반 임상 자동화 시스템입니다.</p>
      </div>

      <div className="help-section">
        <h4 className="help-h3">1. SCERTS 모델이란</h4>
        <p>SCERTS는 자폐 스펙트럼 아동을 위한 발달 기반 종합 중재 모델입니다.</p>
        <div className="help-block">
          <div className="help-block-title">세 가지 핵심 영역</div>
          <ul className="help-ul">
            <li><b>SC (Social Communication / 사회 의사소통)</b> — 공동 관심, 상징 사용</li>
            <li><b>ER (Emotional Regulation / 정서 조절)</b> — 상호 조절, 자기 조절</li>
            <li><b>TS (Transactional Support / 교류 지원)</b> — 대인관계 지원, 학습 지원</li>
          </ul>
        </div>
        <div className="help-block">
          <div className="help-block-title">발달 단계</div>
          <ul className="help-ul">
            <li><b>사회적 파트너 단계</b> — 단어 사용 이전, 비언어적 의사소통 중심</li>
            <li><b>언어 파트너 단계</b> — 단어~짧은 구를 사용하기 시작</li>
            <li><b>대화 파트너 단계</b> — 문장과 대화로 의사소통</li>
          </ul>
        </div>
      </div>

      <div className="help-section">
        <h4 className="help-h3">2. 앱 사용 순서</h4>
        <p className="help-legend">
          <span className="help-badge badge-teacher">🩺 선생님 작성</span>
          <span className="help-badge badge-parent">👶 부모 작성</span>
          <span className="help-badge badge-auto">⚙ 자동 생성 + 선생님 검토</span>
        </p>

        <div className="help-step">
          <div className="help-step-head"><b>STEP 1. 단계 결정</b> <span className="help-badge badge-teacher">🩺 선생님 작성</span></div>
          <p>홈에서 새 아동을 추가한 뒤, "1. 단계 결정" 메뉴로 갑니다. 아동의 현재 단어 사용·의사소통 방식 문항에 선생님이 답합니다. 결정된 단계에 따라 이후 질문지·진단 항목이 달라집니다.</p>
        </div>

        <div className="help-step">
          <div className="help-step-head"><b>STEP 2. 질문지 (보호자 면담)</b> <span className="help-badge badge-parent">👶 부모 작성</span></div>
          <p><b>보호자가 직접 답해야 하는 영역</b>입니다. 가정에서의 아동 모습은 부모가 가장 잘 알기 때문입니다.</p>
          <ul className="help-ul">
            <li><b>함께 면담</b> — 보호자와 직접 만나 면담하며 선생님이 대신 입력</li>
            <li><b>카톡으로 보내기 (추천)</b> — "부모용 질문지 내보내기" 버튼으로 링크 생성 → 부모에게 카톡 전송 → 부모가 직접 답한 뒤 "답안 복사" → 선생님이 받은 코드를 앱에 붙여넣으면 자동 채움</li>
          </ul>
          <p className="help-note">📌 부모만이 답할 수 있는 가정에서의 의사소통, 흥미·어려운 상황, 감정 표현 방식, 가족 우선순위 등이 포함됩니다.</p>
        </div>

        <div className="help-step">
          <div className="help-step-head"><b>STEP 3. 진단</b> <span className="help-badge badge-teacher">🩺 선생님 작성 (임상 관찰 기반)</span></div>
          <p><b>선생님이 아동을 직접 관찰하고 채점</b>하는 영역입니다. 부모 답변이 점수로 자동 환산되지는 않습니다 — 이는 의도된 설계로, SCERTS의 진단은 치료사의 임상 판단을 기반으로 합니다.</p>
          <ul className="help-ul">
            <li><b>📝 항목 채점</b> — 발달 항목별 0점(미관찰)·1점(부분 관찰)·2점(안정적 관찰) 채점</li>
            <li><b>📋 관찰 계획</b> — 언제·어디서·누구와 관찰할지 계획 작성</li>
            <li><b>📊 자동 분석</b> — 20% 이상 채점하면 활성화. MR/SR 패턴, 발달 의존성, 사회·정서 지표 차트가 자동 표시</li>
          </ul>
          <p className="help-note">📌 새 세션을 만들어 "사전/사후 진단으로 저장" 지정하면 진전 그래프가 자동 생성됩니다.</p>
        </div>

        <div className="help-step">
          <div className="help-step-head"><b>STEP 4. IEP 작성</b> <span className="help-badge badge-auto">⚙ 자동 생성 + 선생님 검토</span></div>
          <p>"📊 진단 결과로 자동 채움" 버튼을 누르면 진단 점수와 질문지 답변을 종합해 자동 생성됩니다:</p>
          <ul className="help-ul">
            <li>현행 수준 (SC·ER·TS 영역별) — 진단 점수 + 보호자 질문지 답변 자동 인용</li>
            <li>연간 목표·단기 목표·교수 전략·측정 방법</li>
            <li>주간 우선순위 추천 (진단 점수 + 사회·정서 지표 + 가족 견해 통합)</li>
          </ul>
          <p>생성된 내용을 <b>선생님이 검토하고 필요한 부분만 수정</b>합니다. 추천 목표 클릭 시 아동 목표 / 파트너 교류 지원 목표로 자동 분류됩니다.</p>
        </div>

        <div className="help-step">
          <div className="help-step-head"><b>STEP 5. 활동 기록</b> <span className="help-badge badge-teacher">🩺 선생님 작성</span></div>
          <p>선생님이 회기별 일지를 작성합니다. 각 회기마다 활동·목표별 관찰·평가 등급(독립/부분 보조/언어 촉진 등)을 기록합니다. 이 기록은 중간·종결보고서에 자동 인용됩니다.</p>
        </div>

        <div className="help-step">
          <div className="help-step-head"><b>STEP 6. 중간·종결보고서</b> <span className="help-badge badge-auto">⚙ 자동 생성 + 선생님 검토</span></div>
          <p>모드 토글로 중간/종결 선택. "📊 자동 채움" 버튼이 다음을 한 번에 생성합니다:</p>
          <ul className="help-ul">
            <li>발달 단계 요약</li>
            <li>영역별 진전 (사전·사후 비교)</li>
            <li>회기 일지에서 관찰 사례 자동 인용</li>
            <li>MR/SR 패턴 기반 향후 중재 방향</li>
            <li>(종결 모드) IEP 목표별 달성도</li>
          </ul>
          <p>선생님이 검토 후 보호자에게 전달합니다.</p>
        </div>
      </div>

      <div className="help-section">
        <h4 className="help-h3">3. 추가 양식 (선택)</h4>
        <p>홈 아래쪽 "SCERTS 추가 양식" 섹션에서 부가 양식을 작성할 수 있습니다:</p>
        <ul className="help-ul">
          <li><b>가족 지원 계획서</b> (SCERTS 권장) — 가족과 함께 작성</li>
          <li><b>전문가 협력 / 의사소통 일정표 / 행동 기능 평가</b> — 선생님 작성</li>
        </ul>
      </div>

      {onClose && (
        <div className="help-actions">
          <button className="btn-primary" onClick={onClose}>확인</button>
        </div>
      )}
    </div>
  );
}

function AdminDashboard({ allTeacherData, loading, onRefresh, onOpenChild, onClose }) {
  const [filter, setFilter] = useState('');
  const totalChildren = allTeacherData.reduce((a, t) => a + t.childCount, 0);
  const q = filter.trim().toLowerCase();
  const filtered = allTeacherData.map((t) => ({
    ...t,
    children: q ? t.children.filter((c) =>
      c.name.toLowerCase().includes(q) || t.teacher.toLowerCase().includes(q)) : t.children,
  })).filter((t) => !q || t.teacher.toLowerCase().includes(q) || t.children.length > 0);

  return (
    <div className="app-dialog-overlay no-print" onClick={(e) => { if (e.target === e.currentTarget) onClose(); }}>
      <div className="app-dialog admin-dash" role="dialog" aria-modal="true">
        <div className="account-panel-head">
          <h2 className="account-panel-title">👑 전체 아동 조회</h2>
          <span className="account-panel-count">선생님 {allTeacherData.length}명 · 아동 {totalChildren}명</span>
        </div>
        <div className="admin-dash-controls">
          <input className="account-input" type="text" value={filter}
            onChange={(e) => setFilter(e.target.value)} placeholder="선생님명 · 아동명 검색" />
          <button className="btn-ghost btn-small" onClick={onRefresh}>새로고침</button>
        </div>

        {loading ? (
          <div className="account-empty">불러오는 중…</div>
        ) : allTeacherData.length === 0 ? (
          <div className="account-empty">
            아직 데이터가 없습니다.<br />
            <span style={{ fontSize: '12px' }}>선생님들이 로그인해 아동을 등록하면 여기 표시됩니다.</span>
          </div>
        ) : (
          <div className="admin-dash-list">
            {filtered.map((t) => (
              <div key={t.teacher} className="admin-teacher-block">
                <div className="admin-teacher-head">
                  <span className="admin-teacher-name">👤 {t.teacher}</span>
                  <span className="admin-teacher-count">{t.children.length}명</span>
                </div>
                {t.children.length === 0 ? (
                  <div className="admin-child-empty">등록된 아동 없음</div>
                ) : (
                  <div className="admin-child-grid">
                    {t.children.map((c) => (
                      <button key={c.id} className="admin-child-card"
                        onClick={() => onOpenChild(t.teacher, t.snapshot, c.id)}>
                        <span className="admin-child-name">{c.name}</span>
                        {c.birth && <span className="admin-child-birth">{c.birth}</span>}
                        <span className="admin-child-stage">{c.stage ? STAGE_LABELS[c.stage] : '단계 미정'}</span>
                      </button>
                    ))}
                  </div>
                )}
              </div>
            ))}
          </div>
        )}

        <div className="app-dialog-actions">
          <button className="btn-ghost" onClick={onClose}>닫기</button>
        </div>
      </div>
    </div>
  );
}

// =====================================================================
// 관리자 — 선생님 계정 관리 패널
// =====================================================================
function AccountPanel({ userList, addUser, removeUser, changeUserPw, onClose }) {
  const [newEmail, setNewEmail] = useState('');
  const [newName, setNewName] = useState('');
  const [newPw, setNewPw] = useState('');
  const [msg, setMsg] = useState('');
  const [editPwFor, setEditPwFor] = useState(null);   // userId
  const [editPwVal, setEditPwVal] = useState('');
  const [confirmDel, setConfirmDel] = useState(null); // userId

  // 관리자 제외한 선생님만 목록에 표시
  const teachers = (userList || []).filter((u) => u.role !== 'admin');

  const handleAdd = async () => {
    const r = await addUser(newEmail, newPw, newName);
    if (r.ok) {
      setMsg(`✅ "${newName.trim()}" 선생님 계정이 생성되었습니다. (이메일: ${newEmail.trim()}, 비번: ${newPw.trim()})`);
      setNewEmail(''); setNewName(''); setNewPw('');
    } else setMsg('⚠️ ' + r.msg);
  };
  const handleChangePw = async (userId, displayName) => {
    const r = await changeUserPw(userId, editPwVal);
    if (r.ok) { setMsg(`✅ "${displayName}" 선생님 비밀번호가 변경되었습니다. 새 비밀번호: ${editPwVal.trim()}`); setEditPwFor(null); setEditPwVal(''); }
    else setMsg('⚠️ ' + r.msg);
  };
  const handleDelete = async (userId, displayName) => {
    const r = await removeUser(userId);
    if (r.ok) { setConfirmDel(null); setMsg(`🗑️ "${displayName}" 계정이 삭제되었습니다.`); }
    else setMsg('⚠️ ' + (r.msg || '삭제 실패'));
  };

  return (
    <div className="app-dialog-overlay no-print" onClick={(e) => { if (e.target === e.currentTarget) onClose(); }}>
      <div className="app-dialog account-panel" role="dialog" aria-modal="true">
        <div className="account-panel-head">
          <h2 className="account-panel-title">👑 선생님 계정 관리</h2>
          <span className="account-panel-count">{teachers.length}/{MAX_USERS}명</span>
        </div>

        <div className="account-add">
          <div className="account-add-title">새 선생님 추가</div>
          <div className="account-add-row">
            <input className="account-input" type="email" value={newEmail}
              onChange={(e) => setNewEmail(e.target.value)} placeholder="이메일 (예: kim@gmail.com)"
              autoComplete="off" name={`scerts-new-email-${Math.random().toString(36).slice(2, 8)}`} />
            <input className="account-input" type="text" value={newName}
              onChange={(e) => setNewName(e.target.value)} placeholder="선생님 이름 (예: 김선생)"
              autoComplete="off" name={`scerts-new-name-${Math.random().toString(36).slice(2, 8)}`} />
            <input className="account-input" type="text" value={newPw}
              onChange={(e) => setNewPw(e.target.value)} placeholder="비밀번호 (6자 이상)"
              autoComplete="off" name={`scerts-new-pw-${Math.random().toString(36).slice(2, 8)}`}
              onKeyDown={(e) => { if (e.key === 'Enter') handleAdd(); }} />
            <button className="btn-primary btn-small" onClick={handleAdd}>+ 추가</button>
          </div>
          <div className="account-add-hint">이메일·이름·비밀번호를 정해 선생님께 알려주세요. 선생님은 이메일과 비밀번호로 로그인합니다.</div>
        </div>

        {msg && <div className="account-msg">{msg}</div>}

        <div className="account-list">
          {teachers.length === 0 && <div className="account-empty">아직 등록된 선생님이 없습니다.</div>}
          {teachers.map((u) => (
            <div key={u.user_id} className="account-item">
              <div className="account-item-info">
                <span className="account-item-name">👤 {u.display_name || u.email}</span>
                <span className="account-item-meta">{u.email} · 등록 {u.created_at ? u.created_at.slice(0, 10) : '-'}</span>
              </div>
              {editPwFor === u.user_id ? (
                <div className="account-item-edit">
                  <input className="account-input account-input-sm" type="text" value={editPwVal}
                    onChange={(e) => setEditPwVal(e.target.value)} placeholder="새 비밀번호"
                    autoComplete="off" name={`scerts-edit-pw-${Math.random().toString(36).slice(2, 8)}`}
                    onKeyDown={(e) => { if (e.key === 'Enter') handleChangePw(u.user_id, u.display_name || u.email); }} autoFocus />
                  <button className="btn-primary btn-small" onClick={() => handleChangePw(u.user_id, u.display_name || u.email)}>저장</button>
                  <button className="btn-ghost btn-small" onClick={() => { setEditPwFor(null); setEditPwVal(''); }}>취소</button>
                </div>
              ) : confirmDel === u.user_id ? (
                <div className="account-item-edit">
                  <span className="account-del-warn">삭제할까요? (계정과 모든 데이터가 지워집니다)</span>
                  <button className="btn-danger btn-small" onClick={() => handleDelete(u.user_id, u.display_name || u.email)}>삭제</button>
                  <button className="btn-ghost btn-small" onClick={() => setConfirmDel(null)}>취소</button>
                </div>
              ) : (
                <div className="account-item-actions">
                  <button className="btn-ghost btn-small" onClick={() => { setEditPwFor(u.user_id); setEditPwVal(''); }}>비번 변경</button>
                  <button className="btn-ghost btn-small account-del-btn" onClick={() => setConfirmDel(u.user_id)}>삭제</button>
                </div>
              )}
            </div>
          ))}
        </div>

        <div className="app-dialog-actions">
          <button className="btn-ghost" onClick={onClose}>닫기</button>
        </div>
      </div>
    </div>
  );
}

function Header({ ws, tab, setTab, onExport, onExportChild, onImport, onNew, state, switchChild, addChild, removeChild, onShowBackups, canUndo, canRedo, onUndo, onRedo, authUser, onLogout, onManageAccounts, onAdminDash, onLoadSample, onShowHelp, lastSavedAt, concurrentEditor, onDismissConcurrent }) {
  // 마지막 저장 시각 → "방금 저장됨" / "N분 전 저장됨"
  const [savedLabel, setSavedLabel] = useState('');
  useEffect(() => {
    if (!lastSavedAt) { setSavedLabel(''); return; }
    const update = () => {
      const diff = Math.floor((Date.now() - lastSavedAt) / 1000);
      if (diff < 5) setSavedLabel('방금 저장됨');
      else if (diff < 60) setSavedLabel(`${diff}초 전 저장됨`);
      else if (diff < 3600) setSavedLabel(`${Math.floor(diff/60)}분 전 저장됨`);
      else setSavedLabel(`${Math.floor(diff/3600)}시간 전 저장됨`);
    };
    update();
    const t = setInterval(update, 10000);
    return () => clearInterval(t);
  }, [lastSavedAt]);
  const fileRef = useRef(null);
  const [showChildMenu, setShowChildMenu] = useState(false);
  const [showExportMenu, setShowExportMenu] = useState(false);

  // ── 각 탭의 진행 상태 계산 ──────────────────────────────────────
  // kind: 'required'(필수) | 'optional'(선택)
  // done: 해당 단계가 충분히 작성되었는지
  // SCERTS 절차: 단계결정 → 질문지 → 진단 → (가족우선순위) → IEP → 중간보고서
  const stepStatus = useMemo(() => {
    const d = ws.decision || { q1: {}, q2: {} };
    const decisionDone =
      Object.keys(d.q1 || {}).length > 0 || Object.keys(d.q2 || {}).length > 0;
    const interviewDone = Object.keys(ws.interview?.answers || {}).length >= 3;
    const scoreCount = Object.keys(ws.assessment?.scores || {}).length;
    const assessDone = scoreCount >= 5;
    const iep = ws.iep || {};
    const iepDone = ['sc', 'er', 'ts'].some(
      (k) => (iep.currentLevel?.[k] || iep.annualGoals?.[k] || '').trim() !== '',
    );
    const interimDone = ((ws.interim?.summary || '') + (ws.interim?.direction || '')).trim() !== '';
    const logCount = (ws.activities?.logI || []).length;
    return {
      decision: { kind: 'required', done: decisionDone },
      interview: { kind: 'required', done: interviewDone },
      assess: { kind: 'required', done: assessDone },
      iep: { kind: 'auto', done: iepDone },
      interim: { kind: 'auto', done: interimDone },
      activity: { kind: 'required', done: logCount > 0 },
    };
  }, [ws.decision, ws.interview, ws.assessment, ws.iep, ws.interim, ws.activities]);
  const tabs = [
    { id: 'home', label: '홈' },
    { id: 'decision', label: '1. 단계 결정' },
    { id: 'interview', label: '2. 질문지', disabled: !ws.meta.stage },
    { id: 'assess', label: '3. 진단', disabled: !ws.meta.stage },
    { id: 'iep', label: '4. IEP', disabled: !ws.meta.stage },
    { id: 'activity', label: '5. 활동 기록', disabled: !ws.meta.stage },
    { id: 'interim', label: '6. 중간·종결보고서', disabled: !ws.meta.stage },
  ];
  const handleAddChild = async () => {
    const name = (await appPrompt('새 아동의 이름을 입력하세요:') || '').trim();
    if (name) {
      addChild(name);
      setShowChildMenu(false);
    }
  };
  const handleRemoveChild = async (id, name) => {
    const isLast = state?.children.length <= 1;
    const msg = isLast
      ? `"${name}"의 모든 데이터를 삭제하시겠습니까?\n삭제하면 담당 아동이 없는 빈 상태가 됩니다.\n이 작업은 되돌릴 수 없습니다.`
      : `"${name}"의 모든 데이터를 삭제하시겠습니까?\n이 작업은 되돌릴 수 없습니다.`;
    if (await appConfirm(msg)) {
      removeChild(id);
      setShowChildMenu(false);
    }
  };
  return (
    <header className="header no-print">
      <div className="header-inner">
        <div className="brand">
          <div className="brand-mark">
            <span className="brand-mark-letter">S</span>
          </div>
          <div className="brand-text">
            <div className="brand-title">SCERTS 자동화 시스템</div>
            <div className="brand-sub">검단ABA언어행동연구소</div>
          </div>
        </div>
        <nav className="tabs">
          {tabs.map((t) => {
            const st = stepStatus[t.id];
            // 필수인데 아직 안 했으면 빨간 점, 완료면 체크, 선택은 표시 없음
            let dot = null;
            if (st && !t.disabled) {
              if (st.kind === 'required' && !st.done) dot = <span className="tab-dot tab-dot-need" title="꼭 해야 함">●</span>;
              else if (st.kind === 'required' && st.done) dot = <span className="tab-dot tab-dot-done" title="완료">✓</span>;
              else if (st.kind === 'auto' && st.done) dot = <span className="tab-dot tab-dot-done" title="작성됨">✓</span>;
            }
            return (
              <button
                key={t.id}
                className={`tab ${tab === t.id ? 'active' : ''} ${st && st.kind === 'required' && !st.done && !t.disabled ? 'tab-need' : ''}`}
                onClick={() => !t.disabled && setTab(t.id)}
                disabled={t.disabled}
                title={t.disabled ? '먼저 단계를 결정해 주세요' : ''}
              >
                {t.label}
                {dot}
              </button>
            );
          })}
        </nav>
        <div className="header-actions">
          {state && state.children && (
            <div className="child-selector">
              <button
                className="btn-child-selector"
                onClick={() => setShowChildMenu((v) => !v)}
                title="아동 선택"
              >
                <span className="child-name">{ws.meta.childName || '(이름 미입력)'}</span>
                <span className="child-count">{state.children.length}명</span>
                <span className="child-dropdown-arrow">▾</span>
              </button>
              {showChildMenu && (
                <>
                  <div className="child-menu-backdrop" onClick={() => setShowChildMenu(false)} />
                  <div className="child-menu">
                    <div className="child-menu-header">담당 아동</div>
                    <div className="child-menu-list">
                      {state.children.map((c) => (
                        <div
                          key={c.id}
                          className={`child-menu-item ${c.id === state.activeChildId ? 'active' : ''}`}
                        >
                          <button
                            className="child-menu-name"
                            onClick={() => { switchChild(c.id); setShowChildMenu(false); }}
                          >
                            <span className="child-menu-mark">{c.id === state.activeChildId ? '●' : '○'}</span>
                            <span>{c.meta.childName || '(이름 없음)'}</span>
                            {c.meta.birthDate && (
                              <span className="child-menu-birth">{c.meta.birthDate}</span>
                            )}
                            {c.meta.stage && (
                              <span className="child-menu-stage">
                                {c.meta.stage === 'social' ? '사회' : c.meta.stage === 'language' ? '언어' : '대화'}
                              </span>
                            )}
                          </button>
                          <button
                            className="child-menu-remove"
                            onClick={() => handleRemoveChild(c.id, c.meta.childName || '(이름 없음)')}
                            title="삭제"
                          >×</button>
                        </div>
                      ))}
                    </div>
                    <button className="child-menu-add" onClick={handleAddChild}>+ 새 아동 추가</button>
                    {onLoadSample && (
                      <div className="child-menu-sample-group">
                        <div className="child-menu-sample-label">🧪 샘플 아동 (단계별, 기존 샘플 자동 교체)</div>
                        <button className="child-menu-sample" onClick={() => { onLoadSample('social'); setShowChildMenu(false); }}>사회적 파트너 (김서아, 2세)</button>
                        <button className="child-menu-sample" onClick={() => { onLoadSample('language'); setShowChildMenu(false); }}>언어 파트너 (민준호, 4세)</button>
                        <button className="child-menu-sample" onClick={() => { onLoadSample('conversation'); setShowChildMenu(false); }}>대화 파트너 (이지훈, 6세)</button>
                      </div>
                    )}
                  </div>
                </>
              )}
            </div>
          )}
          <button
            className="btn-icon-toolbar"
            onClick={onUndo}
            disabled={!canUndo}
            title="실행 취소 (Ctrl/Cmd+Z)"
          >↶</button>
          <button
            className="btn-icon-toolbar"
            onClick={onRedo}
            disabled={!canRedo}
            title="다시 실행 (Ctrl/Cmd+Shift+Z)"
          >↷</button>
          <button className="btn-ghost" onClick={() => setTab('archive')} title="보관함">
            📁 보관함
          </button>
          <button className="btn-ghost" onClick={onShowBackups} title="자동 백업 슬롯">
            🕐 백업
          </button>
          <button className="btn-ghost" onClick={onNew}>새 작업</button>
          <button className="btn-ghost" onClick={() => fileRef.current?.click()}>가져오기</button>
          <input
            ref={fileRef}
            type="file"
            accept="application/json"
            style={{ display: 'none' }}
            onChange={(e) => e.target.files[0] && onImport(e.target.files[0])}
          />
          <div className="export-menu-wrap">
            <button className="btn-primary" onClick={() => setShowExportMenu((v) => !v)}>
              내보내기 ▾
            </button>
            {showExportMenu && (
              <>
                <div className="child-menu-backdrop" onClick={() => setShowExportMenu(false)} />
                <div className="export-menu">
                  <button className="export-menu-item" onClick={() => { onExportChild(); setShowExportMenu(false); }}>
                    <strong>현재 아동만</strong>
                    <div className="export-menu-desc">{ws.meta.childName || '(이름 없음)'}의 데이터만</div>
                  </button>
                  <button className="export-menu-item" onClick={() => { onExport(); setShowExportMenu(false); }}>
                    <strong>전체 백업</strong>
                    <div className="export-menu-desc">모든 아동 + 보관함 ({state?.children?.length || 0}명)</div>
                  </button>
                </div>
              </>
            )}
          </div>
          {authUser && (
            <div className="header-auth">
              <span className="header-auth-name">
                {authUser.role === 'admin' ? '👑 ' : '👤 '}{authUser.name}
              </span>
              {savedLabel && <span className="header-saved" title="자동 저장 시각">💾 {savedLabel}</span>}
              <button className="btn-ghost btn-small" onClick={onShowHelp}>📘 도움말</button>
              {authUser.role === 'admin' && (
                <>
                  <button className="btn-ghost btn-small" onClick={onAdminDash}>전체 보기</button>
                  <button className="btn-ghost btn-small" onClick={onManageAccounts}>계정 관리</button>
                </>
              )}
              <button className="btn-ghost btn-logout" onClick={onLogout}>로그아웃</button>
            </div>
          )}
        </div>
      </div>
      {concurrentEditor && (
        <div className="concurrent-banner no-print">
          ⚠️ 다른 기기에서 이 계정으로 저장된 작업이 감지되었습니다 ({concurrentEditor.at}). 두 기기에서 동시에 편집 중이라면 한쪽 작업이 덮어쓰일 수 있습니다. 새로고침으로 최신 데이터를 받거나, 한쪽에서 작업을 마무리하세요.
          <button className="concurrent-btn refresh" onClick={() => window.location.reload()}>새로고침</button>
          <button className="concurrent-btn dismiss" onClick={onDismissConcurrent}>닫기</button>
        </div>
      )}
    </header>
  );
}

// =====================================================================
// HOME
// =====================================================================
function Home({ ws, setTab, updateMeta, archiveCount, state, switchChild, addChild, removeChild, renameChild }) {
  const stageLabel = ws.meta.stage ? STAGE_LABELS[ws.meta.stage] : '미설정';
  const stageData = STAGE_DATA[ws.meta.stage];

  // 진짜 빈 상태인지 판단: 아동 1명 + 이름 없음 + 단계 없음 + 보관함 없음
  const isFreshStart = state
    && state.children.length === 1
    && !ws.meta.childName
    && !ws.meta.stage
    && archiveCount === 0;

  const handleAddChild = async () => {
    const name = (await appPrompt('새 아동의 이름을 입력하세요:') || '').trim();
    if (name) addChild(name);
  };

  // 빈 상태: 안내 + 즉시 아동 정보 입력 가능하도록 hero를 안내로 대체
  if (isFreshStart) {
    return (
      <div className="home">
        <EmptyStateGuide onStart={() => {
          setTimeout(() => {
            const target = document.querySelector('.child-info-card');
            target?.scrollIntoView({ behavior: 'smooth', block: 'start' });
            // 첫 input에 자동 포커스
            const firstInput = target?.querySelector('input[type="text"]');
            firstInput?.focus();
          }, 50);
        }} />

        <section className="card child-info-card">
          <h2 className="section-title">아동 정보</h2>
          <div className="form-grid">
            <Field label="아동명">
              <input
                type="text"
                value={ws.meta.childName}
                onChange={(e) => updateMeta({ childName: e.target.value })}
                placeholder="예: 김민준"
              />
            </Field>
            <Field label="생년월일">
              <input
                type="date"
                value={ws.meta.birthDate}
                onChange={(e) => updateMeta({ birthDate: e.target.value })}
              />
            </Field>
            <Field label="반 / 학급">
              <input
                type="text"
                value={ws.meta.className}
                onChange={(e) => updateMeta({ className: e.target.value })}
                placeholder="예: 햇살반"
              />
            </Field>
            <Field label="담당 임상가">
              <input
                type="text"
                value={ws.meta.therapist}
                onChange={(e) => updateMeta({ therapist: e.target.value })}
              />
            </Field>
          </div>
          {ws.meta.childName && (
            <div style={{ marginTop: 20, textAlign: 'right' }}>
              <button className="btn-primary" onClick={() => setTab('decision')}>
                다음: 단계 결정 →
              </button>
            </div>
          )}
        </section>
      </div>
    );
  }

  return (
    <div className="home">
      <div className="hero">
        <div className="eyebrow">SCERTS Assessment</div>
        <h1 className="hero-title">
          사회 의사소통 · 정서 조절 · 교류 지원<br />
          진단부터 보고서까지 한 화면에서.
        </h1>
        <p className="hero-sub">
          단계 결정 기록지 작성 → 진단 항목 채점 → IEP 자동 구성 → 중간보고서 사전/사후 비교까지.
          모든 데이터는 자동 저장되며, JSON 백업으로 안전하게 관리됩니다.
        </p>
      </div>

      {/* 다중 아동 카드 그리드 — 2명 이상일 때만 표시 (1명이면 헤더 드롭다운으로 충분) */}
      {state && state.children && state.children.length >= 2 && (
        <section className="card">
          <div className="section-title-row">
            <h2 className="section-title">담당 아동 ({state.children.length}명)</h2>
            <button className="btn-primary btn-small" onClick={handleAddChild}>+ 새 아동 추가</button>
          </div>
          <div className="child-card-grid">
            {state.children.map((c) => {
              const isActive = c.id === state.activeChildId;
              const sessionCount = (c.sessions || []).length;
              const preDone = (c.sessions || []).some((s) => s.designation === 'pre');
              const postDone = (c.sessions || []).some((s) => s.designation === 'post');
              const scoredCount = (c.sessions || []).reduce((a, s) => a + Object.keys(s.scores || {}).length, 0);
              const stageStr = c.meta.stage ? STAGE_LABELS[c.meta.stage] : '단계 미정';
              return (
                <div key={c.id} className={`child-card ${isActive ? 'active' : ''}`}>
                  <button className="child-card-main" onClick={() => switchChild(c.id)}>
                    <div className="child-card-name">{c.meta.childName || '(이름 없음)'}</div>
                    {c.meta.birthDate && <div className="child-card-birth">{c.meta.birthDate}</div>}
                    <div className="child-card-stage">{stageStr}</div>
                    <div className="child-card-stats">
                      <div className="child-card-stat">
                        <span className="stat-num">{sessionCount}</span>
                        <span className="stat-label">세션</span>
                      </div>
                      <div className="child-card-stat">
                        <span className="stat-num">{scoredCount}</span>
                        <span className="stat-label">점수</span>
                      </div>
                      <div className="child-card-stat">
                        <span className="stat-num">{preDone && postDone ? '✓✓' : preDone ? '✓·' : postDone ? '·✓' : '··'}</span>
                        <span className="stat-label">사전/사후</span>
                      </div>
                    </div>
                  </button>
                  {isActive && <div className="child-card-active-mark">● 활성</div>}
                </div>
              );
            })}
            <button className="child-card child-card-add" onClick={handleAddChild}>
              <div className="child-card-add-icon">+</div>
              <div className="child-card-add-label">새 아동 추가</div>
            </button>
          </div>
        </section>
      )}

      <section className="card">
        <h2 className="section-title">아동 정보</h2>
        <div className="form-grid">
          <Field label="아동명">
            <input
              type="text"
              value={ws.meta.childName}
              onChange={(e) => updateMeta({ childName: e.target.value })}
              placeholder="예: 김민준"
            />
          </Field>
          <Field label="생년월일">
            <input
              type="date"
              value={ws.meta.birthDate}
              onChange={(e) => updateMeta({ birthDate: e.target.value })}
            />
          </Field>
          <Field label="소속 반">
            <input
              type="text"
              value={ws.meta.className}
              onChange={(e) => updateMeta({ className: e.target.value })}
              placeholder="SCERTS 프로그램"
            />
          </Field>
          <Field label="치료사">
            <input
              type="text"
              value={ws.meta.therapist}
              onChange={(e) => updateMeta({ therapist: e.target.value })}
            />
          </Field>
          <Field label="수업 시작일">
            <input
              type="date"
              value={ws.meta.startDate}
              onChange={(e) => updateMeta({ startDate: e.target.value })}
            />
          </Field>
          <Field label="작성일">
            <input
              type="date"
              value={ws.meta.reportDate}
              onChange={(e) => updateMeta({ reportDate: e.target.value })}
            />
          </Field>
        </div>
      </section>

      <section className="card">
        <h2 className="section-title">진행 상황</h2>
        <div className="progress-grid">
          <ProgressCard
            step="1"
            title="단계 결정"
            status={ws.meta.stage ? '완료' : '시작 전'}
            value={stageLabel}
            onClick={() => setTab('decision')}
          />
          <ProgressCard
            step="2"
            title="질문지"
            status={(() => {
              const n = Object.keys(ws.interview?.answers || {}).filter((k) => k !== '__writer').length;
              return n >= 15 ? '완료' : n > 0 ? '진행 중' : '시작 전';
            })()}
            value={`${Object.keys(ws.interview?.answers || {}).filter((k) => k !== '__writer').length}개 답변`}
            onClick={() => ws.meta.stage && setTab('interview')}
            disabled={!ws.meta.stage}
          />
          <ProgressCard
            step="3"
            title="진단·관찰"
            status={(() => {
              const n = Object.keys(ws.assessment.scores).length;
              return n >= 15 ? '완료' : n > 0 ? '진행 중' : '시작 전';
            })()}
            value={`${Object.keys(ws.assessment.scores).length}개 항목 입력됨`}
            onClick={() => ws.meta.stage && setTab('assess')}
            disabled={!ws.meta.stage}
          />
          <ProgressCard
            step="4"
            title="IEP 작성"
            status={(() => {
              const hasGoals = ws.iep.selectedGoals.length > 0;
              const hasLevel = ['sc', 'er', 'ts'].some((k) => (ws.iep.currentLevel?.[k] || '').trim());
              return (hasGoals && hasLevel) ? '완료' : (hasGoals || hasLevel) ? '진행 중' : '시작 전';
            })()}
            value={`주간 목표 ${ws.iep.selectedGoals.length}개 선택`}
            onClick={() => ws.meta.stage && setTab('iep')}
            disabled={!ws.meta.stage}
          />
          <ProgressCard
            step="5"
            title="중간보고서"
            status={ws.pre && ws.post ? '완료' : ws.pre ? '사후 진단 필요' : '사전 진단 필요'}
            value={`사전 ${ws.pre ? '✓' : '−'} / 사후 ${ws.post ? '✓' : '−'}`}
            onClick={() => ws.meta.stage && setTab('interim')}
            disabled={!ws.meta.stage}
          />
        </div>
        <div className="activity-link no-print" style={{ marginTop: 14 }}>
          <span>📋 활동 일지·주간기록·계획서</span>
          <button className="link-btn" onClick={() => ws.meta.stage && setTab('activity')} disabled={!ws.meta.stage}>활동 기록 열기 →</button>
        </div>
        <div className="archive-link">
          <span>📁 보관함에 저장된 보고서 <strong>{archiveCount}건</strong></span>
          <button className="link-btn" onClick={() => setTab('archive')}>보관함 보기 →</button>
        </div>
      </section>

      {/* 진전 추적 (세션이 2개 이상일 때만 표시) */}
      {ws.meta.stage && (ws._allSessions || []).length >= 2 && stageData && (
        <section className="card">
          <div className="section-title-row">
            <h2 className="section-title">진전 추적</h2>
            <button className="btn-primary btn-small" onClick={() => setTab('sap')}>📄 SAP 요약지 보기</button>
          </div>
          <ProgressTimelineChart ws={ws} stageData={stageData} />
          <SesProgressTimeline ws={ws} />
          <GoalProgressTable ws={ws} stageData={stageData} />
        </section>
      )}

      {/* 세션은 1개라도 SAP 요약지 접근 */}
      {ws.meta.stage && (ws._allSessions || []).length >= 1 && stageData && (ws._allSessions || []).length < 2 && (
        <section className="card">
          <div className="section-title-row">
            <h2 className="section-title">SAP 요약지</h2>
            <button className="btn-primary btn-small" onClick={() => setTab('sap')}>📄 요약지 보기</button>
          </div>
          <p className="hint">현재 1개 세션의 SAP 요약지를 인쇄할 수 있습니다. 진전 추적 차트는 2개 이상의 세션이 필요합니다.</p>
        </section>
      )}

      {/* 협력 계획서 (가족 / 전문가 / 의사소통 일과 / 행동 분석) */}
      {ws.meta.stage && (
        <section className="card">
          <h2 className="section-title">SCERTS 추가 양식 <span className="section-optional-tag">선택</span></h2>
          <p className="hint">필요한 경우에만 작성하세요. 핵심 보고서와는 별개입니다. (단, 가족 지원은 SCERTS 교류 지원의 핵심이라 작성을 권장합니다.)</p>
          <div className="collab-card-grid">
            <button className="collab-card collab-card-recommended" onClick={() => setTab('family')}>
              <div className="collab-card-badge">SCERTS 권장</div>
              <div className="collab-card-icon">👨‍👩‍👧</div>
              <div className="collab-card-title">가족 지원 계획서</div>
              <div className="collab-card-desc">가정 내 적용 전략, 가족 우선순위 목표, 교육 주제</div>
            </button>
            <button className="collab-card" onClick={() => setTab('prof')}>
              <div className="collab-card-icon">🤝</div>
              <div className="collab-card-title">전문가 협력 계획서</div>
              <div className="collab-card-desc">팀 공동 목표, 역할 분담, 사례 회의 기록</div>
            </button>
            <button className="collab-card" onClick={() => setTab('commSchedule')}>
              <div className="collab-card-icon">📅</div>
              <div className="collab-card-title">의사소통 일과 분석</div>
              <div className="collab-card-desc">하루 일과별 의사소통 기회·현재 양상·필요 지원</div>
            </button>
            <button className="collab-card" onClick={() => setTab('fba')}>
              <div className="collab-card-icon">🔍</div>
              <div className="collab-card-title">도전 행동 분석 (FBA)</div>
              <div className="collab-card-desc">ABC 분석, 기능 가설, 대체 행동 중재 계획</div>
            </button>
          </div>
        </section>
      )}

      {/* 데이터 무결성 검증 (진단이 일부라도 진행된 경우) */}
      {ws.meta.stage && Object.keys(ws.assessment?.scores || {}).length >= 5 && (
        <section className="card">
          <h2 className="section-title">진단 데이터 검증</h2>
          <DataIntegrityCheck ws={ws} />
        </section>
      )}
    </div>
  );
}

function ProgressCard({ step, title, status, value, onClick, disabled }) {
  const statusClass = status === '완료' ? 'done'
    : (status === '시작 전' || status === '사전 진단 필요' || status === '사후 진단 필요') ? 'todo'
    : 'progress';
  return (
    <button
      className={`progress-card ${disabled ? 'disabled' : ''} pc-${statusClass}`}
      onClick={onClick}
      disabled={disabled}
    >
      <div className="progress-step">STEP {step}</div>
      <div className="progress-title">{title}</div>
      <div className="progress-value">{value}</div>
      <div className={`progress-status pc-status-${statusClass}`}>
        {status === '완료' ? '✓ 완료' : status}
      </div>
    </button>
  );
}

function Field({ label, children }) {
  return (
    <label className="field">
      <span className="field-label">{label}</span>
      {children}
    </label>
  );
}

// =====================================================================
// 1. DECISION TAB
// =====================================================================
function DecisionTab({ ws, setWs, recommendedStage, onChosen }) {
  const toggleQ1 = (id) => {
    setWs((s) => ({
      ...s,
      decision: {
        ...s.decision,
        q1: { ...s.decision.q1, [id]: !s.decision.q1[id] },
      },
    }));
  };
  const toggleQ2 = (id) => {
    setWs((s) => ({
      ...s,
      decision: {
        ...s.decision,
        q2: { ...s.decision.q2, [id]: !s.decision.q2[id] },
      },
    }));
  };

  const q1All = STAGE_DECISION.q1.items.every((it) => ws.decision.q1[it.id]);
  const showQ2 = q1All;

  return (
    <div className="tab-content">
      <StepBanner
        kind="required"
        done={Object.keys(ws.decision?.q1 || {}).length > 0 || Object.keys(ws.decision?.q2 || {}).length > 0}
        todo="① 아래 문항을 체크해 SCERTS 단계를 결정하세요. (모든 자동 생성의 출발점)"
        okMsg="단계 결정 진행 중 — 권장 단계를 확인하고 아래에서 단계를 선택하세요."
        writer="therapist"
      />
      <div className="card">
        <h2 className="section-title">의사소통 단계 결정 기록지</h2>
        <p className="hint">
          아동의 현재 의사소통 수준을 평가하여 적합한 SCERTS 단계를 결정합니다.
          각 문항에 해당하는 경우 체크하세요.
        </p>

        <div className="decision-block">
          <h3 className="decision-title">{STAGE_DECISION.q1.title}</h3>
          {STAGE_DECISION.q1.items.map((it) => (
            <label key={it.id} className="check-row">
              <input
                type="checkbox"
                checked={!!ws.decision.q1[it.id]}
                onChange={() => toggleQ1(it.id)}
              />
              <span className="check-id">{it.id}</span>
              <span className="check-label">{it.label}</span>
            </label>
          ))}
          <div className="decision-hint">{STAGE_DECISION.q1.instruction}</div>
        </div>

        {showQ2 && (
          <div className="decision-block">
            <h3 className="decision-title">{STAGE_DECISION.q2.title}</h3>
            {STAGE_DECISION.q2.items.map((it) => (
              <label key={it.id} className="check-row">
                <input
                  type="checkbox"
                  checked={!!ws.decision.q2[it.id]}
                  onChange={() => toggleQ2(it.id)}
                />
                <span className="check-id">{it.id}</span>
                <span className="check-label">{it.label}</span>
              </label>
            ))}
            <div className="decision-hint">{STAGE_DECISION.q2.instruction}</div>
          </div>
        )}

        <div className="recommend-box">
          <div className="recommend-label">권장 단계</div>
          <div className="recommend-value">{STAGE_LABELS[recommendedStage]}</div>
          <p className="recommend-hint">
            진단 결과를 바탕으로 자동 추천된 단계입니다. 임상 판단에 따라 다른 단계를 선택할 수도 있습니다.
          </p>
        </div>

        <div className="stage-choose">
          {Object.keys(STAGE_LABELS).map((k) => (
            <button
              key={k}
              className={`stage-btn ${recommendedStage === k ? 'recommended' : ''} ${ws.meta.stage === k ? 'active' : ''}`}
              onClick={() => onChosen(k)}
            >
              <div className="stage-btn-label">{STAGE_LABELS[k]}</div>
              {recommendedStage === k && <div className="stage-btn-badge">권장</div>}
            </button>
          ))}
        </div>
      </div>
    </div>
  );
}

// =====================================================================
// 2. ASSESSMENT TAB
// =====================================================================
function AssessmentTab({ ws, updateScore, updateSes, setWs, onSavePre, onSavePost,
                         addSession, switchSession, removeSession, updateSessionMeta, setSessionDesignation,
                         showToast }) {
  const stageData = STAGE_DATA[ws.meta.stage];
  const [activeDomain, setActiveDomain] = useState(Object.keys(stageData)[0]);
  const [mode, setMode] = useState('score'); // 'score' | 'observation' | 'analysis'

  // 영역별 점수 합산
  const domainTotals = useMemo(() => {
    const totals = {};
    Object.entries(stageData).forEach(([key, domain]) => {
      let sum = 0;
      domain.groups.forEach((g) =>
        g.items.forEach((it) => {
          const v = ws.assessment.scores[it.id];
          if (typeof v === 'number') sum += v;
        }),
      );
      totals[key] = sum;
    });
    return totals;
  }, [ws.assessment.scores, stageData]);

  const domain = stageData[activeDomain];

  // 발달 의존성 트리에서 선행 항목 점수 확인
  const tree = JA_DEVELOPMENT_TREE[ws.meta.stage] || {};

  // MR/SR 패턴 자동 분석
  const mrSrAnalysis = useMemo(() => {
    const mrPct = stageData.mutualReg ? domainTotals.mutualReg / stageData.mutualReg.maxScore : 0;
    const srPct = stageData.selfReg ? domainTotals.selfReg / stageData.selfReg.maxScore : 0;
    // 채점된 항목이 거의 없으면 분석 안 함
    const mrItems = stageData.mutualReg ? stageData.mutualReg.groups.reduce((a, g) => a + g.items.length, 0) : 0;
    const srItems = stageData.selfReg ? stageData.selfReg.groups.reduce((a, g) => a + g.items.length, 0) : 0;
    const mrScored = stageData.mutualReg ? stageData.mutualReg.groups.reduce(
      (a, g) => a + g.items.filter((it) => typeof ws.assessment.scores[it.id] === 'number').length, 0) : 0;
    const srScored = stageData.selfReg ? stageData.selfReg.groups.reduce(
      (a, g) => a + g.items.filter((it) => typeof ws.assessment.scores[it.id] === 'number').length, 0) : 0;

    if (mrScored < mrItems * 0.3 || srScored < srItems * 0.3) {
      return { pattern: 'insufficient', mrPct, srPct };
    }

    let pattern;
    if (mrPct >= 0.5 && srPct < 0.4) pattern = 'highMR_lowSR';
    else if (mrPct < 0.4 && srPct >= 0.5) pattern = 'lowMR_highSR';
    else if (mrPct < 0.4 && srPct < 0.4) pattern = 'lowMR_lowSR';
    else pattern = 'balanced';

    return { pattern, mrPct, srPct };
  }, [ws.assessment.scores, stageData, domainTotals]);

  return (
    <div className="tab-content">
      <StepBanner
        kind="required"
        done={Object.keys(ws.assessment?.scores || {}).length >= 5}
        todo="③ 각 항목을 채점하세요(0/1/2점). 이 점수가 IEP·중간보고서·자동분석의 핵심 뿌리입니다."
        okMsg={`진단 채점 진행 중 — ${Object.keys(ws.assessment?.scores || {}).length}개 항목 입력됨. 채점할수록 자동 생성이 정확해집니다.`}
        writer="therapist"
      />
      <div className="card">
        <div className="assess-header">
          <h2 className="section-title">SCERTS 진단 — {STAGE_LABELS[ws.meta.stage]}</h2>
          <div className="assess-actions">
            <button className="btn-ghost" onClick={onSavePre}>사전 진단으로 저장</button>
            <button className="btn-ghost" onClick={onSavePost}>사후 진단으로 저장</button>
          </div>
        </div>

        {/* 진단 세션 탭 (분기별 채점 기록 관리) */}
        <SessionTabs
          ws={ws}
          addSession={addSession}
          switchSession={switchSession}
          removeSession={removeSession}
          updateSessionMeta={updateSessionMeta}
          setSessionDesignation={setSessionDesignation}
        />

        {/* 모드 토글 */}
        <div className="assess-mode-toggle no-print">
          {[
            { id: 'score', label: '✏️ 항목 채점', desc: '발달 항목별 0/1/2 점수 입력' },
            { id: 'observation', label: '📋 관찰 계획', desc: '관찰 일정과 환경 변인' },
            { id: 'analysis', label: '📊 자동 분석', desc: '발달 의존성·조절 패턴 진단' },
          ].map((m) => (
            <button
              key={m.id}
              className={`assess-mode-btn ${mode === m.id ? 'active' : ''}`}
              onClick={() => setMode(m.id)}
            >
              <div className="assess-mode-label">{m.label}</div>
              <div className="assess-mode-desc">{m.desc}</div>
            </button>
          ))}
        </div>

        {mode === 'score' && (
          <AssessScoreView
            ws={ws}
            setWs={setWs}
            stageData={stageData}
            domain={domain}
            domainTotals={domainTotals}
            activeDomain={activeDomain}
            setActiveDomain={setActiveDomain}
            updateScore={updateScore}
            updateSes={updateSes}
            tree={tree}
            showToast={showToast}
          />
        )}

        {mode === 'observation' && (
          <AssessObservationView ws={ws} setWs={setWs} />
        )}

        {mode === 'analysis' && (
          <AssessAnalysisView
            ws={ws}
            setWs={setWs}
            stageData={stageData}
            domainTotals={domainTotals}
            mrSrAnalysis={mrSrAnalysis}
          />
        )}
      </div>
    </div>
  );
}

// ── 채점 뷰 ──────────────────────────────────────────────────────
function AssessScoreView({
  ws, setWs, stageData, domain, domainTotals, activeDomain, setActiveDomain,
  updateScore, updateSes, tree, showToast,
}) {
  // 회기 일지 기반 진단 점수 제안 (역방향 자동 연계)
  const suggestions = useMemo(() => {
    const logs = ws.activities?.logI || [];
    if (logs.length === 0) return {};

    // 활성 세션 날짜 이후의 회기는 제외 (사후 진단 채점할 때 사전 회기만 반영)
    const sessionDate = (ws._allSessions || []).find((s) => s.id === ws._sessionId)?.date;
    const relevantLogs = sessionDate
      ? logs.filter((l) => !l.date || l.date <= sessionDate)
      : logs;

    // 항목 ID별 평가 집계
    const itemRatings = {};  // {itemId: [{rating, date}, ...]}
    const itemIdPattern = /\b([A-Z]{1,3}\d+\.\d+)\b/;
    const accumulate = (rows, logDate) => {
      (rows || []).forEach((r) => {
        if (!r || !r.goal || !r.rating) return;
        const match = r.goal.match(itemIdPattern);
        if (!match) return;
        const id = match[1];
        if (!itemRatings[id]) itemRatings[id] = [];
        itemRatings[id].push({ rating: r.rating, date: logDate || '' });
      });
    };
    relevantLogs.forEach((log) => {
      accumulate(log.goalsSocial, log.date);
      accumulate(log.goalsEmo, log.date);
    });

    // 항목별 제안 점수 계산
    const result = {};
    Object.entries(itemRatings).forEach(([id, ratings]) => {
      // 최근 5회로 제한 (가장 최근 우선)
      const recent = [...ratings].slice(-5);
      if (recent.length < 3) return;  // 3회 미만이면 신뢰도 부족
      const plus = recent.filter((r) => r.rating === '+').length;
      const partial = recent.filter((r) => r.rating === '+/−' || r.rating === '+/-').length;
      const minus = recent.filter((r) => r.rating === '−' || r.rating === '-').length;
      const reachRate = (plus + partial * 0.5) / recent.length;

      let suggested = null;
      let reason = '';
      if (plus >= 4 && minus === 0) {
        suggested = 2;
        reason = `최근 ${recent.length}회 중 ${plus}회 일관된 + → 2점 (안정적 사용)`;
      } else if (reachRate >= 0.7 && plus >= 2) {
        suggested = 2;
        reason = `최근 ${recent.length}회 도달률 ${Math.round(reachRate*100)}% → 2점 (일관성 ↑)`;
      } else if (reachRate >= 0.4) {
        suggested = 1;
        reason = `최근 ${recent.length}회 중 ${plus}회 + / ${partial}회 +/− → 1점 (촉구 시 가능)`;
      } else if (plus + partial >= 2) {
        suggested = 1;
        reason = `최근 ${recent.length}회 중 일부 + 관찰 → 1점 검토`;
      }

      if (suggested !== null) {
        result[id] = { suggested, reason, count: recent.length, reachRate };
      }
    });
    return result;
  }, [ws.activities, ws._sessionId, ws._allSessions]);

  // 적용 가능한 (현재 점수와 다른) 제안만 카운트
  const applicableSuggestions = useMemo(() => {
    return Object.entries(suggestions).filter(([id, sug]) => {
      const cur = ws.assessment.scores[id];
      return cur !== sug.suggested;
    });
  }, [suggestions, ws.assessment.scores]);

  const applyAllSuggestions = async () => {
    if (applicableSuggestions.length === 0) return;
    const msg = `회기 일지에서 ${applicableSuggestions.length}개 항목의 점수가 제안되었습니다.\n\n예시:\n` +
      applicableSuggestions.slice(0, 3).map(([id, s]) => `- ${id}: ${s.suggested}점 (${s.reason})`).join('\n') +
      (applicableSuggestions.length > 3 ? `\n... 외 ${applicableSuggestions.length - 3}개` : '') +
      `\n\n현재 미채점 항목만 자동 적용합니다 (이미 채점된 항목은 보존).\n계속하시겠습니까?`;
    if (!await appConfirm(msg)) return;
    let appliedCount = 0;
    let preservedCount = 0;
    applicableSuggestions.forEach(([id, s]) => {
      const cur = ws.assessment.scores[id];
      if (typeof cur === 'number') {
        preservedCount++;
        return;
      }
      updateScore(id, s.suggested);
      appliedCount++;
    });
    if (showToast) {
      showToast(`${appliedCount}개 항목 자동 채점 · ${preservedCount}개 기존 점수 보존`);
    }
  };

  return (
    <>
      {/* 회기 기반 제안 (있을 때만) */}
      {applicableSuggestions.length > 0 && (
        <div className="session-suggestion-bar">
          <div className="ss-info">
            <span className="ss-icon">💡</span>
            <div>
              <strong>{applicableSuggestions.length}개 항목 점수 제안 가능</strong>
              <div className="ss-hint">회기 일지의 도달 평가를 분석한 자동 제안입니다. 현재 점수와 다른 항목만 표시되며, 미채점 항목에만 자동 적용됩니다.</div>
            </div>
          </div>
          <button className="btn-primary btn-small" onClick={applyAllSuggestions}>
            제안 모두 적용
          </button>
        </div>
      )}

      {/* 분기 선택 */}
      <div className="quarter-row">
        {[1, 2, 3, 4].map((q) => (
          <button
            key={q}
            className={`quarter-btn ${ws.assessment.quarter === q ? 'active' : ''}`}
            onClick={() => setWs((s) => ({ ...s, assessment: { ...s.assessment, quarter: q } }))}
          >
            {q}/4 분기
          </button>
        ))}
      </div>

      {/* 채점 기준 안내 */}
      <div className="legend">
        {SCORING_LEGEND.map((l) => (
          <div key={l.score} className="legend-item">
            <span className={`legend-score score-${l.score}`}>{l.score}</span>
            <span className="legend-label"><strong>{l.label}</strong> · {l.desc}</span>
          </div>
        ))}
      </div>

      {/* 영역 탭 */}
      <div className="domain-tabs">
        {DOMAIN_GROUPS.map((group) => (
          <div key={group.title} className="domain-group">
            <div className="domain-group-title">{group.title}</div>
            <div className="domain-buttons">
              {group.domains.map((d) => {
                const dom = stageData[d];
                return (
                  <button
                    key={d}
                    className={`domain-btn ${activeDomain === d ? 'active' : ''}`}
                    onClick={() => setActiveDomain(d)}
                  >
                    <span className="domain-btn-label">{dom.label}</span>
                    <span className="domain-btn-score">{domainTotals[d]}/{dom.maxScore}</span>
                  </button>
                );
              })}
            </div>
          </div>
        ))}
      </div>

      {/* 항목 채점 */}
      <div className="domain-detail">
        <div className="domain-detail-header">
          <h3>{domain.label}</h3>
          <div className="domain-detail-score">총점 {domainTotals[activeDomain]} / {domain.maxScore}</div>
        </div>
        {domain.groups.map((group) => (
          <div key={group.title} className="score-group">
            <h4 className="score-group-title">{group.title}</h4>
            {group.items.map((item) => {
              const v = ws.assessment.scores[item.id];
              // 발달 의존성 체크
              const prereqs = tree[item.id] || [];
              const unmetPrereqs = prereqs.filter(
                (pid) => (ws.assessment.scores[pid] === 0 || ws.assessment.scores[pid] === undefined),
              );
              const hasWarning = (v === 2 || v === 1) && unmetPrereqs.length > 0;
              // 회기 기반 제안
              const sug = suggestions[item.id];
              const hasSuggestion = sug && sug.suggested !== v;
              // 원전 동일 항목(=) 연동
              const equivalents = getEquivalentItems(ws.meta.stage, item.id);
              return (
                <div key={item.id} className={`score-row ${hasWarning ? 'has-warning' : ''} ${hasSuggestion ? 'has-suggestion' : ''}`}>
                  <span className="score-id">{item.id}</span>
                  <span className="score-label">
                    {item.label}
                    {equivalents.length > 0 && (
                      <span className="equivalent-badge" title={`원전 동일 항목: ${equivalents.join(', ')} (채점 시 자동 연동됩니다)`}>
                        ⇄ {equivalents.join(', ')}
                      </span>
                    )}
                    {hasWarning && (
                      <span className="prereq-warning" title={`선행 항목 미도달: ${unmetPrereqs.join(', ')}`}>
                        ⚠ 선행 {unmetPrereqs.join(', ')}
                      </span>
                    )}
                    {hasSuggestion && (
                      <button
                        className="session-suggestion-chip"
                        onClick={() => updateScore(item.id, sug.suggested)}
                        title={sug.reason}
                      >
                        💡 회기 기반 {sug.suggested}점 제안
                      </button>
                    )}
                  </span>
                  <div className="score-buttons">
                    {[0, 1, 2].map((n) => (
                      <button
                        key={n}
                        className={`score-pip score-${n} ${v === n ? 'active' : ''}`}
                        onClick={() => updateScore(item.id, n)}
                      >
                        {n}
                      </button>
                    ))}
                    <button
                      className="score-clear"
                      onClick={() => updateScore(item.id, undefined)}
                      title="삭제"
                    >×</button>
                  </div>
                </div>
              );
            })}
          </div>
        ))}
      </div>

      {/* 사회-정서 성장 지표 */}
      <div className="ses-section">
        <h3>사회-정서 성장 지표 (0~10)</h3>
        <p className="hint" style={{ marginBottom: 14 }}>
          항목 채점이 미시적 능력이라면, 이 지표는 아동의 전반적 발달 방향성을 보여줍니다.
        </p>
        {SES_INDICATORS.map((ind) => {
          const v = ws.assessment.ses[ind.id] ?? 0;
          const range = SES_INTERPRETATION.ranges.find((r) => v >= r.min && v <= r.max);
          return (
            <div key={ind.id} className="ses-row">
              <span className="ses-label">{ind.label}</span>
              <input
                type="range"
                min={0} max={10} step={1}
                value={v}
                onChange={(e) => updateSes(ind.id, Number(e.target.value))}
              />
              <span className="ses-value" style={{ color: range?.color }}>
                {v}/10 · {range?.label}
              </span>
            </div>
          );
        })}
      </div>

      {/* 관찰 메모 */}
      <div className="notes-section">
        <h3>관찰 메모</h3>
        <textarea
          rows={4}
          value={ws.assessment.notes}
          onChange={(e) => setWs((s) => ({ ...s, assessment: { ...s.assessment, notes: e.target.value } }))}
          placeholder="진단 과정에서 관찰된 특이사항을 기록하세요."
        />
      </div>
    </>
  );
}

// ── 관찰 계획 뷰 (이전 ObservationTab을 가져와 토글로 통합) ────
function AssessObservationView({ ws, setWs }) {
  const updateCell = (planId, rowId, fieldId, value) => {
    setWs((s) => {
      const data = { ...s.observation.data };
      if (!data[planId]) data[planId] = {};
      if (!data[planId][rowId]) data[planId][rowId] = {};
      data[planId][rowId][fieldId] = value;
      return { ...s, observation: { ...s.observation, data } };
    });
  };
  const updateVariant = (planId, idx, value) => {
    setWs((s) => {
      const data = { ...s.observation.data };
      if (!data[planId]) data[planId] = {};
      if (!data[planId].activity) data[planId].activity = { variants: {} };
      data[planId].activity = { ...data[planId].activity, variants: { ...data[planId].activity.variants, [idx]: value } };
      return { ...s, observation: { ...s.observation, data } };
    });
  };

  return (
    <div className="observation-inner">
      <div className="info-box no-print">
        <strong>왜 관찰 계획이 필요한가요?</strong><br />
        SCERTS는 <em>"두 가지 상황에서 두 명의 파트너에 걸쳐 일관성 있게 도달"</em>해야 2점을 줍니다.
        그래서 진단 전에 관찰 환경을 다양하게 계획해야 정확한 채점이 가능합니다.
        최소 2개 자연스러운 상황(예: 가정 + 어린이집)에서, 친숙/비친숙 파트너를 포함해 관찰하세요.
      </div>

      <div className="no-print" style={{ textAlign: 'right', marginBottom: 12 }}>
        <button className="btn-primary" onClick={printReport}>📄 관찰 계획서 인쇄</button>
      </div>

      <div id="printable-report" className="printable">
        <ReportHeader title="SCERTS 관찰 계획서" ws={ws} />

        <section className="report-section">
          <p className="hint">{OBSERVATION_MAP.intro}</p>
          <table className="obs-table">
            <thead>
              <tr>
                <th style={{ width: '18%' }}>구분</th>
                <th>관찰 #1</th>
                <th>관찰 #2</th>
              </tr>
            </thead>
            <tbody>
              {OBSERVATION_MAP.rows.map((row) => (
                <tr key={row.id}>
                  <td className="obs-label-cell">
                    <strong>{row.label}</strong>
                    <div className="obs-note">{row.note}</div>
                  </td>
                  {ws.observation.plans.map((plan) => (
                    <td key={plan.id} className="obs-data-cell">
                      {renderObsCell(row, plan.id, ws.observation.data[plan.id]?.[row.id],
                        (fieldId, value) => updateCell(plan.id, row.id, fieldId, value),
                        (idx, value) => updateVariant(plan.id, idx, value),
                      )}
                    </td>
                  ))}
                </tr>
          ))}
        </tbody>
      </table>
        </section>
      </div>
    </div>
  );
}

// ── 자동 분석 뷰 — 단계특징, MR/SR 다리, 가족우선순위, SES 레이더 ──
function AssessAnalysisView({ ws, setWs, stageData, domainTotals, mrSrAnalysis }) {
  const profile = STAGE_PROFILE[ws.meta.stage];
  const scoredCount = Object.keys(ws.assessment.scores).filter(
    (k) => typeof ws.assessment.scores[k] === 'number',
  ).length;
  const totalItems = Object.values(stageData).reduce(
    (a, d) => a + d.groups.reduce((b, g) => b + g.items.length, 0), 0,
  );

  if (scoredCount < totalItems * 0.2) {
    return (
      <div className="empty-hint" style={{ padding: 24 }}>
        자동 분석은 진단 항목의 20% 이상이 채점되어야 활성화됩니다.
        현재 {scoredCount}/{totalItems}개 항목 채점됨.
      </div>
    );
  }

  const mrSrInfo = mrSrAnalysis.pattern !== 'insufficient' ? MR_SR_BRIDGE[mrSrAnalysis.pattern] : null;

  return (
    <div className="analysis-inner">
      {/* 단계별 발달 특징 */}
      <div className="analysis-block">
        <h3 className="analysis-h3">📍 {profile.headline} — 발달적 특징</h3>
        <div className="profile-card">
          <div className="profile-subtitle">{profile.subtitle} · {profile.age}</div>
          <p className="profile-summary">{profile.summary}</p>
          <div className="profile-features">
            <strong>이 단계의 핵심 특징</strong>
            <ul>
              {profile.features.map((f, i) => <li key={i}>{f}</li>)}
            </ul>
          </div>
        </div>
      </div>

      {/* MR/SR 다리 분석 */}
      {mrSrInfo && (
        <div className="analysis-block">
          <h3 className="analysis-h3">🌉 상호조절(MR) ↔ 자기조절(SR) 분석</h3>
          <div className="mrsr-bars">
            <div className="mrsr-bar">
              <div className="mrsr-bar-label">MR (도움 받아 조절)</div>
              <div className="mrsr-bar-track">
                <div className="mrsr-bar-fill mr" style={{ width: `${Math.round(mrSrAnalysis.mrPct * 100)}%` }} />
              </div>
              <div className="mrsr-bar-pct">{Math.round(mrSrAnalysis.mrPct * 100)}%</div>
            </div>
            <div className="mrsr-bar">
              <div className="mrsr-bar-label">SR (스스로 조절)</div>
              <div className="mrsr-bar-track">
                <div className="mrsr-bar-fill sr" style={{ width: `${Math.round(mrSrAnalysis.srPct * 100)}%` }} />
              </div>
              <div className="mrsr-bar-pct">{Math.round(mrSrAnalysis.srPct * 100)}%</div>
            </div>
          </div>
          <div className="pattern-card">
            <div className="pattern-title">진단된 패턴: {mrSrInfo.title}</div>
            <p className="pattern-interpretation">{mrSrInfo.interpretation}</p>
            <strong>발달 다리 전략</strong>
            <ul className="strategy-list">
              {mrSrInfo.strategies.map((s, i) => <li key={i}>{s}</li>)}
            </ul>
          </div>
        </div>
      )}

      {/* 가족 우선순위 (SCERTS 원전 부합) */}
      <FamilyPrioritiesBlock ws={ws} setWs={setWs} stageData={stageData} />

      {/* 사회-정서 지표 레이더 */}
      <div className="analysis-block">
        <h3 className="analysis-h3">🌱 사회-정서 성장 지표</h3>
        <SesRadarChart values={ws.assessment.ses} />
      </div>
    </div>
  );
}

// ── 가족의 견해 및 우선순위 (SCERTS 매뉴얼 p.20/42/67 양식 부합) ──
function FamilyPrioritiesBlock({ ws, setWs, stageData }) {
  const fp = ws.familyPriorities || {};
  const updateFP = (patch) => {
    setWs((s) => ({ ...s, familyPriorities: { ...s.familyPriorities, ...patch } }));
  };

  // 0~1점 항목 중에서 가족이 선택할 수 있도록 노출
  const candidateItems = useMemo(() => {
    const list = [];
    Object.entries(stageData).forEach(([dkey, domain]) => {
      domain.groups.forEach((g) =>
        g.items.forEach((it) => {
          const v = ws.assessment.scores[it.id];
          if (v === 0 || v === 1) {
            list.push({ id: it.id, label: it.label, domain: domain.label });
          }
        }),
      );
    });
    return list;
  }, [ws.assessment.scores, stageData]);

  const toggleFocus = (id) => {
    const cur = fp.focusGoalIds || [];
    const next = cur.includes(id) ? cur.filter((x) => x !== id) : [...cur, id];
    updateFP({ focusGoalIds: next });
  };

  return (
    <div className="analysis-block">
      <h3 className="analysis-h3">❤️ 가족의 견해 및 우선순위</h3>
      <div className="info-box">
        SCERTS 매뉴얼은 진단 결과를 가족과 공유하고, 가족의 관점·우선순위를 IEP 목표 선정에
        반드시 반영하도록 안내합니다 (Prizant et al., 2006, 부록 진단 요약지 p.20/42/67).
        아래 4가지를 가족과 함께 채워보세요.
      </div>

      <div className="family-priorities-grid">
        <div className="fp-question">
          <div className="fp-q-label">1. 이 진단 프로파일이 자녀를 정확히 묘사하고 있습니까? 만일 그렇지 않다면, 어떤 점에서 그러한지 설명해 주십시오.</div>
          <textarea
            className="iq-text"
            rows={3}
            value={fp.profileAccurate || ''}
            onChange={(e) => updateFP({ profileAccurate: e.target.value })}
            placeholder="면담 시 보호자의 답변을 그대로 기록 (예: 어떤 점이 맞고, 어떤 점이 다른지)"
          />
        </div>
        <div className="fp-question">
          <div className="fp-q-label">2. 자녀를 위한 교육을 계획하는 데 필요하다고 생각되는 추가 정보가 있습니까?</div>
          <textarea
            className="iq-text"
            rows={3}
            value={fp.additionalInfo || ''}
            onChange={(e) => updateFP({ additionalInfo: e.target.value })}
            placeholder="가정 상황, 형제 관계, 의료적 사항 등 교육 계획에 참고할 정보"
          />
        </div>
        <div className="fp-question">
          <div className="fp-q-label">3. 만일 자녀를 위해 한 가지 일에 집중해야 한다면 어떤 것에 집중하시겠습니까?</div>
          <textarea
            className="iq-text"
            rows={3}
            value={fp.focusOne || ''}
            onChange={(e) => updateFP({ focusOne: e.target.value })}
            placeholder="보호자가 가장 우선시하는 한 가지를 그대로 기록"
          />
        </div>
        <div className="fp-question">
          <div className="fp-q-label">4. 앞으로 3개월 내에 자녀가 배우기를 바라는 기술은 무엇입니까?</div>
          <textarea
            className="iq-text"
            rows={3}
            value={fp.threeMonthHope || ''}
            onChange={(e) => updateFP({ threeMonthHope: e.target.value })}
            placeholder="보호자가 바라는 구체적 기술을 그대로 기록 (예: 이름 부르면 쳐다보기)"
          />
        </div>
      </div>

      {candidateItems.length > 0 && (
        <div className="fp-item-select">
          <div className="fp-q-label" style={{ marginBottom: 10 }}>
            가족이 우선시하는 발달 항목 선택 <span style={{ color: '#6b6452', fontWeight: 400 }}>(IEP 추천에서 ❤️ 표시되며 가장 큰 가중치를 받습니다)</span>
          </div>
          <div className="goal-recommend">
            {candidateItems.map((it) => {
              const selected = (fp.focusGoalIds || []).includes(it.id);
              return (
                <button
                  key={it.id}
                  className={`goal-chip ${selected ? 'selected family-choice' : ''}`}
                  onClick={() => toggleFocus(it.id)}
                >
                  <span className="goal-chip-id">{it.id}</span>
                  {selected && <span className="goal-tag family-tag">❤️</span>}
                  <span>{it.label}</span>
                </button>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
}

// ── 사회-정서 지표 레이더 차트 (SVG) ────────────────────────────
function SesRadarChart({ values }) {
  const cx = 220, cy = 220, R = 160;
  const n = SES_INDICATORS.length;

  const points = SES_INDICATORS.map((ind, i) => {
    const angle = (Math.PI * 2 * i) / n - Math.PI / 2;
    const v = (values[ind.id] ?? 0) / 10;
    const x = cx + Math.cos(angle) * R * v;
    const y = cy + Math.sin(angle) * R * v;
    return { x, y, ind, angle, v };
  });

  const polyPoints = points.map((p) => `${p.x},${p.y}`).join(' ');

  // 그리드 (5단계)
  const gridLevels = [0.2, 0.4, 0.6, 0.8, 1.0];

  return (
    <div className="radar-wrap">
      <svg viewBox="0 0 440 440" className="ses-radar">
        {/* 그리드 */}
        {gridLevels.map((lv) => (
          <polygon
            key={lv}
            points={SES_INDICATORS.map((_, i) => {
              const angle = (Math.PI * 2 * i) / n - Math.PI / 2;
              return `${cx + Math.cos(angle) * R * lv},${cy + Math.sin(angle) * R * lv}`;
            }).join(' ')}
            fill="none"
            stroke="#e6e0cd"
            strokeWidth="1"
          />
        ))}
        {/* 축 라인 */}
        {SES_INDICATORS.map((ind, i) => {
          const angle = (Math.PI * 2 * i) / n - Math.PI / 2;
          return (
            <line
              key={ind.id}
              x1={cx} y1={cy}
              x2={cx + Math.cos(angle) * R}
              y2={cy + Math.sin(angle) * R}
              stroke="#e6e0cd"
              strokeWidth="1"
            />
          );
        })}
        {/* 데이터 폴리곤 */}
        <polygon
          points={polyPoints}
          fill="rgba(45, 74, 62, 0.18)"
          stroke="#2d4a3e"
          strokeWidth="2"
        />
        {/* 데이터 포인트 */}
        {points.map((p, i) => (
          <circle key={i} cx={p.x} cy={p.y} r={4} fill="#c19a3a" stroke="#2d4a3e" strokeWidth="1.5" />
        ))}
        {/* 라벨 */}
        {SES_INDICATORS.map((ind, i) => {
          const angle = (Math.PI * 2 * i) / n - Math.PI / 2;
          const lx = cx + Math.cos(angle) * (R + 30);
          const ly = cy + Math.sin(angle) * (R + 30);
          const v = values[ind.id] ?? 0;
          return (
            <g key={ind.id}>
              <text
                x={lx} y={ly}
                textAnchor="middle"
                dominantBaseline="middle"
                className="radar-label"
              >
                {ind.label}
              </text>
              <text
                x={lx} y={ly + 14}
                textAnchor="middle"
                className="radar-value"
              >
                {v}/10
              </text>
            </g>
          );
        })}
      </svg>
    </div>
  );
}

// =====================================================================
// 3. IEP TAB
// =====================================================================
function IEPTab({ ws, setWs, onArchive, showToast }) {
  const stageData = STAGE_DATA[ws.meta.stage];

  const updateIEP = (path, value) => {
    setWs((s) => {
      const next = { ...s, iep: { ...s.iep } };
      const keys = path.split('.');
      let cur = next.iep;
      for (let i = 0; i < keys.length - 1; i++) {
        cur[keys[i]] = { ...cur[keys[i]] };
        cur = cur[keys[i]];
      }
      cur[keys[keys.length - 1]] = value;
      return next;
    });
  };

  // 점수가 0~1인 항목들 (우선순위 추천)
  const recommendedGoals = useMemo(() => {
    const list = [];
    const stageKey = ws.meta.stage;
    const weights = IEP_PRIORITY_WEIGHTS;
    const foundations = FOUNDATION_ITEMS[stageKey] || new Set();
    const tree = JA_DEVELOPMENT_TREE[stageKey] || {};
    const familyFocus = new Set(ws.familyPriorities?.focusGoalIds || []);

    Object.entries(stageData).forEach(([dkey, domain]) => {
      domain.groups.forEach((g) =>
        g.items.forEach((it) => {
          const v = ws.assessment.scores[it.id];
          if (v === 0 || v === 1) {
            // 우선순위 점수 계산
            let priority = weights.scoreBoost[v] || 0;
            priority += weights.domainBoost[stageKey]?.[dkey] || 0;
            if (foundations.has(it.id)) priority += weights.foundationBoost;
            // 가족이 우선 선택한 항목은 SCERTS의 핵심 가치 - 가장 큰 가중치
            const isFamilyChoice = familyFocus.has(it.id);
            if (isFamilyChoice) priority += weights.familyChoiceBoost;
            // 선행 항목이 모두 충족된 경우만 추천 가능
            const prereqs = tree[it.id] || [];
            const prereqsMet = prereqs.every(
              (pid) => ws.assessment.scores[pid] === 1 || ws.assessment.scores[pid] === 2,
            );
            // 선행 미충족이면 우선순위 감소 (단, 가족 선택은 존중)
            if (!prereqsMet && prereqs.length > 0 && !isFamilyChoice) priority -= 30;

            list.push({
              id: it.id,
              label: it.label,
              domain: domain.label,
              domainKey: dkey,
              score: v,
              priority,
              isFoundation: foundations.has(it.id),
              isFamilyChoice,
              prereqsMet,
            });
          }
        }),
      );
    });

    // 우선순위 내림차순 정렬
    return list.sort((a, b) => b.priority - a.priority);
  }, [ws.assessment.scores, stageData, ws.meta.stage, ws.familyPriorities]);

  const toggleGoal = (item) => {
    // IS/LS(교류 지원)는 파트너 목표로 분기, 그 외는 아동 목표(selectedGoals)
    // recommendedGoals는 domainKey(영문키)와 domain(한글라벨)을 둘 다 가짐 → domainKey 우선 비교
    const dk = item.domainKey || item.domain;
    const isPartnerDomain = (dk === 'interpersonalSupport' || dk === 'learningSupport');
    setWs((s) => {
      if (isPartnerDomain) {
        const arr = [...(s.iep.partnerGoals || [])];
        // 항목이 객체면 id로, 문자열이면 "[id]" 접두로 매칭
        const matches = (v) => (typeof v === 'object' && v?.id === item.id) ||
                               (typeof v === 'string' && v.startsWith(`[${item.id}]`));
        const existsIdx = arr.findIndex(matches);
        if (existsIdx >= 0) {
          arr.splice(existsIdx, 1); // 토글: 이미 있으면 제거
        } else {
          // 빈 슬롯에 채우거나 끝에 추가 (객체 형태로 통일)
          const entry = { id: item.id, label: item.label, domain: item.domain, domainKey: dk };
          const emptyIdx = arr.findIndex((v) => !v || (typeof v === 'string' && !v.trim()));
          if (emptyIdx >= 0) arr[emptyIdx] = entry;
          else arr.push(entry);
        }
        return { ...s, iep: { ...s.iep, partnerGoals: arr } };
      }
      // 아동 목표 (기존 동작)
      const exists = s.iep.selectedGoals.find((g) => g.id === item.id);
      const next = exists
        ? s.iep.selectedGoals.filter((g) => g.id !== item.id)
        : [...s.iep.selectedGoals, { id: item.id, label: item.label, domain: item.domain }];
      return { ...s, iep: { ...s.iep, selectedGoals: next } };
    });
  };

  const updateSelectedGoalText = (id, text) => {
    setWs((s) => ({
      ...s,
      iep: {
        ...s.iep,
        selectedGoals: s.iep.selectedGoals.map((g) => (g.id === id ? { ...g, customGoal: text } : g)),
      },
    }));
  };

  const autoFillIEP = async () => {
    const stageData = STAGE_DATA[ws.meta.stage];
    const stageLabel = STAGE_LABELS[ws.meta.stage];
    const profile = STAGE_PROFILE[ws.meta.stage];

    // 진단 완료도 확인
    const totalItems = Object.values(stageData).reduce(
      (a, d) => a + d.groups.reduce((b, g) => b + g.items.length, 0), 0,
    );
    const scoredCount = Object.keys(ws.assessment.scores).filter(
      (k) => typeof ws.assessment.scores[k] === 'number',
    ).length;
    const completionPct = Math.round((scoredCount / totalItems) * 100);

    if (completionPct < 30) {
      if (!await appConfirm(
        `진단 채점이 ${completionPct}%만 완료되었습니다 (${scoredCount}/${totalItems}개).\n` +
        `자동 채움 결과의 신뢰도가 낮을 수 있습니다.\n\n계속하시겠습니까?`
      )) return;
    }

    // 영역별 점수 합산
    const domainTotals = {};
    Object.entries(stageData).forEach(([key, domain]) => {
      let sum = 0;
      domain.groups.forEach((g) =>
        g.items.forEach((it) => {
          const v = ws.assessment.scores[it.id];
          if (typeof v === 'number') sum += v;
        }),
      );
      domainTotals[key] = { score: sum, max: domain.maxScore, label: domain.label };
    });

    // 진단 점수 기반 현행 수준 자동 생성
    const scTotal = (domainTotals.joinAttention?.score || 0) + (domainTotals.symbolUse?.score || 0);
    const scMax = (domainTotals.joinAttention?.max || 0) + (domainTotals.symbolUse?.max || 0);
    const erTotal = (domainTotals.mutualReg?.score || 0) + (domainTotals.selfReg?.score || 0);
    const erMax = (domainTotals.mutualReg?.max || 0) + (domainTotals.selfReg?.max || 0);
    const tsTotal = (domainTotals.interpersonalSupport?.score || 0) + (domainTotals.learningSupport?.score || 0);
    const tsMax = (domainTotals.interpersonalSupport?.max || 0) + (domainTotals.learningSupport?.max || 0);

    const pct = (a, b) => b ? Math.round((a / b) * 100) : 0;

    // MR/SR 패턴 식별
    const mrPct = domainTotals.mutualReg ? domainTotals.mutualReg.score / domainTotals.mutualReg.max : 0;
    const srPct = domainTotals.selfReg ? domainTotals.selfReg.score / domainTotals.selfReg.max : 0;
    let mrSrPattern = null;
    if (mrPct >= 0.5 && srPct < 0.4) mrSrPattern = 'highMR_lowSR';
    else if (mrPct < 0.4 && srPct >= 0.5) mrSrPattern = 'lowMR_highSR';
    else if (mrPct < 0.4 && srPct < 0.4) mrSrPattern = 'lowMR_lowSR';
    else if (mrPct >= 0.5 && srPct >= 0.5) mrSrPattern = 'balanced';
    const mrSrInfo = mrSrPattern ? MR_SR_BRIDGE[mrSrPattern] : null;

    // 질문지 응답에서 핵심 답변 추출 (사회의사소통 1, 정서조절 1, 교류지원 11 등)
    const interviewAns = ws.interview?.answers || {};
    const stagePrefix = ws.meta.stage === 'social' ? 'sp' : ws.meta.stage === 'language' ? 'lp' : 'cp';
    const q_sc1 = interviewAns[`${stagePrefix}_sc_1`] || '';
    const q_er_strength = interviewAns[`${stagePrefix}_er_2`] || ''; // 가장 흥미를 보이는 활동
    const q_er_challenge = interviewAns[`${stagePrefix}_er_3`] || ''; // 가장 힘들어하는 활동

    // 가족 우선순위
    const fp = ws.familyPriorities || {};
    const familyFocusText = fp.focusOne || '';
    const familyHopeText = fp.threeMonthHope || '';

    // 현행 수준 자동 생성 (진단 결과 + 질문지 정보)
    const cName = ws.meta.childName || '';
    // 보호자 보고 문장: 끝에 마침표 없으면 붙여서 다음 문장과 자연스럽게 분리
    const q_sc1_clean = q_sc1 ? (q_sc1.slice(0, 100).replace(/[.。]?\s*$/, '') + '. ') : '';
    const currentLevel = {
      sc: `${nmEunNeun(cName)} 사회 의사소통 영역 진단에서 ${scTotal}/${scMax}점(${pct(scTotal, scMax)}%)을 받았다. ` +
          (q_sc1_clean ? `보호자 보고에 따르면 ${q_sc1_clean}` : '') +
          `${profile.headline} 수준에서 공동관심은 ${pct(domainTotals.joinAttention?.score || 0, domainTotals.joinAttention?.max || 0)}%, ` +
          `상징 사용은 ${pct(domainTotals.symbolUse?.score || 0, domainTotals.symbolUse?.max || 0)}%로 나타났다. ` +
          `점수가 낮은 항목을 IEP 목표로 선정하였다.`,
      er: `${nmEunNeun(cName)} 정서 조절 영역 진단에서 ${erTotal}/${erMax}점(${pct(erTotal, erMax)}%)을 받았다. ` +
          `상호조절 ${Math.round(mrPct * 100)}%, 자기조절 ${Math.round(srPct * 100)}%로, ` +
          `${mrSrInfo ? `${mrSrInfo.title}에 해당한다. ` : '두 영역이 균형적이다. '}` +
          (mrSrInfo ? localizeText(mrSrInfo.interpretation, cName) + ' ' : '') +
          (q_er_strength ? `흥미를 보이는 활동은 ${q_er_strength.slice(0, 80).replace(/[.。]?\s*$/, '')}이며, ` : '') +
          (q_er_challenge ? `어려움을 보이는 상황은 ${q_er_challenge.slice(0, 80).replace(/[.。]?\s*$/, '')}이다.` : ''),
      ts: `${nmEunNeun(cName)} 교류 지원 영역 진단에서 ${tsTotal}/${tsMax}점(${pct(tsTotal, tsMax)}%)을 받았다. ` +
          `대인관계 지원 ${pct(domainTotals.interpersonalSupport?.score || 0, domainTotals.interpersonalSupport?.max || 0)}%, ` +
          `학습 지원 ${pct(domainTotals.learningSupport?.score || 0, domainTotals.learningSupport?.max || 0)}% 수준이다. ` +
          `파트너의 반응성, 시작행동 촉진, 언어 조절, 시각 지원 사용에서 교실과 가정 간 일관성 확보가 우선 과제이다.`,
    };

    // 가족 우선순위가 있으면 단기 목표에 반영
    const familyEcho = familyHopeText ? ` (가족 희망: ${familyHopeText.slice(0, 50).replace(/[.。]?\s*$/, '')})` : '';

    // priorities 텍스트 끝의 '안정화/확장' 등과 뒤 동사 중복 방지
    const scPriority = profile.priorities[0].split('—')[0].trim();
    const scGoalVerb = /안정화$/.test(scPriority) ? '를 목표로 한다' :
                       /확장$/.test(scPriority) ? '을 목표로 한다' : '을 안정화한다';

    const filled = {
      currentLevel,
      annualGoals: {
        sc: `${nmEunNeun(cName)} 일상적인 놀이 및 과제 상황에서 기능적인 의사소통 수단을 사용하여 ` +
            `${scPriority}${scGoalVerb}.${familyEcho}`,
        er: `${nmEunNeun(cName)} 감정 변화 상황에서 ${mrSrInfo && mrSrPattern === 'lowMR_lowSR' ? '파트너의 도움을 받아' : '점진적으로 스스로'} ` +
            `조절 전략을 사용하여 활동에 재참여한다.`,
        ts: `파트너는 ${nmUi(cName)} 의사소통 및 정서 신호를 일관성 있게 인식하고 반응하며, ` +
            `예측 가능한 환경과 시각 지원을 제공한다.`,
      },
      shortGoals: {
        sc: '원하는 활동 또는 물건을 요청 시 자발적으로 단어 이상 수준의 의사소통을 1일 2회 이상 사용한다.',
        er: mrSrInfo && mrSrInfo.strategies && mrSrInfo.strategies[0]
            ? localizeText(mrSrInfo.strategies[0], cName)
            : '활동 전 전이 상황에서 시각일과표·타이머 사용을 통해 전이에 긍정적으로 반응한다.',
        ts: '시각일과표를 보며 다음 활동을 예측하고, 준비 행동을 3회 중 2회 이상 수행한다.',
      },
      strategies: {
        sc: 'NET + FCT, 촉구 계층, 자연스러운 의사소통 기회 조성',
        er: '시각 단서 사용, 전이 예고 루틴, 감정 온도계',
        ts: '시각일과표, 강화계획, 일관된 파트너 반응',
      },
      measures: {
        sc: '일일 기록지, 빈도 측정',
        er: '반응 체크리스트, 회복 시간 측정',
        ts: '활동 전 관찰 기록, 파트너 자기점검',
      },
    };
    // 기존 사용자 입력은 보존, 빈 값만 자동 채움
    let filledCount = 0;
    let preservedCount = 0;
    const merge = (existing, generated) => {
      const out = { ...existing };
      Object.keys(generated).forEach((k) => {
        if (!existing[k] || (typeof existing[k] === 'string' && existing[k].trim() === '')) {
          out[k] = generated[k];
          filledCount++;
        } else {
          preservedCount++;
        }
      });
      return out;
    };
    setWs((s) => ({
      ...s,
      iep: {
        ...s.iep,
        currentLevel: merge(s.iep.currentLevel || {}, filled.currentLevel),
        annualGoals: merge(s.iep.annualGoals || {}, filled.annualGoals),
        shortGoals: merge(s.iep.shortGoals || {}, filled.shortGoals),
        strategies: merge(s.iep.strategies || {}, filled.strategies),
        measures: merge(s.iep.measures || {}, filled.measures),
      },
    }));
    if (showToast) {
      const msg = preservedCount > 0
        ? `${filledCount}개 필드 자동 채움 · ${preservedCount}개 기존 입력 보존`
        : `${filledCount}개 필드를 자동으로 채웠습니다`;
      showToast(msg);
    }
  };

  return (
    <div className="tab-content">
      <StepBanner
        kind="auto"
        done={false}
        todo='"📊 진단 결과로 자동 채움" 버튼을 누르면 진단·질문지·가족 우선순위를 바탕으로 초안이 채워집니다. 빈 칸만 채우고 직접 쓴 내용은 보존됩니다.'
        writer="therapist"
      />
      <div className="card no-break">
        <div className="iep-header">
          <h2 className="section-title">개별화 프로그램 계획안 (IEP)</h2>
          <div className="iep-actions no-print">
            <button className="btn-ghost" onClick={autoFillIEP}>📊 진단 결과로 자동 채움</button>
            <button className="btn-ghost" onClick={onArchive}>보관함에 저장</button>
            <button className="btn-primary" onClick={printReport}>인쇄 / PDF</button>
          </div>
        </div>

        {/* 인쇄용 보고서 */}
        <div id="printable-report" className="printable">
          <ReportHeader title="SCERTS 개별화 프로그램 계획안 (IEP)" ws={ws}
            dateValue={ws.iep.reportDate}
            dateOnChange={(v) => setWs((s) => ({ ...s, iep: { ...s.iep, reportDate: v } }))} />

          {/* 단계별 발달 특징 박스 (자동) */}
          <StageProfileBox stage={ws.meta.stage} />

          {/* 가족의 견해 및 우선순위 (SCERTS 원전 부합) */}
          <FamilyPrioritiesReport ws={ws} />

          {/* 진단 관찰 정보 (자동 인용) */}
          <ObservationSummary ws={ws} />

          {/* 2. 세부 목표 및 중재 전략 */}
          <section className="report-section">
            <h3 className="report-h3">1. 세부 목표 및 중재 전략</h3>
            <table className="report-table">
              <thead>
                <tr>
                  <th style={{ width: '14%' }}>영역</th>
                  <th>연간 목표</th>
                  <th>단기 목표</th>
                  <th style={{ width: '16%' }}>교수 전략</th>
                  <th style={{ width: '14%' }}>측정 방법</th>
                </tr>
              </thead>
              <tbody>
                <IEPRow
                  area="사회적 의사소통"
                  paths={['annualGoals.sc', 'shortGoals.sc', 'strategies.sc', 'measures.sc']}
                  ws={ws}
                  updateIEP={updateIEP}
                />
                <IEPRow
                  area="정서 조절"
                  paths={['annualGoals.er', 'shortGoals.er', 'strategies.er', 'measures.er']}
                  ws={ws}
                  updateIEP={updateIEP}
                />
                <IEPRow
                  area="교류 지원"
                  paths={['annualGoals.ts', 'shortGoals.ts', 'strategies.ts', 'measures.ts']}
                  ws={ws}
                  updateIEP={updateIEP}
                />
              </tbody>
            </table>
          </section>

          {/* 3. 평가 결과 및 현행 수준 */}
          <section className="report-section">
            <h3 className="report-h3">2. 평가 결과 및 현행 수준</h3>
            <div className="level-blocks">
              {[
                { key: 'sc', label: '사회적 의사소통 영역', placeholder: '아동의 사회적 의사소통 현행 수준을 기술하세요.' },
                { key: 'er', label: '정서 조절 영역', placeholder: '아동의 정서 조절 현행 수준을 기술하세요.' },
                { key: 'ts', label: '교류 지원 영역', placeholder: '교류 지원 측면의 현행 수준을 기술하세요.' },
              ].map((b) => (
                <div key={b.key} className="level-block">
                  <div className="level-block-label">{b.label}</div>
                  <Editable
                    value={ws.iep.currentLevel[b.key]}
                    onChange={(v) => updateIEP(`currentLevel.${b.key}`, v)}
                    placeholder={b.placeholder}
                    multiline
                  />
                </div>
              ))}
            </div>
          </section>

          {/* 4. 주간 교수목표의 우선순위 */}
          <section className="report-section page-break-before">
            <h3 className="report-h3">3. SCERTS 주간 교수목표의 우선순위</h3>
            <p className="hint no-print">
              SCERTS 매뉴얼은 우선순위 결정 시 <strong>① 진단 점수 ② 사회-정서 지표 ③ 가족의 견해</strong>
              세 요소를 통합하도록 안내합니다. 아래 추천은 이 원칙을 자동 반영한 정렬입니다.
              <span className="legend-tag family">❤️ 가족 우선</span>은 가족 우선순위에서 선택한 항목,
              <span className="legend-tag found">🏛 토대</span>는 영역의 첫 항목,
              <span className="legend-tag prereq">⚠ 선행</span>은 선행 항목이 아직 미도달인 항목입니다.
              <span className="legend-tag partner-legend">👥 파트너</span>는 교류 지원 영역으로, 클릭 시 우측 "파트너 교류 지원" 칸에 추가됩니다.
              <br />
              <em>※ 토대성·선행 의존성은 임상 판단의 보조 가이드이며 절대적 규칙이 아닙니다.</em>
            </p>
            <div className="goal-recommend no-print">
              {recommendedGoals.length === 0 && (
                <div className="empty-hint">먼저 진단 채점을 완료해 주세요.</div>
              )}
              {recommendedGoals.slice(0, 30).map((g, rank) => {
                const gdk = g.domainKey || g.domain;
                const isPartnerDomain = (gdk === 'interpersonalSupport' || gdk === 'learningSupport');
                const selected = isPartnerDomain
                  ? (ws.iep.partnerGoals || []).some((v) =>
                      (typeof v === 'object' && v?.id === g.id) ||
                      (typeof v === 'string' && v.startsWith(`[${g.id}]`)))
                  : ws.iep.selectedGoals.some((s) => s.id === g.id);
                return (
                  <button
                    key={g.id}
                    className={`goal-chip ${selected ? 'selected' : ''} ${g.isFoundation ? 'foundation' : ''} ${g.isFamilyChoice ? 'family-choice' : ''} ${!g.prereqsMet ? 'prereq-unmet' : ''} ${isPartnerDomain ? 'partner-domain' : ''}`}
                    onClick={() => toggleGoal(g)}
                    title={`우선순위 점수: ${g.priority}${isPartnerDomain ? ' (파트너 교류 지원 목표)' : ''}`}
                  >
                    {rank < 5 && <span className="goal-rank">#{rank + 1}</span>}
                    <span className="goal-chip-id">{g.id}</span>
                    {isPartnerDomain && <span className="goal-tag partner-tag">👥</span>}
                    {g.isFamilyChoice && <span className="goal-tag family-tag">❤️</span>}
                    {g.isFoundation && <span className="goal-tag found-tag">🏛</span>}
                    {!g.prereqsMet && <span className="goal-tag prereq-tag">⚠</span>}
                    <span>{g.label}</span>
                    <span className={`goal-chip-score score-${g.score}`}>{g.score}점</span>
                  </button>
                );
              })}
            </div>

            <table className="goal-table">
              <thead>
                <tr>
                  <th style={{ width: '50%' }}>아동: 사회 의사소통 및 정서 조절 목표</th>
                  <th>파트너: 교류 지원 목표</th>
                </tr>
              </thead>
              <tbody>
                {(() => {
                  // 행 수: 아동/파트너 목표 중 더 많은 쪽에 맞추되 최소 8행
                  const childCount = (ws.iep.selectedGoals || []).length;
                  const partnerCount = (ws.iep.partnerGoals || []).length;
                  const rowCount = Math.max(8, childCount, partnerCount);
                  return Array.from({ length: rowCount }).map((_, i) => {
                  const childGoal = ws.iep.selectedGoals[i];
                  const partnerGoal = ws.iep.partnerGoals[i] || '';
                  return (
                    <tr key={i}>
                      <td>
                        {childGoal ? (
                          <div>
                            <span className="goal-id-tag">{childGoal.id}</span>
                            <Editable
                              value={childGoal.customGoal || childGoal.label}
                              onChange={(v) => updateSelectedGoalText(childGoal.id, v)}
                              multiline
                            />
                          </div>
                        ) : (
                          <span className="empty-cell no-print">위 추천 목표를 선택하세요</span>
                        )}
                      </td>
                      <td>
                        {(() => {
                          const pg = ws.iep.partnerGoals[i];
                          // 객체 형태 (추천 칩에서 자동 추가): ID 태그 + 라벨 분리 표시
                          if (pg && typeof pg === 'object' && pg.id) {
                            return (
                              <div>
                                <span className="goal-id-tag">{pg.id}</span>
                                <Editable
                                  value={pg.customGoal || pg.label || ''}
                                  onChange={(v) => {
                                    const arr = [...(ws.iep.partnerGoals || [])];
                                    arr[i] = { ...pg, customGoal: v };
                                    updateIEP('partnerGoals', arr);
                                  }}
                                  multiline
                                />
                              </div>
                            );
                          }
                          // 문자열 형태 (직접 입력): 평소 입력칸
                          return (
                            <Editable
                              value={typeof pg === 'string' ? pg : ''}
                              onChange={(v) => {
                                const arr = [...(ws.iep.partnerGoals || [])];
                                arr[i] = v;
                                updateIEP('partnerGoals', arr);
                              }}
                              placeholder="파트너 교류 지원 목표"
                              multiline
                            />
                          );
                        })()}
                      </td>
                    </tr>
                  );
                  });
                })()}
              </tbody>
            </table>
          </section>

          <ApprovalBlock reportDate={ws.iep.reportDate || ws.meta.reportDate} />
        </div>
      </div>
    </div>
  );
}

function IEPRow({ area, paths, ws, updateIEP }) {
  return (
    <tr>
      <td className="td-area"><strong>{area}</strong></td>
      {paths.map((p) => (
        <td key={p}>
          <Editable
            value={getByPath(ws.iep, p)}
            onChange={(v) => updateIEP(p, v)}
            multiline
          />
        </td>
      ))}
    </tr>
  );
}

function getByPath(obj, path) {
  return path.split('.').reduce((acc, k) => (acc && acc[k] != null ? acc[k] : ''), obj);
}

// =====================================================================
// 4. INTERIM REPORT TAB
// =====================================================================
// 종결 사유 선택지 (중간보고서의 종결 모드에서 사용)
const CLOSING_REASONS = [
  '목표 달성으로 인한 종결',
  '학령기 전환 (취학)',
  '타 기관 이전',
  '보호자 요청',
  '기타',
];

function InterimTab({ ws, setWs, onArchive, showToast }) {
  const stageData = STAGE_DATA[ws.meta.stage];
  const isClosing = (ws.interim.reportType || 'interim') === 'closing';
  const reportLabel = isClosing ? '종결 보고서' : '중간 보고서';

  const updateInterim = (key, value) => {
    setWs((s) => ({ ...s, interim: { ...s.interim, [key]: value } }));
  };

  // 사전/사후 점수 비교 (영역별 합산)
  const compareData = useMemo(() => {
    if (!ws.pre || !ws.post) return null;
    const result = [];
    Object.entries(stageData).forEach(([key, domain]) => {
      let pre = 0, post = 0;
      domain.groups.forEach((g) =>
        g.items.forEach((it) => {
          if (typeof ws.pre.scores[it.id] === 'number') pre += ws.pre.scores[it.id];
          if (typeof ws.post.scores[it.id] === 'number') post += ws.post.scores[it.id];
        }),
      );
      result.push({
        domain: key,
        label: domain.label.replace(/\s*\(.*\)/, ''),
        pre,
        post,
        max: domain.maxScore,
        delta: post - pre,
      });
    });
    return result;
  }, [ws.pre, ws.post, stageData]);

  // 진단·활동기록·MR-SR 분석을 통합한 자동 채움
  const autoFillInterim = () => {
    const profile = STAGE_PROFILE[ws.meta.stage];
    const cName = ws.meta.childName || '';

    // 1) 현재 발달 수준 요약 - 진단 점수 + 단계 특징 + 사전/사후 변화 + 가족 우선순위 + 강점/과제
    let summary = `${nmEunNeun(cName)} ${profile.headline}(${profile.subtitle}) 수준에 해당한다. ` +
                  `이번 평가 기간 동안 SCERTS 세 영역(사회 의사소통, 정서 조절, 교류 지원)을 중심으로 중재를 진행하였다. `;
    if (compareData) {
      const totals = compareData.reduce((acc, d) => {
        acc.pre += d.pre; acc.post += d.post; acc.max += d.max;
        return acc;
      }, { pre: 0, post: 0, max: 0 });
      const delta = totals.post - totals.pre;
      const pct = totals.max ? Math.round((totals.post / totals.max) * 100) : 0;
      summary += `진단 총점은 사전 ${totals.pre}/${totals.max}점에서 사후 ${totals.post}/${totals.max}점(${pct}%)으로 ` +
                 `${delta > 0 ? `${delta}점 상승하였다` : delta < 0 ? `${Math.abs(delta)}점 하락하였다` : '동일하게 유지되었다'}. `;
      // 가장 진전이 큰 영역 한 가지 강조
      const topGains = [...compareData].filter((d) => d.delta > 0).sort((a, b) => b.delta - a.delta);
      if (topGains.length > 0) {
        summary += `특히 ${topGains[0].label} 영역에서 ${topGains[0].delta}점의 가장 큰 향상이 관찰되었다. `;
      }
    }
    summary += `이 단계의 핵심 발달 과제는 ${profile.features.slice(0, 2).join(', ')}이며, 해당 과제를 중심으로 지원하였다.`;
    // 가족 우선순위 인용
    const familyFocus = (ws.familyPriorities?.focusOne || '').trim();
    const familyHope = (ws.familyPriorities?.threeMonthHope || '').trim();
    if (familyFocus || familyHope) {
      summary += `\n\n가족 우선순위로는 `;
      if (familyFocus) summary += `"${familyFocus}"`;
      if (familyHope) summary += `${familyFocus ? '를' : ''} 중점 영역으로 두고, 3개월 내 "${familyHope}"를 단기 희망으로 공유하였다.`;
      else summary += `를 중심으로 지원하였다.`;
    }

    // 2) 영역별 진전 - 사전/사후 비교 + 영역 내 항목별 향상 (건조한 임상 문체)
    const domainSummary = {};
    if (compareData) {
      const preScores = ws.pre?.scores || {};
      const postScores2 = ws.post?.scores || {};
      compareData.forEach((d) => {
        // 이 영역에서 점수가 향상된 항목 수집
        const improvedItems = [];
        if (stageData[d.domain]) {
          stageData[d.domain].groups.forEach((g) =>
            g.items.forEach((it) => {
              const pre = preScores[it.id];
              const post = postScores2[it.id];
              if (typeof pre === 'number' && typeof post === 'number' && post > pre) {
                improvedItems.push(`[${it.id}] ${it.label}`);
              }
            }),
          );
        }
        let progress = `사전 ${d.pre}점에서 사후 ${d.post}점으로 ${d.delta > 0 ? `${d.delta}점 상승` : d.delta < 0 ? `${Math.abs(d.delta)}점 하락` : '변화 없음'}(만점 ${d.max}점). ` +
                       `${d.delta > 0 ? '향상이 확인되었다.' : d.delta < 0 ? '재평가가 필요하다.' : '수준이 유지되었다.'}`;
        if (improvedItems.length > 0) {
          progress += ` 향상이 관찰된 항목: ${improvedItems.slice(0, 3).join(', ')}${improvedItems.length > 3 ? ` 외 ${improvedItems.length - 3}개` : ''}.`;
        }
        domainSummary[d.domain] = { behavior: '', progress };
      });
    }

    // 3) 관찰 예시 - 활동 일지 I의 최근 회기에서 추출
    const logs = ws.activities?.logI || [];
    let observations = '';
    if (logs.length > 0) {
      observations = `회기별 활동 일지 ${logs.length}건 중 최근 회기의 주요 관찰 사례는 다음과 같다.\n\n`;
      const recentLogs = logs.slice(-3); // 최근 3회기
      recentLogs.forEach((log, i) => {
        observations += `▸ ${log.date || `회기 ${i + 1}`} - ${log.fields?.activity || '활동'}\n`;
        const allObs = [
          ...(log.goalsSocial || []).filter((g) => g?.observed),
          ...(log.goalsEmo || []).filter((g) => g?.observed),
        ];
        if (allObs.length > 0) {
          observations += allObs.slice(0, 2).map((g) => `  · ${g.observed} (${g.rating || '기록 중'})`).join('\n') + '\n';
        }
        if (log.notes) observations += `  메모: ${log.notes.slice(0, 100)}\n`;
        observations += '\n';
      });
    } else {
      observations = '활동 일지에 회기 기록을 추가하면 관찰 사례가 자동으로 인용됩니다.';
    }

    // 4) 향후 중재 방향 - MR/SR 패턴 분석에서 전략 가져오기
    const postScores = ws.post?.scores || ws.assessment.scores;
    let mrSum = 0, mrMax = 0, srSum = 0, srMax = 0;
    if (stageData.mutualReg) {
      stageData.mutualReg.groups.forEach((g) =>
        g.items.forEach((it) => {
          mrMax += 2;
          if (typeof postScores[it.id] === 'number') mrSum += postScores[it.id];
        }),
      );
    }
    if (stageData.selfReg) {
      stageData.selfReg.groups.forEach((g) =>
        g.items.forEach((it) => {
          srMax += 2;
          if (typeof postScores[it.id] === 'number') srSum += postScores[it.id];
        }),
      );
    }
    const mrP = mrMax ? mrSum / mrMax : 0;
    const srP = srMax ? srSum / srMax : 0;
    let pattern = 'balanced';
    if (mrP >= 0.5 && srP < 0.4) pattern = 'highMR_lowSR';
    else if (mrP < 0.4 && srP >= 0.5) pattern = 'lowMR_highSR';
    else if (mrP < 0.4 && srP < 0.4) pattern = 'lowMR_lowSR';
    const mrSrInfo = MR_SR_BRIDGE[pattern];

    let direction = `정서 조절 영역의 현재 프로파일은 상호조절 ${Math.round(mrP * 100)}%, 자기조절 ${Math.round(srP * 100)}%로 ` +
                    `${mrSrInfo.title}에 해당한다.\n\n` +
                    `${localizeText(mrSrInfo.interpretation, cName)}\n\n` +
                    `다음 기간에는 다음 전략을 중점적으로 적용한다.\n` +
                    mrSrInfo.strategies.map((s, i) => `${i + 1}. ${localizeText(s, cName)}`).join('\n');
    // IEP 주간 우선순위 목표 연결
    const selectedGoals = ws.iep?.selectedGoals || [];
    if (selectedGoals.length > 0) {
      direction += `\n\n또한 IEP에서 선정된 주간 우선순위 목표를 다음 기간에도 지속 적용한다:\n` +
                   selectedGoals.slice(0, 5).map((g, i) =>
                     `${i + 1}. [${g.id}] ${g.customGoal || g.label || g.goal || ''}`
                   ).join('\n');
    }
    // 파트너 교류 지원 목표 연결
    const partnerGoals = (ws.iep?.partnerGoals || []).filter((p) => {
      if (typeof p === 'object' && p?.id) return (p.customGoal || p.label || '').trim();
      return typeof p === 'string' && p.trim();
    });
    if (partnerGoals.length > 0) {
      direction += `\n\n파트너(치료사·부모) 교류 지원 측면에서는:\n` +
                   partnerGoals.slice(0, 3).map((p, i) => {
                     const txt = typeof p === 'object'
                       ? `[${p.id}] ${p.customGoal || p.label || ''}`
                       : p;
                     return `${i + 1}. ${txt}`;
                   }).join('\n');
    }

    // 빈 필드만 자동 채움 (사용자 입력 보존)
    const isEmpty = (v) => !v || (typeof v === 'string' && v.trim() === '');
    let filledCount = 0;
    let preservedCount = 0;
    if (isEmpty(ws.interim.summary)) { updateInterim('summary', summary); filledCount++; } else preservedCount++;
    if (Object.keys(ws.interim.domainSummary || {}).length === 0) { updateInterim('domainSummary', domainSummary); filledCount++; } else preservedCount++;
    if (isEmpty(ws.interim.observations)) { updateInterim('observations', observations); filledCount++; } else preservedCount++;
    if (isEmpty(ws.interim.direction)) { updateInterim('direction', direction); filledCount++; } else preservedCount++;

    // [종결 모드] 목표 달성도(IEP 끌어오기) + 향후 권고 자동 채움
    if (isClosing) {
      if ((ws.interim.goalAchievement || []).length === 0) {
        const goals = [];
        ['sc', 'er', 'ts'].forEach((k) => {
          const g = (ws.iep?.annualGoals?.[k] || '').trim();
          if (g) goals.push({ goal: g, status: '', note: '' });
        });
        (ws.iep?.selectedGoals || []).forEach((sg) => {
          const g = (sg.customGoal || sg.label || sg.goal || '').trim();
          if (g) goals.push({ goal: g, status: '', note: '' });
        });
        if (goals.length > 0) { updateInterim('goalAchievement', goals); filledCount++; }
      } else preservedCount++;
      if (isEmpty(ws.interim.recommendation)) {
        updateInterim('recommendation', '가정 및 다음 환경(학교/기관)에서의 일관된 지원을 위해 다음을 권고한다: ① 자발적 의사소통 기회 확대, ② 시각적 지원과 정서 조절 전략의 지속, ③ 새로운 환경 전이 시 점진적 적응 지원.');
        filledCount++;
      } else preservedCount++;
    }
    if (showToast) {
      const msg = preservedCount > 0
        ? `${filledCount}개 섹션 자동 채움 · ${preservedCount}개 기존 입력 보존`
        : `${filledCount}개 섹션을 자동으로 채웠습니다`;
      showToast(msg);
    }
  };

  return (
    <div className="tab-content">
      <StepBanner
        kind="auto"
        done={false}
        todo={
          (ws.activities?.logI || []).length === 0
            ? '⚠ 활동 기록(회기 일지)이 아직 없습니다. 먼저 "활동 기록" 탭에서 회기를 기록하면, 자동 채움 시 관찰 사례가 인용됩니다.'
            : `"📊 진단·활동기록으로 자동 채움" 버튼을 누르면 사전/사후 비교와 회기 일지 ${(ws.activities?.logI || []).length}건의 관찰 사례가 자동 인용됩니다.`
        }
        writer="therapist"
      />
      <div className="card no-break">
        <div className="iep-header">
          <h2 className="section-title">{reportLabel}</h2>
          <div className="iep-actions no-print">
            <button className="btn-ghost" onClick={autoFillInterim}>📊 진단·활동기록으로 자동 채움</button>
            <button className="btn-ghost" onClick={onArchive}>보관함에 저장</button>
            <button className="btn-primary" onClick={printReport}>인쇄 / PDF</button>
          </div>
        </div>

        {/* 보고서 유형 선택: 중간 점검 / 종결 */}
        <div className="report-type-toggle no-print">
          <span className="rtt-label">보고서 유형</span>
          <button
            className={`rtt-btn ${!isClosing ? 'active' : ''}`}
            onClick={() => updateInterim('reportType', 'interim')}
          >중간 점검</button>
          <button
            className={`rtt-btn ${isClosing ? 'active' : ''}`}
            onClick={() => updateInterim('reportType', 'closing')}
          >종결</button>
          <span className="rtt-hint">
            {isClosing
              ? '치료 종료 시점의 최종 정리입니다. 종결 사유·목표 달성도·향후 권고가 추가됩니다.'
              : '진행 중 점검용입니다. 마지막 점검을 종결로 전환하면 종결 보고서가 됩니다.'}
          </span>
        </div>

        <div id="printable-report" className="printable">
          <ReportHeader title={`SCERTS ${reportLabel}`} ws={ws}
            dateValue={ws.interim.reportDate}
            dateOnChange={(v) => updateInterim('reportDate', v)}
            extras={[
            { label: isClosing ? '치료 기간' : '보고 기간', editable: true, value: ws.interim.period,
              onChange: (v) => updateInterim('period', v) },
          ]} />

          {/* 단계별 발달 특징 박스 (자동) */}
          <StageProfileBox stage={ws.meta.stage} />

          {/* [종결 모드] 종결 사유 */}
          {isClosing && (
            <section className="report-section">
              <h3 className="report-h3">■ 종결 사유</h3>
              <div className="closing-reason-grid no-print">
                {CLOSING_REASONS.map((r) => (
                  <label key={r} className={`closing-reason-opt ${ws.interim.closingReason === r ? 'sel' : ''}`}>
                    <input type="radio" name="interimClosingReason" checked={ws.interim.closingReason === r} onChange={() => updateInterim('closingReason', r)} />
                    <span>{r}</span>
                  </label>
                ))}
              </div>
              <div className="closing-reason-print print-only">{ws.interim.closingReason || '—'}</div>
              <Editable value={ws.interim.closingReasonDetail} onChange={(v) => updateInterim('closingReasonDetail', v)} placeholder="종결 사유에 대한 구체적 설명 (선택)" multiline minLines={2} />
            </section>
          )}

          {/* 가족의 견해 및 우선순위 */}
          <FamilyPrioritiesReport ws={ws} />

          {/* 1. 현재 발달 수준 요약 */}
          <section className="report-section">
            <h3 className="report-h3">1. 현재 발달 수준 요약</h3>
            <Editable
              value={ws.interim.summary}
              onChange={(v) => updateInterim('summary', v)}
              placeholder="아동의 전반적 발달 수준, 강점, 우선 지원 영역에 대해 종합적으로 기술하세요."
              multiline
              minLines={5}
              examples={EXAMPLE_BANK.interimSummary}
            />
          </section>

          {/* 2. 영역별 진전 요약 */}
          <section className="report-section">
            <h3 className="report-h3">2. SCERTS 영역별 진전 요약</h3>
            <table className="report-table">
              <thead>
                <tr>
                  <th style={{ width: '20%' }}>영역</th>
                  <th style={{ width: '20%' }}>핵심 행동</th>
                  <th>진전 요약</th>
                </tr>
              </thead>
              <tbody>
                {Object.entries(stageData).map(([key, domain]) => (
                  <tr key={key}>
                    <td><strong>{domain.label}</strong></td>
                    <td>
                      <Editable
                        value={(ws.interim.domainSummary[key]?.behavior) || ''}
                        onChange={(v) => {
                          const cur = ws.interim.domainSummary[key] || {};
                          updateInterim('domainSummary', { ...ws.interim.domainSummary, [key]: { ...cur, behavior: v } });
                        }}
                        placeholder="예: 시선 공유, 요청"
                        multiline
                        examples={EXAMPLE_BANK.domainBehavior}
                      />
                    </td>
                    <td>
                      <Editable
                        value={(ws.interim.domainSummary[key]?.progress) || ''}
                        onChange={(v) => {
                          const cur = ws.interim.domainSummary[key] || {};
                          updateInterim('domainSummary', { ...ws.interim.domainSummary, [key]: { ...cur, progress: v } });
                        }}
                        placeholder="예: 요청 시 발화 출현 증가, 시선 유지 시간 향상"
                        multiline
                        examples={EXAMPLE_BANK.domainProgress}
                      />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </section>

          {/* 3. 사전/사후 비교 차트 */}
          <section className="report-section">
            <h3 className="report-h3">3. 사전/사후 점수 비교</h3>
            {!compareData && (
              <div className="empty-hint">
                사전 및 사후 진단을 먼저 저장해 주세요. (진단 탭 → "현재 점수를 사전/사후 진단으로 저장")
              </div>
            )}
            {compareData && (
              <>
                <ComparisonChart data={compareData} />
                <table className="compare-table">
                  <thead>
                    <tr>
                      <th>영역</th>
                      <th>사전</th>
                      <th>사후</th>
                      <th>변화</th>
                      <th>만점</th>
                    </tr>
                  </thead>
                  <tbody>
                    {compareData.map((d) => (
                      <tr key={d.domain}>
                        <td>{d.label}</td>
                        <td>{d.pre}</td>
                        <td>{d.post}</td>
                        <td className={d.delta > 0 ? 'delta-up' : d.delta < 0 ? 'delta-down' : ''}>
                          {d.delta > 0 ? `+${d.delta}` : d.delta}
                        </td>
                        <td>{d.max}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </>
            )}
          </section>

          {/* 사회-정서 성장 지표 (자동 인용) */}
          <SesIndicatorSummary
            values={ws.post?.ses || ws.assessment.ses || {}}
            title="사회-정서 성장 지표 (사후 기준)"
          />

          {/* 진단 관찰 정보 (자동 인용) */}
          <ObservationSummary ws={ws} />

          {/* 4. 관찰 예시 및 주요 변화 사례 */}
          <section className="report-section">
            <h3 className="report-h3">4. 관찰 예시 및 주요 변화 사례</h3>
            <Editable
              value={ws.interim.observations}
              onChange={(v) => updateInterim('observations', v)}
              placeholder="구체적인 관찰 사례를 시기별로 기술하세요."
              multiline
              minLines={4}
            />
          </section>

          {/* 5. 향후 중재 방향 (중간 모드에서만) */}
          {!isClosing && (
          <section className="report-section">
            <h3 className="report-h3">5. 향후 중재 방향 및 제언</h3>
            <Editable
              value={ws.interim.direction}
              onChange={(v) => updateInterim('direction', v)}
              placeholder="다음 분기 중점 목표 및 중재 방향을 기술하세요."
              multiline
              minLines={4}
              examples={EXAMPLE_BANK.interimDirection}
            />
          </section>
          )}

          {/* [종결 모드] 목표 달성도 */}
          {isClosing && (
          <section className="report-section">
            <h3 className="report-h3">5. 목표 달성도</h3>
            <table className="report-table closing-goal-table">
              <thead>
                <tr>
                  <th>목표</th>
                  <th style={{ width: '20%' }}>달성도</th>
                  <th style={{ width: '28%' }}>비고</th>
                  <th className="no-print" style={{ width: '40px' }}></th>
                </tr>
              </thead>
              <tbody>
                {(ws.interim.goalAchievement || []).length === 0 && (
                  <tr><td colSpan={4} className="closing-empty">자동 채움을 누르거나 아래 버튼으로 목표를 추가하세요.</td></tr>
                )}
                {(ws.interim.goalAchievement || []).map((g, i) => (
                  <tr key={i}>
                    <td><Editable value={g.goal} onChange={(v) => { const arr=[...ws.interim.goalAchievement]; arr[i]={...arr[i],goal:v}; updateInterim('goalAchievement',arr); }} placeholder="목표 내용" multiline minLines={1} /></td>
                    <td>
                      <select className="closing-status-sel" value={g.status} onChange={(e) => { const arr=[...ws.interim.goalAchievement]; arr[i]={...arr[i],status:e.target.value}; updateInterim('goalAchievement',arr); }}>
                        <option value="">선택</option>
                        <option value="달성">달성</option>
                        <option value="부분 달성">부분 달성</option>
                        <option value="미달성">미달성</option>
                      </select>
                      <span className="closing-status-print print-only">{g.status || '—'}</span>
                    </td>
                    <td><Editable value={g.note} onChange={(v) => { const arr=[...ws.interim.goalAchievement]; arr[i]={...arr[i],note:v}; updateInterim('goalAchievement',arr); }} placeholder="비고" multiline minLines={1} /></td>
                    <td className="no-print"><button className="closing-row-del" onClick={() => updateInterim('goalAchievement', ws.interim.goalAchievement.filter((_,idx)=>idx!==i))} title="삭제">×</button></td>
                  </tr>
                ))}
              </tbody>
            </table>
            <button className="btn-ghost btn-small no-print" onClick={() => updateInterim('goalAchievement', [...(ws.interim.goalAchievement||[]), {goal:'',status:'',note:''}])}>+ 목표 추가</button>
          </section>
          )}

          {/* [종결 모드] 향후 권고 */}
          {isClosing && (
          <section className="report-section">
            <h3 className="report-h3">6. 향후 권고</h3>
            <Editable
              value={ws.interim.recommendation}
              onChange={(v) => updateInterim('recommendation', v)}
              placeholder="다음 환경(가정/학교/기관)으로의 전이 지원 및 권고 사항을 기술하세요."
              multiline
              minLines={4}
              examples={EXAMPLE_BANK.interimDirection}
            />
          </section>
          )}

          {/* 보호자 협력 제안 */}
          <section className="report-section">
            <h3 className="report-h3">{isClosing ? '7' : '6'}. 보호자 협력 제안</h3>
            <ol className="suggestion-list">
              {ws.interim.familySuggestions.map((s, i) => (
                <li key={i}>
                  <Editable
                    value={s}
                    onChange={(v) => {
                      const arr = [...ws.interim.familySuggestions];
                      arr[i] = v;
                      updateInterim('familySuggestions', arr);
                    }}
                    multiline
                  />
                </li>
              ))}
            </ol>
          </section>

          <ApprovalBlock reportDate={ws.interim.reportDate || ws.meta.reportDate} />
        </div>
      </div>
    </div>
  );
}


// =====================================================================
// COMPARISON CHART (사전/사후 막대그래프 SVG)
// =====================================================================
function ComparisonChart({ data }) {
  const W = 720;
  const H = 320;
  const PAD = { top: 24, right: 24, bottom: 60, left: 48 };
  const innerW = W - PAD.left - PAD.right;
  const innerH = H - PAD.top - PAD.bottom;
  const maxVal = Math.max(...data.map((d) => Math.max(d.pre, d.post, d.max * 0.4)));
  const barW = innerW / data.length / 2.6;
  const groupW = innerW / data.length;

  return (
    <div className="chart-wrap">
      <svg viewBox={`0 0 ${W} ${H}`} className="comparison-chart" preserveAspectRatio="xMidYMid meet">
        {/* Y axis grid */}
        {Array.from({ length: 5 }).map((_, i) => {
          const v = Math.round((maxVal / 4) * i);
          const y = PAD.top + innerH - (v / maxVal) * innerH;
          return (
            <g key={i}>
              <line x1={PAD.left} y1={y} x2={W - PAD.right} y2={y} stroke="#e6e2d8" strokeDasharray="2,3" />
              <text x={PAD.left - 8} y={y + 4} textAnchor="end" className="chart-axis-text">{v}</text>
            </g>
          );
        })}
        {/* X axis */}
        <line x1={PAD.left} y1={H - PAD.bottom} x2={W - PAD.right} y2={H - PAD.bottom} stroke="#3d3527" />

        {/* Bars */}
        {data.map((d, i) => {
          const cx = PAD.left + groupW * i + groupW / 2;
          const preH = (d.pre / maxVal) * innerH;
          const postH = (d.post / maxVal) * innerH;
          const yPre = PAD.top + innerH - preH;
          const yPost = PAD.top + innerH - postH;
          return (
            <g key={d.domain}>
              <rect x={cx - barW - 3} y={yPre} width={barW} height={preH} className="bar-pre" />
              <rect x={cx + 3} y={yPost} width={barW} height={postH} className="bar-post" />
              <text x={cx - barW / 2 - 3} y={yPre - 4} textAnchor="middle" className="bar-value">{d.pre}</text>
              <text x={cx + barW / 2 + 3} y={yPost - 4} textAnchor="middle" className="bar-value">{d.post}</text>
              <text x={cx} y={H - PAD.bottom + 18} textAnchor="middle" className="bar-label">
                {d.label}
              </text>
              <text x={cx} y={H - PAD.bottom + 36} textAnchor="middle" className={`bar-delta ${d.delta > 0 ? 'up' : d.delta < 0 ? 'down' : ''}`}>
                {d.delta > 0 ? `▲ +${d.delta}` : d.delta < 0 ? `▼ ${d.delta}` : '−'}
              </text>
            </g>
          );
        })}

        {/* Legend */}
        <g transform={`translate(${W - PAD.right - 140}, ${PAD.top - 8})`}>
          <rect x={0} y={-10} width={12} height={12} className="bar-pre" />
          <text x={18} y={1} className="chart-legend-text">사전</text>
          <rect x={70} y={-10} width={12} height={12} className="bar-post" />
          <text x={88} y={1} className="chart-legend-text">사후</text>
        </g>
      </svg>
    </div>
  );
}

// =====================================================================
// 5. ARCHIVE TAB
// =====================================================================
function ArchiveTab({ archive, onLoad, onRemove }) {
  const [query, setQuery] = useState('');
  const [filterKind, setFilterKind] = useState('all');  // 'all' | 'iep' | 'interim'
  const [filterChild, setFilterChild] = useState('all');
  const [filterStage, setFilterStage] = useState('all');
  const [sortBy, setSortBy] = useState('newest');  // 'newest' | 'oldest' | 'name'

  // 보관함의 모든 아동 이름 추출 (필터용)
  const childNames = useMemo(() => {
    const set = new Set();
    archive.forEach((a) => {
      const n = a.childName || a.snapshot?.meta?.childName;
      if (n) set.add(n);
    });
    return Array.from(set).sort();
  }, [archive]);

  // 필터링·정렬
  const filtered = useMemo(() => {
    let list = [...archive];
    // 종류 필터
    if (filterKind !== 'all') list = list.filter((a) => a.kind === filterKind);
    // 아동 필터
    if (filterChild !== 'all') {
      list = list.filter((a) => (a.childName || a.snapshot?.meta?.childName) === filterChild);
    }
    // 단계 필터
    if (filterStage !== 'all') {
      list = list.filter((a) => a.snapshot?.meta?.stage === filterStage);
    }
    // 검색어 (아동명, 단계, 날짜)
    if (query.trim()) {
      const q = query.trim().toLowerCase();
      list = list.filter((a) => {
        const name = (a.childName || a.snapshot?.meta?.childName || '').toLowerCase();
        const stage = STAGE_LABELS[a.snapshot?.meta?.stage] || '';
        const date = new Date(a.savedAt).toLocaleDateString('ko-KR');
        const kind = a.kind === 'iep' ? 'iep 개별화' : '중간보고서';
        return name.includes(q) || stage.toLowerCase().includes(q) || date.includes(q) || kind.includes(q);
      });
    }
    // 정렬
    if (sortBy === 'newest') list.sort((a, b) => b.savedAt.localeCompare(a.savedAt));
    else if (sortBy === 'oldest') list.sort((a, b) => a.savedAt.localeCompare(b.savedAt));
    else if (sortBy === 'name') list.sort((a, b) => {
      const na = a.childName || a.snapshot?.meta?.childName || '';
      const nb = b.childName || b.snapshot?.meta?.childName || '';
      return na.localeCompare(nb);
    });
    return list;
  }, [archive, query, filterKind, filterChild, filterStage, sortBy]);

  const clearFilters = async () => {
    setQuery(''); setFilterKind('all'); setFilterChild('all'); setFilterStage('all'); setSortBy('newest');
  };
  const hasActiveFilter = query || filterKind !== 'all' || filterChild !== 'all' || filterStage !== 'all';

  return (
    <div className="tab-content">
      <div className="card">
        <h2 className="section-title">보관함</h2>
        <p className="hint">저장된 IEP와 중간보고서를 불러올 수 있습니다. 총 {archive.length}건 중 {filtered.length}건 표시.</p>

        {archive.length === 0 && (
          <div className="empty-hint">아직 저장된 보고서가 없습니다.</div>
        )}

        {archive.length > 0 && (
          <div className="archive-filter-bar no-print">
            <div className="archive-search">
              <span className="archive-search-icon">🔍</span>
              <input
                type="text"
                className="archive-search-input"
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                placeholder="아동명·단계·날짜로 검색"
              />
              {query && <button className="archive-search-clear" onClick={() => setQuery('')}>×</button>}
            </div>
            <div className="archive-filter-group">
              <select className="archive-filter-select" value={filterKind} onChange={(e) => setFilterKind(e.target.value)}>
                <option value="all">전체 종류</option>
                <option value="iep">IEP</option>
                <option value="interim">중간보고서</option>
              </select>
              <select className="archive-filter-select" value={filterChild} onChange={(e) => setFilterChild(e.target.value)}>
                <option value="all">전체 아동</option>
                {childNames.map((n) => <option key={n} value={n}>{n}</option>)}
              </select>
              <select className="archive-filter-select" value={filterStage} onChange={(e) => setFilterStage(e.target.value)}>
                <option value="all">전체 단계</option>
                <option value="social">사회적 파트너</option>
                <option value="language">언어 파트너</option>
                <option value="conversation">대화 파트너</option>
              </select>
              <select className="archive-filter-select" value={sortBy} onChange={(e) => setSortBy(e.target.value)}>
                <option value="newest">최신순</option>
                <option value="oldest">오래된순</option>
                <option value="name">이름순</option>
              </select>
              {hasActiveFilter && (
                <button className="btn-ghost btn-small" onClick={clearFilters}>필터 초기화</button>
              )}
            </div>
          </div>
        )}

        {archive.length > 0 && filtered.length === 0 && (
          <div className="empty-hint">검색 조건에 맞는 항목이 없습니다.</div>
        )}

        <ul className="archive-list">
          {filtered.map((a) => (
            <li key={a.id} className="archive-item">
              <div className="archive-meta">
                <div className="archive-name">
                  <span className={`archive-tag tag-${a.kind}`}>
                    {a.kind === 'iep' ? 'IEP' : '중간보고서'}
                  </span>
                  <strong>{a.childName || a.snapshot.meta.childName || '이름 없음'}</strong>
                  <span className="archive-stage">{STAGE_LABELS[a.snapshot.meta.stage]}</span>
                </div>
                <div className="archive-date">
                  {new Date(a.savedAt).toLocaleString('ko-KR')}
                </div>
              </div>
              <div className="archive-actions">
                <button className="btn-ghost" onClick={() => onLoad(a.snapshot)}>불러오기</button>
                <button className="btn-danger" onClick={async () => {
                  if (await appConfirm('이 항목을 삭제하시겠습니까?')) onRemove(a.id);
                }}>삭제</button>
              </div>
            </li>
          ))}
        </ul>
      </div>
    </div>
  );
}

// =====================================================================
// 공통: 보고서 헤더 / 승인서
// =====================================================================
function ReportHeader({ title, ws, extras, dateValue, dateOnChange }) {
  // 보고서별 작성일: dateValue가 주어지면 그걸 사용(편집 가능), 없으면 홈 작성일 표시
  const effectiveDate = (dateValue !== undefined && dateValue !== null && dateValue !== '')
    ? dateValue : ws.meta.reportDate;
  return (
    <div className="report-header">
      <div className="report-brand">
        <div className="report-mark">SCERTS</div>
        <div className="report-mark-sub">검단ABA언어행동연구소</div>
      </div>
      <h1 className="report-title">{title}</h1>
      <table className="report-meta">
        <tbody>
          <tr>
            <th>아 동 명</th><td>{ws.meta.childName}</td>
            <th>생 년 월 일</th><td>{ws.meta.birthDate}</td>
          </tr>
          <tr>
            <th>소 속 반</th><td>{ws.meta.className}</td>
            <th>치 료 사</th><td>{ws.meta.therapist}</td>
          </tr>
          <tr>
            <th>접근 방식</th><td>발달 중심 + 가족, 학교 기반 협력적 접근</td>
            <th>단 계</th><td>{STAGE_LABELS[ws.meta.stage]}</td>
          </tr>
          <tr>
            <th>수업 시작일</th><td>{ws.meta.startDate}</td>
            <th>작성일</th>
            <td>
              {dateOnChange ? (
                <input type="date" className="report-date-input no-print"
                  value={effectiveDate || ''} onChange={(e) => dateOnChange(e.target.value)} />
              ) : null}
              <span className={dateOnChange ? 'print-only' : ''}>{effectiveDate}</span>
            </td>
          </tr>
          {extras && extras.map((ex, i) => (
            <tr key={i}>
              <th>{ex.label}</th>
              <td colSpan={3}>
                {ex.editable ? (
                  <Editable value={ex.value} onChange={ex.onChange} placeholder={ex.label} />
                ) : ex.value}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

// =====================================================================
// 외부(부모) 작성 페이지 — 로그인 없이 링크(#/fill/{token})로 접속
//   기존 buildParentQuestionnaireHTML 의 collect() 와 동일한 형식으로
//   답변을 만들어 shared_store 에 제출한다. (자동 채움 호환)
// =====================================================================
function ExternalFillPage({ token }) {
  const info = decodeScertsFillToken(token);
  const stage = info?.sc;
  const interview = stage ? INTERVIEWS[stage] : null;

  // 작성 중 자동 임시저장 키 (케이스별로 구분)
  const draftKey = info?.cid ? `scerts-fill-draft::${info.cid}` : null;

  // 초기값: 임시저장된 내용이 있으면 복원
  const [answers, setAnswers] = useState(() => {
    if (!draftKey) return {};
    try {
      const raw = localStorage.getItem(draftKey);
      if (raw) { const d = JSON.parse(raw); return d.answers || {}; }
    } catch (e) {}
    return {};
  });
  const [writer, setWriter] = useState(() => {
    if (!draftKey) return '';
    try {
      const raw = localStorage.getItem(draftKey);
      if (raw) { const d = JSON.parse(raw); return d.writer || ''; }
    } catch (e) {}
    return '';
  });
  const [state, setState] = useState(() => {
    // 이 폰에서 이미 제출했으면 done 화면으로 시작
    if (info?.cid) {
      try { if (localStorage.getItem(`scerts-fill-done::${info.cid}`)) return 'done'; } catch (e) {}
    }
    return 'idle';
  }); // idle | saving | done | error
  const [errMsg, setErrMsg] = useState('');
  const [restored, setRestored] = useState(() => {
    // 복원된 내용이 있었는지 (안내 배너용)
    if (!draftKey) return false;
    try { const raw = localStorage.getItem(draftKey); if (raw) { const d = JSON.parse(raw); return !!(d && (Object.keys(d.answers || {}).length || d.writer)); } } catch (e) {}
    return false;
  });

  // 값이 바뀔 때마다 자동 임시저장 (제출 완료 전까지)
  useEffect(() => {
    if (!draftKey || state === 'done') return;
    try { localStorage.setItem(draftKey, JSON.stringify({ answers, writer, savedAt: Date.now() })); } catch (e) {}
  }, [answers, writer, draftKey, state]);

  if (!info || !interview) {
    return (
      <div style={extStyles.wrap}>
        <div style={extStyles.head}>
          <div style={{ fontSize: 20, fontWeight: 700 }}>SCERTS 질문지</div>
        </div>
        <div style={{ ...extStyles.card, textAlign: 'center' }}>
          <div style={{ fontWeight: 700, fontSize: 16, marginBottom: 6 }}>링크가 올바르지 않아요</div>
          <div style={{ fontSize: 13, color: '#7a6f55', lineHeight: 1.6 }}>
            링크가 손상되었거나 만료되었을 수 있어요. 보내주신 선생님께 새 링크를 요청해 주세요.
          </div>
        </div>
      </div>
    );
  }

  const stageLabel = stage === 'social' ? '사회적 파트너 단계'
    : stage === 'language' ? '언어 파트너 단계' : '대화 파트너 단계';

  // ── 답변 갱신 헬퍼 (기존 collect() 형식과 동일하게) ──
  const setText = (id, val) => setAnswers((a) => ({ ...a, [id]: val }));
  const toggleCheck = (id, opt, on) => setAnswers((a) => {
    const cur = a[id] && typeof a[id] === 'object' ? { checked: { ...(a[id].checked || {}) }, texts: { ...(a[id].texts || {}) } } : { checked: {}, texts: {} };
    if (on) cur.checked[opt] = true; else delete cur.checked[opt];
    return { ...a, [id]: cur };
  });
  const setExtraText = (id, wtId, val) => setAnswers((a) => {
    const cur = a[id] && typeof a[id] === 'object' ? { checked: { ...(a[id].checked || {}) }, texts: { ...(a[id].texts || {}) } } : { checked: {}, texts: {} };
    if (val) cur.texts[wtId] = val; else delete cur.texts[wtId];
    return { ...a, [id]: cur };
  });
  const setFreq = (id, row, col) => setAnswers((a) => {
    const cur = a[id] && typeof a[id] === 'object' ? { ...a[id] } : {};
    cur[row] = col;
    return { ...a, [id]: cur };
  });
  // 특수 타입(emotionsRows/recoveryPair/scale02List) 공용 setter: 객체 병합
  const setObjField = (id, field, val) => setAnswers((a) => {
    const cur = a[id] && typeof a[id] === 'object' ? { ...a[id] } : {};
    cur[field] = val;
    return { ...a, [id]: cur };
  });

  // 질문 id → 타입 조회용 맵 (buildSubmission에서 타입 기반 정리)
  const qTypeById = {};
  interview.sections.forEach((sec) => sec.questions.forEach((q) => { qTypeById[q.id] = q.type; }));

  // ── 제출 시 정리: 타입 기반으로 빈 값 제거 ──
  const buildSubmission = () => {
    const out = {};
    if (writer.trim()) out.__writer = writer.trim();
    Object.keys(answers).forEach((id) => {
      const v = answers[id];
      if (v == null) return;
      const type = qTypeById[id];

      if (type === 'checklist') {
        const checked = (v && v.checked) || {};
        const texts = (v && v.texts) || {};
        const hasChecked = Object.keys(checked).some((k) => checked[k]);
        const hasText = Object.keys(texts).some((k) => texts[k] && String(texts[k]).trim());
        if (hasChecked || hasText) {
          const obj = {};
          if (hasChecked) { obj.checked = {}; Object.keys(checked).forEach((k) => { if (checked[k]) obj.checked[k] = true; }); }
          if (hasText) { obj.texts = {}; Object.keys(texts).forEach((k) => { if (texts[k] && String(texts[k]).trim()) obj.texts[k] = texts[k]; }); }
          out[id] = obj;
        }
      } else if (type === 'frequency') {
        if (v && typeof v === 'object') {
          const rows = Object.keys(v).filter((k) => v[k] != null && v[k] !== '');
          if (rows.length) { out[id] = {}; rows.forEach((k) => { out[id][k] = v[k]; }); }
        }
      } else if (type === 'emotionsRows' || type === 'recoveryPair' || type === 'scale02List') {
        // 값이 있는 필드만 남김 (선생님 렌더 형식과 동일한 객체 구조 유지)
        if (v && typeof v === 'object') {
          const obj = {};
          Object.keys(v).forEach((k) => {
            const val = v[k];
            if (val === 0 || (val != null && String(val).trim() !== '')) obj[k] = val;
          });
          if (Object.keys(obj).length) out[id] = obj;
        }
      } else {
        // text 및 기타 → 문자열
        if (typeof v === 'string' && v.trim()) out[id] = v;
      }
    });
    return out;
  };

  const submit = async () => {
    setState('saving'); setErrMsg('');
    try {
      const submission = {
        stage,
        childName: info.cn || '',
        writer: writer.trim() || '',
        answers: buildSubmission(),
      };
      // 이 폰의 고정 제출 id (아동별) — 같은 폰에서 다시 내면 이전 제출을 덮어씀
      let deviceSid = '';
      try {
        const sidKey = `scerts-fill-sid::${info.cid}`;
        deviceSid = localStorage.getItem(sidKey) || '';
        if (!deviceSid) {
          deviceSid = `dev_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
          localStorage.setItem(sidKey, deviceSid);
        }
      } catch (e) { deviceSid = ''; }  // localStorage 막힌 환경이면 새 제출로 처리
      const r = await saveScertsSubmission(info.cid, submission, deviceSid);
      if (!r) { setState('error'); setErrMsg('제출에 실패했어요. 인터넷 연결을 확인하고 다시 시도해 주세요.'); return; }
      // 제출 성공 → 이 폰에 "제출 완료" 기록
      // (임시저장은 남겨둠 → "다시 작성하기" 시 이전 답변이 복원되도록)
      try { if (info.cid) localStorage.setItem(`scerts-fill-done::${info.cid}`, String(Date.now())); } catch (e) {}
      setState('done');
      window.scrollTo({ top: 0, behavior: 'smooth' });
    } catch (e) {
      setState('error'); setErrMsg('제출에 실패했어요. 인터넷 연결을 확인하고 다시 시도해 주세요.');
    }
  };

  if (state === 'done') {
    return (
      <div style={extStyles.wrap}>
        <div style={extStyles.head}>
          <div style={{ fontSize: 20, fontWeight: 700 }}>SCERTS 질문지</div>
          <div style={{ fontSize: 13, opacity: 0.85, marginTop: 4 }}>{stageLabel}{info.cn ? ' · ' + info.cn : ''}</div>
        </div>
        <div style={{ ...extStyles.card, textAlign: 'center', background: '#eef6ef', border: '1px solid #bcdcc6' }}>
          <div style={{ fontSize: 40, marginBottom: 8 }}>✅</div>
          <div style={{ fontWeight: 700, fontSize: 17, color: '#2d7a4f', marginBottom: 8 }}>제출이 완료되었어요!</div>
          <div style={{ fontSize: 13.5, color: '#3a5a44', lineHeight: 1.6 }}>
            작성해 주셔서 감사합니다. 선생님께 자동으로 전달되었어요.<br />이 창은 닫으셔도 됩니다.
          </div>
        </div>
        <div style={{ textAlign: 'center' }}>
          <button
            onClick={() => {
              try { if (info.cid) localStorage.removeItem(`scerts-fill-done::${info.cid}`); } catch (e) {}
              setState('idle');
              window.scrollTo({ top: 0, behavior: 'smooth' });
            }}
            style={{ background: 'none', border: '1px solid #bcdcc6', color: '#2d7a4f', borderRadius: 9, padding: '10px 20px', fontSize: 13.5, fontFamily: 'inherit', cursor: 'pointer' }}
          >
            내용을 추가·수정하려면 다시 작성하기
          </button>
          <div style={{ fontSize: 12, color: '#8a7f65', marginTop: 8 }}>다시 제출하면 새 답변으로 한 번 더 전달됩니다.</div>
        </div>
      </div>
    );
  }

  return (
    <div style={extStyles.wrap}>
      <div style={extStyles.head}>
        <div style={{ fontSize: 20, fontWeight: 700 }}>SCERTS 질문지</div>
        <div style={{ fontSize: 13, opacity: 0.85, marginTop: 4 }}>{stageLabel}{info.cn ? ' · ' + info.cn : ''}</div>
      </div>

      <div style={extStyles.intro}>{interview.intro}</div>

      {restored && (
        <div style={{ background: '#eef6ef', border: '1px solid #bcdcc6', borderRadius: 10, padding: '11px 14px', marginBottom: 16, fontSize: 13, color: '#2d7a4f', display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 10 }}>
          <span>✅ 이전에 작성하던 내용을 불러왔어요. 이어서 작성하세요.</span>
          <button onClick={() => setRestored(false)} style={{ background: 'none', border: 'none', color: '#2d7a4f', fontSize: 18, cursor: 'pointer', lineHeight: 1 }}>×</button>
        </div>
      )}

      <div style={extStyles.card}>
        <label style={{ fontSize: 13, fontWeight: 600, display: 'block', marginBottom: 6 }}>작성자 (성함) / 아동과의 관계</label>
        <input
          type="text" value={writer} onChange={(e) => setWriter(e.target.value)}
          placeholder="예: 김영희 / 어머니" style={extStyles.input}
        />
      </div>

      {interview.sections.map((sec) => (
        <div key={sec.key}>
          <div style={extStyles.secTitle}>{sec.title}</div>
          {sec.questions.map((q, qi) => (
            <ExtQuestion
              key={q.id} q={q} idx={qi + 1} value={answers[q.id]}
              onText={setText} onToggle={toggleCheck} onExtra={setExtraText} onFreq={setFreq} onObj={setObjField}
            />
          ))}
        </div>
      ))}

      {state === 'error' && (
        <div style={{ ...extStyles.card, background: '#fdecec', border: '1px solid #f2b8b8', color: '#b23', fontSize: 13 }}>{errMsg}</div>
      )}

      <div style={{ padding: '20px 0 40px', textAlign: 'center' }}>
        <button onClick={submit} disabled={state === 'saving'} style={{ ...extStyles.btn, opacity: state === 'saving' ? 0.6 : 1 }}>
          {state === 'saving' ? '제출 중...' : '✅ 작성 완료 — 제출하기'}
        </button>
        <div style={{ fontSize: 12, color: '#8a7f65', marginTop: 10 }}>제출하면 선생님께 자동으로 전달됩니다.</div>
      </div>
    </div>
  );
}

// 외부 작성 페이지의 개별 질문 렌더러
function ExtQuestion({ q, idx, value, onText, onToggle, onExtra, onFreq, onObj }) {
  const freqCols = ['거의/전혀', '가끔', '자주'];
  const scaleLabels = ['거의/전혀', '가끔', '대부분'];
  return (
    <div style={extStyles.q}>
      <div style={extStyles.qText}><span style={extStyles.qIdx}>{idx}.</span> {q.q}</div>
      {q.type === 'checklist' ? (
        <div>
          {(q.options || []).map((opt) => {
            const on = !!(value && value.checked && value.checked[opt]);
            return (
              <label key={opt} style={extStyles.opt}>
                <input type="checkbox" checked={on} onChange={(e) => onToggle(q.id, opt, e.target.checked)} style={{ marginTop: 4 }} />
                <span>{opt}</span>
              </label>
            );
          })}
          {(q.withText || []).map((wt) => {
            const on = !!(value && value.checked && value.checked[wt.id]);
            const txt = (value && value.texts && value.texts[wt.id]) || '';
            return (
              <div key={wt.id}>
                <label style={extStyles.opt}>
                  <input type="checkbox" checked={on} onChange={(e) => onToggle(q.id, wt.id, e.target.checked)} style={{ marginTop: 4 }} />
                  <span>{wt.label}</span>
                </label>
                <input type="text" value={txt} placeholder="구체적인 예" onChange={(e) => onExtra(q.id, wt.id, e.target.value)} style={extStyles.extra} />
              </div>
            );
          })}
        </div>
      ) : q.type === 'frequency' ? (
        <table style={extStyles.freq}>
          <thead>
            <tr>
              <th style={extStyles.freqCell}></th>
              {freqCols.map((c) => <th key={c} style={extStyles.freqCell}>{c}</th>)}
            </tr>
          </thead>
          <tbody>
            {(q.partners || []).map((p, ri) => (
              <tr key={ri}>
                <td style={{ ...extStyles.freqCell, textAlign: 'left' }}>{p}</td>
                {freqCols.map((c, ci) => (
                  <td key={ci} style={extStyles.freqCell}>
                    <input type="radio" name={`${q.id}_${ri}`} checked={!!(value && value[ri] === ci)} onChange={() => onFreq(q.id, ri, ci)} />
                  </td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      ) : q.type === 'emotionsRows' ? (
        // 감정별로 나눠서 작성
        <div>
          {(q.emotions || []).map((emo) => (
            <div key={emo} style={{ marginBottom: 8 }}>
              <div style={{ fontSize: 13.5, fontWeight: 600, marginBottom: 4 }}>{emo}</div>
              <textarea
                value={(value && value[emo]) || ''}
                placeholder="어떻게 표현하는지 적어주세요"
                onChange={(e) => onObj(q.id, emo, e.target.value)}
                style={{ ...extStyles.textarea, minHeight: 44 }}
              />
            </div>
          ))}
        </div>
      ) : q.type === 'recoveryPair' ? (
        // 스스로 회복 / 파트너 도움 두 칸으로 분리
        <div>
          <div style={{ marginBottom: 8 }}>
            <div style={{ fontSize: 13.5, fontWeight: 600, marginBottom: 4 }}>• {q.self}</div>
            <textarea
              value={(value && value.self) || ''}
              placeholder="여기에 답변을 입력하세요"
              onChange={(e) => onObj(q.id, 'self', e.target.value)}
              style={extStyles.textarea}
            />
          </div>
          <div>
            <div style={{ fontSize: 13.5, fontWeight: 600, marginBottom: 4 }}>• {q.partner}</div>
            <textarea
              value={(value && value.partner) || ''}
              placeholder="여기에 답변을 입력하세요"
              onChange={(e) => onObj(q.id, 'partner', e.target.value)}
              style={extStyles.textarea}
            />
          </div>
        </div>
      ) : q.type === 'scale02List' ? (
        // 항목별 0/1/2 척도 (부모가 이해하기 쉽게 라벨 표시)
        <table style={extStyles.freq}>
          <thead>
            <tr>
              <th style={extStyles.freqCell}></th>
              {scaleLabels.map((c, i) => <th key={i} style={extStyles.freqCell}>{c}<br /><span style={{ fontSize: 11, color: '#8a7f65' }}>({i})</span></th>)}
            </tr>
          </thead>
          <tbody>
            {(q.items || []).map((item, ri) => (
              <tr key={ri}>
                <td style={{ ...extStyles.freqCell, textAlign: 'left' }}>{item}</td>
                {[0, 1, 2].map((n) => (
                  <td key={n} style={extStyles.freqCell}>
                    <input type="radio" name={`${q.id}_${ri}`} checked={!!(value && value[item] === n)} onChange={() => onObj(q.id, item, n)} />
                  </td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      ) : (
        // text 및 기타 → 자유 서술
        <textarea
          value={typeof value === 'string' ? value : ''}
          placeholder="여기에 답변을 입력하세요"
          onChange={(e) => onText(q.id, e.target.value)}
          style={extStyles.textarea}
        />
      )}
    </div>
  );
}

const extStyles = {
  wrap: { maxWidth: 760, margin: '0 auto', padding: '20px 16px 40px', fontFamily: "'IBM Plex Sans KR', sans-serif", color: '#2a2419', lineHeight: 1.6, minHeight: '100vh', background: '#f4efe4' },
  head: { background: '#2d4a3e', color: '#f4efe4', padding: '22px 20px', borderRadius: 14, marginBottom: 18 },
  intro: { background: '#fff7e6', border: '1px solid #eecf9e', borderRadius: 10, padding: '14px 16px', fontSize: 13.5, color: '#5a4a20', marginBottom: 20 },
  card: { background: '#fff', border: '1px solid #e4dcc8', borderRadius: 10, padding: '14px 16px', marginBottom: 18 },
  secTitle: { fontSize: 17, fontWeight: 700, color: '#2d4a3e', margin: '26px 0 12px', paddingBottom: 6, borderBottom: '2px solid #c19a3a' },
  q: { background: '#fff', border: '1px solid #e4dcc8', borderRadius: 10, padding: '14px 16px', marginBottom: 12 },
  qText: { fontSize: 14.5, fontWeight: 500, marginBottom: 10 },
  qIdx: { color: '#c19a3a', fontWeight: 700, marginRight: 4 },
  textarea: { width: '100%', minHeight: 64, padding: '9px 11px', border: '1px solid #d9d1bd', borderRadius: 8, fontFamily: 'inherit', fontSize: 14, resize: 'vertical', boxSizing: 'border-box' },
  opt: { display: 'flex', alignItems: 'flex-start', gap: 8, padding: '5px 0', fontSize: 14 },
  extra: { width: '100%', marginTop: 4, padding: '7px 10px', border: '1px solid #e0d8c4', borderRadius: 7, fontSize: 13, fontFamily: 'inherit', boxSizing: 'border-box' },
  freq: { width: '100%', borderCollapse: 'collapse', marginTop: 6, fontSize: 13 },
  freqCell: { border: '1px solid #e0d8c4', padding: 7, textAlign: 'center' },
  input: { width: '100%', padding: '9px 11px', border: '1px solid #d9d1bd', borderRadius: 8, fontSize: 14, fontFamily: 'inherit', boxSizing: 'border-box' },
  btn: { background: '#2d4a3e', color: '#fff', border: 'none', borderRadius: 10, padding: '14px 30px', fontSize: 15, fontWeight: 700, fontFamily: 'inherit', cursor: 'pointer' },
};

// =====================================================================
// INTERVIEW TAB — 보호자/교사 질문지 (단계별)
// =====================================================================
function InterviewTab({ ws, setWs, showToast }) {
  const interview = INTERVIEWS[ws.meta.stage];
  const [activeSection, setActiveSection] = useState(interview.sections[0].key);

  // ── 부모용 "링크" 방식 ──
  const [fillLink, setFillLink] = useState('');   // 생성된 링크
  const [subs, setSubs] = useState([]);           // 받은 부모 제출 목록
  const [subsLoading, setSubsLoading] = useState(false);

  // 링크 생성: 케이스 식별 정보를 토큰에 담아 #/fill/{token} URL 만들기
  const makeParentLink = () => {
    const childId = ws._childId;
    if (!childId) { showToast && showToast('먼저 아동을 저장한 뒤 링크를 만들 수 있습니다'); return; }
    const token = encodeScertsFillToken({ cid: childId, cn: ws.meta.childName || '', sc: ws.meta.stage });
    if (!token) { showToast && showToast('링크 생성에 실패했습니다'); return; }
    const base = (typeof window !== 'undefined')
      ? window.location.origin + window.location.pathname
      : '';
    const link = `${base}#/fill/${token}`;
    setFillLink(link);
    // 링크 발송 기록 (workspace에 저장 → scerts_data에 자동 반영)
    setWs((s) => ({ ...s, interview: { ...s.interview, linkSentAt: new Date().toISOString() } }));
    try { navigator.clipboard.writeText(link); showToast && showToast('링크를 복사했습니다. 카톡으로 부모님께 보내세요'); }
    catch (e) { showToast && showToast('링크가 생성되었습니다'); }
  };

  // 받은 제출 조회
  const loadSubmissions = async () => {
    const childId = ws._childId;
    if (!childId) return;
    setSubsLoading(true);
    const rows = await listScertsSubmissions(childId);
    setSubs(rows);
    setSubsLoading(false);
  };
  useEffect(() => { loadSubmissions(); /* eslint-disable-next-line react-hooks/exhaustive-deps */ }, [ws._childId]);

  // 창 포커스가 돌아오거나 탭이 다시 보일 때 자동 새로고침
  // (부모가 방금 제출한 내용을 선생님이 놓치지 않도록)
  useEffect(() => {
    const onFocus = () => { if (document.visibilityState !== 'hidden') loadSubmissions(); };
    window.addEventListener('focus', onFocus);
    document.addEventListener('visibilitychange', onFocus);
    return () => {
      window.removeEventListener('focus', onFocus);
      document.removeEventListener('visibilitychange', onFocus);
    };
    /* eslint-disable-next-line react-hooks/exhaustive-deps */
  }, [ws._childId]);

  // 받은 제출을 질문지에 자동 채움 (기존 붙여넣기 로직과 동일 방식)
  const applySubmission = async (sub) => {
    const incoming = sub.answers || {};
    const writer = sub.writer || incoming.__writer || '';
    setWs((s) => {
      const merged = { ...s.interview.answers };
      Object.keys(incoming).forEach((k) => { if (k !== '__writer') merged[k] = incoming[k]; });
      const newMeta = { ...s.interview.meta };
      if (writer && !newMeta.reporter) {
        const parts = writer.split('/').map((x) => x.trim());
        newMeta.reporter = parts[0] || writer;
        if (parts[1] && !newMeta.relation) newMeta.relation = parts[1];
      }
      return { ...s, interview: { ...s.interview, answers: merged, meta: newMeta } };
    });
    const cnt = Object.keys(incoming).filter((k) => k !== '__writer').length;
    showToast && showToast(`부모 답안 ${cnt}개 문항을 불러왔습니다`);
  };

  // 받은 제출 삭제
  const removeSubmission = async (sub) => {
    const ok = await appConfirm('이 제출을 삭제할까요? (되돌릴 수 없습니다)');
    if (!ok) return;
    await deleteScertsSubmission(ws._childId, sub.sid);
    setSubs((prev) => prev.filter((x) => x.sid !== sub.sid));
    showToast && showToast('제출을 삭제했습니다');
  };

  // 부모용 질문지 HTML 다운로드 (카톡 전송용)
  const exportParentForm = () => {
    const html = buildParentQuestionnaireHTML(ws.meta.stage, ws.meta.childName, ws.interview.answers);
    if (!html) { showToast && showToast('질문지를 만들 수 없습니다'); return; }
    try {
      const blob = new Blob([html], { type: 'text/html;charset=utf-8' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      const nm = (ws.meta.childName || '아동').replace(/[\\/:*?"<>|]/g, '_');
      a.href = url;
      a.download = `SCERTS_질문지_${nm}.html`;
      document.body.appendChild(a);
      a.click();
      setTimeout(() => { document.body.removeChild(a); URL.revokeObjectURL(url); }, 1000);
      showToast && showToast('부모용 질문지를 다운로드했습니다. 카톡으로 보내주세요');
    } catch (e) {
      showToast && showToast('다운로드에 실패했습니다');
    }
  };

  // 부모 답안 코드 붙여넣기 → 질문지 자동 채움
  const importParentAnswers = async () => {
    const code = await appPrompt('부모님이 보내준 답안 코드를 붙여넣으세요\n(SCERTS:: 로 시작하는 긴 텍스트)', '');
    if (!code) return;
    const decoded = decodeParentAnswers(code);
    if (!decoded) {
      await appAlert('답안 코드를 인식하지 못했습니다.\n부모님이 보낸 "SCERTS::"로 시작하는 전체 텍스트를 정확히 붙여넣었는지 확인해 주세요.');
      return;
    }
    if (decoded.stage && decoded.stage !== ws.meta.stage) {
      const ok = await appConfirm(`이 답안은 다른 단계(${STAGE_LABELS[decoded.stage] || decoded.stage})의 질문지입니다.\n현재 단계와 다르지만 그래도 불러올까요?`);
      if (!ok) return;
    }
    const incoming = decoded.answers || {};
    const writer = incoming.__writer || '';
    setWs((s) => {
      const merged = { ...s.interview.answers };
      Object.keys(incoming).forEach((k) => { if (k !== '__writer') merged[k] = incoming[k]; });
      const newMeta = { ...s.interview.meta };
      if (writer && !newMeta.reporter) {
        // "이름 / 관계" 형태면 분리 시도
        const parts = writer.split('/').map((x) => x.trim());
        newMeta.reporter = parts[0] || writer;
        if (parts[1] && !newMeta.relation) newMeta.relation = parts[1];
      }
      return { ...s, interview: { ...s.interview, answers: merged, meta: newMeta } };
    });
    const cnt = Object.keys(incoming).filter((k) => k !== '__writer').length;
    showToast && showToast(`부모 답안 ${cnt}개 문항을 불러왔습니다`);
  };

  const updateMeta = (k, v) => {
    setWs((s) => ({
      ...s,
      interview: { ...s.interview, meta: { ...s.interview.meta, [k]: v } },
    }));
  };

  // 질문지 메타(이름/연령/작성일)가 비어 있으면 위 헤더 정보에서 자동으로 채운다.
  // (이미 값이 있으면 건드리지 않음 → 사용자가 직접 쓴 값 보존)
  useEffect(() => {
    const m = ws.interview.meta || {};
    const patch = {};
    if (!m.name && ws.meta.childName) patch.name = ws.meta.childName;
    if (!m.date && ws.meta.reportDate) patch.date = ws.meta.reportDate;
    const autoAge = calcAge(ws.meta.birthDate, m.date || ws.meta.reportDate);
    if (!m.age && autoAge) patch.age = autoAge;
    if (Object.keys(patch).length > 0) {
      setWs((s) => ({
        ...s,
        interview: { ...s.interview, meta: { ...s.interview.meta, ...patch } },
      }));
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [ws.meta.childName, ws.meta.birthDate, ws.meta.reportDate]);

  const updateAnswer = (id, value) => {
    setWs((s) => ({
      ...s,
      interview: { ...s.interview, answers: { ...s.interview.answers, [id]: value } },
    }));
  };

  const currentSection = interview.sections.find((sec) => sec.key === activeSection);

  return (
    <div className="tab-content">
      <StepBanner
        kind="required"
        done={Object.keys(ws.interview?.answers || {}).length >= 3}
        todo="② 보호자 면담 내용을 기록하세요. 진단 채점과 IEP 자동 생성의 근거가 됩니다."
        okMsg="질문지 작성됨 — 진단(3번)으로 넘어가세요."
        writer="parent"
      />
      <div className="kakao-box no-print" style={{ borderColor: '#2d4a3e' }}>
        <div className="kakao-box-title">🔗 부모님께 링크로 보내기 (추천)</div>
        <div className="kakao-box-desc">
          링크를 카톡으로 보내면, 부모님이 링크만 눌러 바로 작성·제출할 수 있어요. 복사·붙여넣기가 필요 없습니다.
        </div>
        <div className="kakao-box-steps">
          <div className="kakao-step">
            <span className="kakao-step-num">1</span>
            <div>
              <button className="btn-primary btn-small" onClick={makeParentLink}>🔗 작성 링크 만들기</button>
              <div className="kakao-step-hint">링크가 자동 복사됩니다. 카톡으로 부모님께 붙여넣어 보내세요.</div>
              {ws.interview?.linkSentAt && (
                <div style={{ fontSize: 12, color: '#2d7a4f', marginTop: 4 }}>
                  ✓ 링크 발송 기록: {String(ws.interview.linkSentAt).slice(0, 10)}
                </div>
              )}
              {fillLink && (
                <div style={{ marginTop: 8, display: 'flex', gap: 6, alignItems: 'center', flexWrap: 'wrap' }}>
                  <input readOnly value={fillLink} onClick={(e) => e.target.select()}
                    style={{ flex: 1, minWidth: 180, fontSize: 12, padding: '7px 9px', border: '1px solid #d9d1bd', borderRadius: 7, background: '#fafafa', color: '#555' }} />
                  <button className="btn-ghost btn-small" onClick={() => { try { navigator.clipboard.writeText(fillLink); showToast && showToast('링크를 복사했습니다'); } catch (e) {} }}>복사</button>
                </div>
              )}
            </div>
          </div>
          <div className="kakao-step">
            <span className="kakao-step-num">2</span>
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
                <b style={{ fontSize: 14 }}>받은 제출 {subs.length > 0 ? `(${subs.length}건)` : ''}</b>
                <button className="btn-ghost btn-small" onClick={loadSubmissions} disabled={subsLoading}>
                  {subsLoading ? '불러오는 중…' : '🔄 새로고침'}
                </button>
              </div>
              <div className="kakao-step-hint">부모님이 제출하면 여기에 자동으로 뜹니다. "불러오기"를 누르면 질문지가 채워집니다.</div>
              {subs.length === 0 && !subsLoading && (
                <div style={{ fontSize: 12.5, color: '#8a7f65', marginTop: 8 }}>아직 받은 제출이 없습니다.</div>
              )}
              {subs.map((sub) => {
                const cnt = Object.keys(sub.answers || {}).filter((k) => k !== '__writer').length;
                return (
                  <div key={sub.sid} style={{ marginTop: 8, padding: '10px 12px', background: '#fff', border: '1px solid #e4dcc8', borderRadius: 8, display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}>
                    <div style={{ flex: 1, minWidth: 140 }}>
                      <div style={{ fontSize: 13.5, fontWeight: 600 }}>
                        {sub.writer || '작성자 미기재'}
                      </div>
                      <div style={{ fontSize: 11.5, color: '#8a7f65', marginTop: 2 }}>
                        {cnt}개 문항 · 제출 {sub.submittedAt ? String(sub.submittedAt).slice(0, 10) : ''}
                      </div>
                    </div>
                    <button className="btn-primary btn-small" onClick={() => applySubmission(sub)}>불러오기</button>
                    <button className="btn-ghost btn-small" onClick={() => removeSubmission(sub)}>삭제</button>
                  </div>
                );
              })}
            </div>
          </div>
        </div>
      </div>
      <div className="kakao-box no-print">
        <div className="kakao-box-title">💬 부모님께 보내서 받기 (다른 방법 — 파일)</div>
        <div className="kakao-box-desc">
          링크가 어려운 경우, 파일을 카톡으로 보내고 부모님이 보낸 코드를 붙여넣어 채울 수도 있습니다.
        </div>
        <div className="kakao-box-steps">
          <div className="kakao-step">
            <span className="kakao-step-num">1</span>
            <div>
              <button className="btn-primary btn-small" onClick={exportParentForm}>📤 부모용 질문지 내보내기</button>
              <div className="kakao-step-hint">다운로드된 파일을 카톡으로 부모님께 전송하세요. 부모님은 폰에서 바로 작성할 수 있습니다.</div>
            </div>
          </div>
          <div className="kakao-step">
            <span className="kakao-step-num">2</span>
            <div>
              <button className="btn-ghost btn-small" onClick={importParentAnswers}>📥 부모 답안 붙여넣기</button>
              <div className="kakao-step-hint">부모님이 카톡으로 보내준 "SCERTS::" 코드를 붙여넣으면 질문지가 자동으로 채워집니다.</div>
            </div>
          </div>
        </div>
      </div>
      <div className="card no-break">
        <div className="iep-header">
          <h2 className="section-title">SCERTS 진단 — 질문지 ({STAGE_LABELS[ws.meta.stage]})</h2>
          <div className="iep-actions no-print">
            <button className="btn-primary" onClick={printReport}>인쇄 / PDF</button>
          </div>
        </div>

        <div id="printable-report" className="printable">
          <ReportHeader title={`SCERTS 진단-질문지 (${STAGE_LABELS[ws.meta.stage]})`} ws={ws} />

          <section className="report-section">
            <p className="interview-intro">{interview.intro}</p>
            <table className="report-table interview-meta-table">
              <tbody>
                {(() => {
                  // 위 헤더 정보에서 자동 연계되는 값
                  const autoVals = {
                    name: ws.meta.childName || '',
                    age: calcAge(ws.meta.birthDate, ws.interview.meta.date || ws.meta.reportDate),
                    date: ws.meta.reportDate || '',
                    reporter: '',   // 작성자는 개별 정보라 자동값 없음
                    relation: '',   // 관계도 개별 정보
                  };
                  return [
                    ['이름', 'name'], ['연령', 'age'], ['작성일', 'date'],
                    ['작성자', 'reporter'], ['아동과의 관계', 'relation'],
                  ].map(([label, key]) => {
                    const manual = ws.interview.meta[key] || '';
                    const auto = autoVals[key] || '';
                    // 직접 입력값이 있으면 그것을, 없으면 자동값을 표시 (자동값은 회색 안내처럼)
                    return (
                      <tr key={key}>
                        <th style={{ width: '14%' }}>{label}</th>
                        <td>
                          <input
                            type="text"
                            className="interview-input"
                            value={manual || auto}
                            placeholder={auto || ''}
                            onChange={(e) => updateMeta(key, e.target.value)}
                            title={auto && !manual ? '위 정보에서 자동으로 채워졌습니다 (수정 가능)' : ''}
                          />
                        </td>
                      </tr>
                    );
                  });
                })()}
              </tbody>
            </table>
          </section>

          {/* 섹션 네비게이션 */}
          <div className="interview-nav no-print">
            {interview.sections.map((sec) => (
              <button
                key={sec.key}
                className={`interview-nav-btn ${activeSection === sec.key ? 'active' : ''}`}
                onClick={() => setActiveSection(sec.key)}
              >
                {sec.title}
              </button>
            ))}
          </div>

          {/* 모든 섹션을 인쇄용으로 렌더 + 화면용으로는 선택된 섹션만 */}
          {interview.sections.map((sec) => (
            <section
              key={sec.key}
              className={`report-section interview-section ${sec.key !== activeSection ? 'screen-hidden' : ''}`}
            >
              <h3 className="report-h3">{sec.title}</h3>
              <div className="interview-questions">
                {sec.questions.map((q, idx) => (
                  <InterviewQuestion
                    key={q.id}
                    q={q}
                    index={idx + 1}
                    value={ws.interview.answers[q.id]}
                    onChange={(v) => updateAnswer(q.id, v)}
                  />
                ))}
              </div>
            </section>
          ))}
        </div>
      </div>
    </div>
  );
}

function InterviewQuestion({ q, index, value, onChange }) {
  if (q.type === 'text') {
    return (
      <div className="iq-row">
        <div className="iq-q"><span className="iq-idx">{index}.</span> {q.q}</div>
        <textarea
          className="iq-text"
          value={value || ''}
          onChange={(e) => onChange(e.target.value)}
          rows={3}
          placeholder="여기에 답변을 입력하세요"
        />
      </div>
    );
  }

  if (q.type === 'checklist') {
    const v = value || { checked: {}, texts: {} };
    return (
      <div className="iq-row">
        <div className="iq-q"><span className="iq-idx">{index}.</span> {q.q}</div>
        <div className="iq-checklist">
          {q.options.map((opt, i) => (
            <label key={i} className="iq-check-item">
              <input
                type="checkbox"
                checked={!!v.checked?.[opt]}
                onChange={(e) =>
                  onChange({
                    ...v,
                    checked: { ...v.checked, [opt]: e.target.checked },
                  })
                }
              />
              <span>{opt}</span>
            </label>
          ))}
          {q.withText &&
            q.withText.map((wt) => (
              <div key={wt.id} className="iq-check-with-text">
                <label className="iq-check-item">
                  <input
                    type="checkbox"
                    checked={!!v.checked?.[wt.id]}
                    onChange={(e) =>
                      onChange({
                        ...v,
                        checked: { ...v.checked, [wt.id]: e.target.checked },
                      })
                    }
                  />
                  <span>{wt.label}</span>
                </label>
                <input
                  type="text"
                  className="iq-extra-input"
                  value={v.texts?.[wt.id] || ''}
                  onChange={(e) =>
                    onChange({
                      ...v,
                      texts: { ...v.texts, [wt.id]: e.target.value },
                    })
                  }
                  placeholder="구체적인 예를 적으세요"
                />
              </div>
            ))}
        </div>
      </div>
    );
  }

  if (q.type === 'frequency') {
    const v = value || {};
    const cols = ['거의 또는 전혀 하지 않음', '가끔', '자주'];
    return (
      <div className="iq-row">
        <div className="iq-q"><span className="iq-idx">{index}.</span> {q.q}</div>
        <table className="iq-frequency-table">
          <thead>
            <tr>
              <th></th>
              {cols.map((c) => <th key={c}>{c}</th>)}
            </tr>
          </thead>
          <tbody>
            {q.partners.map((p, i) => (
              <tr key={i}>
                <td>{p}</td>
                {cols.map((c, j) => (
                  <td key={j} className="iq-freq-cell">
                    <input
                      type="radio"
                      name={`${q.id}_${i}`}
                      checked={v[i] === j}
                      onChange={() => onChange({ ...v, [i]: j })}
                    />
                  </td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    );
  }

  if (q.type === 'emotionsRows' || q.type === 'emotionPairs') {
    const v = value || {};
    if (q.type === 'emotionsRows') {
      return (
        <div className="iq-row">
          <div className="iq-q"><span className="iq-idx">{index}.</span> {q.q}</div>
          <table className="iq-emotion-table">
            <tbody>
              {q.emotions.map((emo) => (
                <tr key={emo}>
                  <td className="iq-emo-label">{emo}</td>
                  <td>
                    <textarea
                      className="iq-text"
                      rows={1}
                      value={v[emo] || ''}
                      onChange={(e) => onChange({ ...v, [emo]: e.target.value })}
                      placeholder="어떻게 표현하는지 기술"
                    />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      );
    }
    return (
      <div className="iq-row">
        <div className="iq-q"><span className="iq-idx">{index}.</span> {q.q}</div>
        <table className="iq-emotion-pair-table">
          <thead>
            <tr><th>긍정적인 감정</th><th>부정적인 감정</th></tr>
          </thead>
          <tbody>
            {q.pairs.map((pair, i) => (
              <tr key={i}>
                {pair.map((emo) => (
                  <td key={emo}>
                    <div className="iq-emo-label">{emo}</div>
                    <textarea
                      className="iq-text"
                      rows={1}
                      value={v[emo] || ''}
                      onChange={(e) => onChange({ ...v, [emo]: e.target.value })}
                      placeholder="표현 방식 기술"
                    />
                  </td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    );
  }

  if (q.type === 'recoveryPair') {
    const v = value || {};
    return (
      <div className="iq-row">
        <div className="iq-q"><span className="iq-idx">{index}.</span> {q.q}</div>
        <div className="iq-recovery">
          <div className="iq-recovery-block">
            <div className="iq-recovery-label">• {q.self}</div>
            <textarea
              className="iq-text"
              rows={2}
              value={v.self || ''}
              onChange={(e) => onChange({ ...v, self: e.target.value })}
            />
          </div>
          <div className="iq-recovery-block">
            <div className="iq-recovery-label">• {q.partner}</div>
            <textarea
              className="iq-text"
              rows={2}
              value={v.partner || ''}
              onChange={(e) => onChange({ ...v, partner: e.target.value })}
            />
          </div>
        </div>
      </div>
    );
  }

  if (q.type === 'scale02List') {
    const v = value || {};
    return (
      <div className="iq-row">
        <div className="iq-q"><span className="iq-idx">{index}.</span> {q.q}</div>
        <table className="iq-scale-table">
          <tbody>
            {q.items.map((item, i) => (
              <tr key={i}>
                <td className="iq-scale-label">{item}</td>
                {[0, 1, 2].map((n) => (
                  <td key={n} className="iq-scale-cell">
                    <button
                      type="button"
                      className={`score-pip score-${n} ${v[item] === n ? 'active' : ''}`}
                      onClick={() => onChange({ ...v, [item]: n })}
                    >
                      {n}
                    </button>
                  </td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    );
  }

  return null;
}

// =====================================================================
// (ObservationTab은 AssessmentTab의 토글로 통합됨 - AssessObservationView 참조)
// =====================================================================

function renderObsCell(row, planId, value, onChange, onVariantChange) {
  if (row.type === 'text') {
    return (
      <textarea
        className="editable multi"
        rows={3}
        value={(value && value.value) || ''}
        onChange={(e) => onChange('value', e.target.value)}
        placeholder="기록 내용"
      />
    );
  }
  if (row.type === 'datetime') {
    return (
      <div className="obs-fields">
        {row.fields.map((f) => (
          <div key={f} className="obs-field">
            <div className="obs-field-label">{f}</div>
            <textarea
              className="editable multi"
              rows={2}
              value={(value && value[f]) || ''}
              onChange={(e) => onChange(f, e.target.value)}
            />
          </div>
        ))}
      </div>
    );
  }
  if (row.type === 'variants') {
    const variants = value?.variants || {};
    return (
      <div className="obs-variants">
        {row.variants.map((pair, i) => (
          <div key={i} className="obs-variant-row">
            <label className="obs-variant-opt">
              <input
                type="radio"
                name={`var_${planId}_${i}`}
                checked={variants[i] === 'a'}
                onChange={() => onVariantChange(i, 'a')}
              />
              <span>{pair[0]}</span>
            </label>
            <label className="obs-variant-opt">
              <input
                type="radio"
                name={`var_${planId}_${i}`}
                checked={variants[i] === 'b'}
                onChange={() => onVariantChange(i, 'b')}
              />
              <span>{pair[1]}</span>
            </label>
          </div>
        ))}
      </div>
    );
  }
  if (row.type === 'list') {
    return (
      <div className="obs-list">
        {Array.from({ length: row.count }).map((_, i) => (
          <div key={i} className="obs-list-item">
            <span className="obs-list-num">{i + 1}.</span>
            <input
              type="text"
              className="obs-list-input"
              value={(value && value[i]) || ''}
              onChange={(e) => onChange(i, e.target.value)}
            />
          </div>
        ))}
      </div>
    );
  }
  return null;
}

// =====================================================================
// ACTIVITY TAB — 활동 일지 I/II + 주간 기록지 + 활동 계획서
// =====================================================================
function ActivityTab({ ws, setWs, showToast }) {
  const [view, setView] = useState('logI');

  return (
    <div className="tab-content">
      <StepBanner
        kind="required"
        done={(ws.activities?.logI || []).length > 0}
        todo="④ 회기를 진행하며 활동 일지를 기록하세요. 중간보고서의 관찰 사례가 여기서 자동 인용됩니다."
        okMsg={`회기 일지 ${(ws.activities?.logI || []).length}건 기록됨 — 중간보고서 자동 채움 시 인용됩니다.`}
        writer="therapist"
      />
      <div className="card">
        <h2 className="section-title">활동 기록</h2>
        <p className="hint">개별 회기, 주간 종합, 활동 계획서를 작성할 수 있습니다.</p>

        <div className="activity-nav no-print">
          {[
            { id: 'logI', label: '회기별 활동 일지' },
            { id: 'logII', label: '주간 종합 기록' },
            { id: 'plan', label: '활동 계획서' },
            { id: 'stats', label: '📊 회기 통계' },
          ].map((v) => (
            <button
              key={v.id}
              className={`activity-nav-btn ${view === v.id ? 'active' : ''}`}
              onClick={() => setView(v.id)}
            >
              {v.label}
            </button>
          ))}
        </div>

        {view === 'logI' && <ActivityLogI ws={ws} setWs={setWs} showToast={showToast} />}
        {view === 'logII' && <ActivityLogII ws={ws} setWs={setWs} />}
        {view === 'plan' && <ActivityPlan ws={ws} setWs={setWs} />}
        {view === 'stats' && <ActivityStats ws={ws} />}
      </div>
    </div>
  );
}

function ActivityLogI({ ws, setWs, showToast }) {
  const [activeIdx, setActiveIdx] = useState(0);
  const logs = ws.activities.logI || [];

  // IEP 선정 목표에서 사회의사소통/정서조절 자동 분리
  const importedGoals = useMemo(() => {
    const stageData = STAGE_DATA[ws.meta.stage];
    if (!stageData) return { social: [], emo: [] };
    const social = [];
    const emo = [];
    (ws.iep?.selectedGoals || []).forEach((g) => {
      // 도메인 키로 분류
      let domainKey = null;
      Object.entries(stageData).forEach(([k, d]) => {
        d.groups.forEach((grp) => {
          grp.items.forEach((it) => {
            if (it.id === g.id) domainKey = k;
          });
        });
      });
      const goalText = g.customGoal || g.label;
      const entry = { goal: `[${g.id}] ${goalText}`, observed: '', rating: '' };
      if (domainKey === 'joinAttention' || domainKey === 'symbolUse') {
        social.push(entry);
      } else if (domainKey === 'mutualReg' || domainKey === 'selfReg') {
        emo.push(entry);
      }
    });
    // 파트너 목표 (객체 형태 + 문자열 형태 모두 지원)
    const partner = (ws.iep?.partnerGoals || [])
      .map((p) => {
        if (typeof p === 'object' && p?.id) {
          const txt = (p.customGoal || p.label || '').trim();
          return txt ? `[${p.id}] ${txt}` : '';
        }
        return typeof p === 'string' ? p.trim() : '';
      })
      .filter(Boolean)
      .map((goalText) => ({ goal: goalText, observed: '', rating: '' }));
    return { social, emo, partner };
  }, [ws.iep, ws.meta.stage]);

  const addLog = () => {
    setWs((s) => {
      const next = [...s.activities.logI, {
        id: 'log_' + Date.now(),
        date: new Date().toISOString().slice(0, 10),
        fields: {},
        // IEP 선정 목표를 회기 일지에 자동 import
        goalsSocial: [...importedGoals.social],
        goalsEmo: [...importedGoals.emo],
        partnerGoals: [...importedGoals.partner],
        notes: '',
      }];
      return { ...s, activities: { ...s.activities, logI: next } };
    });
    setActiveIdx(logs.length);
    if (importedGoals.social.length + importedGoals.emo.length > 0) {
      showToast(`IEP 선정 목표 ${importedGoals.social.length + importedGoals.emo.length}개를 자동 불러왔습니다`);
    }
  };

  // 기존 회기에 IEP 목표 다시 불러오기
  const reimportFromIEP = async () => {
    if (!await appConfirm('현재 회기의 목표 행을 IEP 선정 목표로 덮어씁니다. 진행하시겠습니까?')) return;
    setWs((s) => {
      const arr = [...s.activities.logI];
      arr[activeIdx] = {
        ...arr[activeIdx],
        goalsSocial: [...importedGoals.social],
        goalsEmo: [...importedGoals.emo],
        partnerGoals: [...importedGoals.partner],
      };
      return { ...s, activities: { ...s.activities, logI: arr } };
    });
    showToast('IEP 목표를 다시 불러왔습니다');
  };

  const removeLog = async (idx) => {
    if (!await appConfirm('이 회기 기록을 삭제하시겠습니까?')) return;
    setWs((s) => ({
      ...s,
      activities: { ...s.activities, logI: s.activities.logI.filter((_, i) => i !== idx) },
    }));
    setActiveIdx(Math.max(0, activeIdx - 1));
  };

  const updateLog = (patch) => {
    setWs((s) => {
      const arr = [...s.activities.logI];
      arr[activeIdx] = { ...arr[activeIdx], ...patch };
      return { ...s, activities: { ...s.activities, logI: arr } };
    });
  };

  const log = logs[activeIdx];

  // 템플릿 관리
  const [templates, setTemplates] = useState(loadTemplates);
  const [showTemplateMenu, setShowTemplateMenu] = useState(false);

  const refreshTemplates = () => setTemplates(loadTemplates());

  const saveCurrentAsTemplate = async () => {
    if (!log) return;
    const defaultName = log.fields?.activity || '회기 템플릿';
    const name = await appPrompt('템플릿 이름을 입력하세요:', defaultName);
    if (!name || !name.trim()) return;
    const newTpl = {
      id: 'tpl_' + Date.now() + '_' + Math.random().toString(36).slice(2, 6),
      name: name.trim(),
      createdAt: new Date().toISOString(),
      fields: { ...(log.fields || {}) },
      // 평가는 비워둠 (재사용 시 새로 평가)
      goalsSocial: (log.goalsSocial || []).map((g) => ({ goal: g.goal, observed: '', rating: '' })),
      goalsEmo: (log.goalsEmo || []).map((g) => ({ goal: g.goal, observed: '', rating: '' })),
      partnerGoals: (log.partnerGoals || []).map((g) => ({ goal: g.goal, observed: '', rating: '' })),
    };
    const updated = [newTpl, ...templates];
    saveTemplates(updated);
    setTemplates(updated);
    if (showToast) showToast(`템플릿 "${name.trim()}" 저장됨`);
    setShowTemplateMenu(false);
  };

  const applyTemplate = async (tpl) => {
    if (!log) return;
    if (!await appConfirm(`템플릿 "${tpl.name}"을 현재 회기에 적용합니다.\n\n활동 정보·목표 행이 덮어씌워집니다 (날짜·메모는 보존).\n계속하시겠습니까?`)) return;
    updateLog({
      fields: { ...tpl.fields },
      goalsSocial: tpl.goalsSocial.map((g) => ({ ...g })),
      goalsEmo: tpl.goalsEmo.map((g) => ({ ...g })),
      partnerGoals: tpl.partnerGoals.map((g) => ({ ...g })),
    });
    if (showToast) showToast(`템플릿 "${tpl.name}" 적용됨`);
    setShowTemplateMenu(false);
  };

  const deleteTemplate = async (id, name) => {
    if (!await appConfirm(`템플릿 "${name}"을 삭제하시겠습니까?`)) return;
    const updated = templates.filter((t) => t.id !== id);
    saveTemplates(updated);
    setTemplates(updated);
  };

  // 템플릿으로 새 회기 추가
  const addLogFromTemplate = (tpl) => {
    setWs((s) => {
      const next = [...s.activities.logI, {
        id: 'log_' + Date.now(),
        date: new Date().toISOString().slice(0, 10),
        fields: { ...tpl.fields },
        goalsSocial: tpl.goalsSocial.map((g) => ({ ...g })),
        goalsEmo: tpl.goalsEmo.map((g) => ({ ...g })),
        partnerGoals: tpl.partnerGoals.map((g) => ({ ...g })),
        notes: '',
      }];
      return { ...s, activities: { ...s.activities, logI: next } };
    });
    setActiveIdx(logs.length);
    if (showToast) showToast(`템플릿 "${tpl.name}"로 새 회기 생성됨`);
    setShowTemplateMenu(false);
  };

  // 회기 검색·필터
  const [logQuery, setLogQuery] = useState('');
  const filteredIndices = useMemo(() => {
    if (!logQuery.trim()) return logs.map((_, i) => i);
    const q = logQuery.trim().toLowerCase();
    return logs.map((l, i) => {
      // 검색 대상: 날짜, 활동명, 메모, 목표 내용
      const fields = Object.values(l.fields || {}).join(' ').toLowerCase();
      const goals = [...(l.goalsSocial || []), ...(l.goalsEmo || []), ...(l.partnerGoals || [])]
        .map((g) => `${g.goal || ''} ${g.observed || ''}`).join(' ').toLowerCase();
      const notes = (l.notes || '').toLowerCase();
      const matched = (l.date || '').includes(q) || fields.includes(q) || goals.includes(q) || notes.includes(q);
      return matched ? i : -1;
    }).filter((i) => i >= 0);
  }, [logs, logQuery]);

  return (
    <div>
      {logs.length > 5 && (
        <div className="logI-search no-print">
          <span className="archive-search-icon">🔍</span>
          <input
            type="text"
            className="archive-search-input"
            placeholder={`${logs.length}개 회기 중 검색 (날짜·활동명·메모·목표 내용)`}
            value={logQuery}
            onChange={(e) => setLogQuery(e.target.value)}
          />
          {logQuery && <button className="archive-search-clear" onClick={() => setLogQuery('')}>×</button>}
          <span className="logI-search-count">
            {filteredIndices.length}/{logs.length}건
          </span>
        </div>
      )}
      <div className="logI-tabs no-print">
        {filteredIndices.map((i) => {
          const l = logs[i];
          return (
            <button
              key={l.id}
              className={`logI-tab ${i === activeIdx ? 'active' : ''}`}
              onClick={() => setActiveIdx(i)}
              title={l.fields?.activity || ''}
            >
              {l.date || `회기 ${i + 1}`}
            </button>
          );
        })}
        <button className="logI-tab add" onClick={addLog}>+ 새 회기</button>
        <div className="logI-template-wrap">
          <button
            className="logI-tab template-btn"
            onClick={() => setShowTemplateMenu((v) => !v)}
            title="회기 템플릿"
          >📋 템플릿{templates.length > 0 && ` (${templates.length})`}</button>
          {showTemplateMenu && (
            <>
              <div className="child-menu-backdrop" onClick={() => setShowTemplateMenu(false)} />
              <div className="template-menu">
                <div className="template-menu-header">
                  <strong>회기 템플릿</strong>
                  <span className="template-menu-hint">자주 쓰는 활동·목표를 저장해 빠르게 재사용하세요</span>
                </div>
                {log && (
                  <button className="template-menu-save" onClick={saveCurrentAsTemplate}>
                    💾 현재 회기를 템플릿으로 저장
                  </button>
                )}
                <div className="template-menu-divider">저장된 템플릿</div>
                {templates.length === 0 && (
                  <div className="template-menu-empty">저장된 템플릿이 없습니다.</div>
                )}
                {templates.map((tpl) => (
                  <div key={tpl.id} className="template-menu-item">
                    <div className="template-menu-info">
                      <strong>{tpl.name}</strong>
                      <div className="template-menu-meta">
                        목표 {(tpl.goalsSocial?.length || 0) + (tpl.goalsEmo?.length || 0)}개 ·
                        {tpl.fields?.activity ? ` ${tpl.fields.activity} ·` : ''}
                        {' '}{new Date(tpl.createdAt).toLocaleDateString('ko-KR')}
                      </div>
                    </div>
                    <div className="template-menu-actions">
                      {log && (
                        <button className="btn-ghost btn-small" onClick={() => applyTemplate(tpl)} title="현재 회기에 적용">적용</button>
                      )}
                      <button className="btn-ghost btn-small" onClick={() => addLogFromTemplate(tpl)} title="이 템플릿으로 새 회기">+새 회기</button>
                      <button className="btn-icon" onClick={() => deleteTemplate(tpl.id, tpl.name)} title="삭제">×</button>
                    </div>
                  </div>
                ))}
              </div>
            </>
          )}
        </div>
      </div>

      {!log && (
        <div className="empty-hint">+ 새 회기 버튼을 눌러 활동 일지를 추가하세요.</div>
      )}

      {log && (
        <div id="printable-report" className="printable">
          <ReportHeader title="SCERTS 활동 일지 I" ws={ws} />

          <section className="report-section">
            <table className="report-table">
              <tbody>
                {ACTIVITY_LOG_I.fields.map((f) => (
                  <tr key={f.id}>
                    <th style={{ width: '18%' }}>{f.label}</th>
                    <td>
                      <input
                        type={f.id === 'date' ? 'date' : 'text'}
                        className="interview-input"
                        value={(f.id === 'date' ? log.date : log.fields[f.id]) || ''}
                        onChange={(e) => {
                          if (f.id === 'date') {
                            updateLog({ date: e.target.value });
                          } else {
                            updateLog({ fields: { ...log.fields, [f.id]: e.target.value } });
                          }
                        }}
                      />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </section>

          {[
            { title: '아동의 사회 의사소통 목표', key: 'goalsSocial', cols: ['목표', '관찰된 행동/예', '도달 여부'], rows: 6 },
            { title: '아동의 정서 조절 목표', key: 'goalsEmo', cols: ['목표', '관찰된 행동/예', '도달 여부'], rows: 4 },
            { title: '파트너의 교류 지원 목표', key: 'partnerGoals', cols: ['목표', '사용한 전략/예', '효과'], rows: 6 },
          ].map((s) => (
            <section key={s.key} className="report-section">
              <h3 className="report-h3">{s.title}</h3>
              <table className="report-table">
                <thead>
                  <tr>{s.cols.map((c) => <th key={c}>{c}</th>)}</tr>
                </thead>
                <tbody>
                  {Array.from({ length: s.rows }).map((_, i) => {
                    const item = (log[s.key] && log[s.key][i]) || {};
                    return (
                      <tr key={i}>
                        <td>
                          <Editable
                            value={item.goal}
                            onChange={(v) => {
                              const arr = [...(log[s.key] || [])];
                              arr[i] = { ...arr[i], goal: v };
                              updateLog({ [s.key]: arr });
                            }}
                            multiline
                          />
                        </td>
                        <td>
                          <Editable
                            value={item.observed}
                            onChange={(v) => {
                              const arr = [...(log[s.key] || [])];
                              arr[i] = { ...arr[i], observed: v };
                              updateLog({ [s.key]: arr });
                            }}
                            multiline
                          />
                        </td>
                        <td>
                          <select
                            className="rating-select"
                            value={item.rating || ''}
                            onChange={(e) => {
                              const arr = [...(log[s.key] || [])];
                              arr[i] = { ...arr[i], rating: e.target.value };
                              updateLog({ [s.key]: arr });
                            }}
                          >
                            <option value="">—</option>
                            <option value="−">−</option>
                            <option value="+/−">+/−</option>
                            <option value="+">+</option>
                          </select>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </section>
          ))}

          <section className="report-section">
            <h3 className="report-h3">활동 후 관찰 메모</h3>
            <Editable
              value={log.notes}
              onChange={(v) => updateLog({ notes: v })}
              placeholder="추가 관찰 내용, 다음 회기에 반영할 사항 등"
              multiline
              minLines={4}
            />
          </section>

          <div className="no-print" style={{ marginTop: 16, textAlign: 'right' }}>
            <button className="btn-ghost" onClick={reimportFromIEP}>📥 IEP 목표 다시 불러오기</button>
            <button className="btn-danger" style={{ marginLeft: 8 }} onClick={() => removeLog(activeIdx)}>이 회기 삭제</button>
            <button className="btn-primary" style={{ marginLeft: 8 }} onClick={printReport}>인쇄 / PDF</button>
          </div>
        </div>
      )}
    </div>
  );
}

function ActivityLogII({ ws, setWs }) {
  const data = ws.activities.logII || { weekOf: '', daily: {}, summary: '', social: '', emo: '', ts: '', adjust: '' };
  const update = (patch) => setWs((s) => ({
    ...s, activities: { ...s.activities, logII: { ...s.activities.logII, ...patch } },
  }));
  const updateDaily = (day, field, value) => {
    setWs((s) => ({
      ...s,
      activities: {
        ...s.activities,
        logII: {
          ...s.activities.logII,
          daily: {
            ...s.activities.logII.daily,
            [day]: { ...(s.activities.logII.daily?.[day] || {}), [field]: value },
          },
        },
      },
    }));
  };
  const days = ['월', '화', '수', '목', '금', '토/일'];
  const cols = ['활동/환경', '주요 목표', '진전/관찰'];

  return (
    <div id="printable-report" className="printable">
      <ReportHeader title="SCERTS 주간 종합 기록" ws={ws} extras={[
        { label: '주차/기간', editable: true, value: data.weekOf, onChange: (v) => update({ weekOf: v }) },
      ]} />

      <section className="report-section">
        <h3 className="report-h3">주간 활동 요약</h3>
        <table className="report-table">
          <thead>
            <tr>
              <th style={{ width: '10%' }}>요일</th>
              {cols.map((c) => <th key={c}>{c}</th>)}
            </tr>
          </thead>
          <tbody>
            {days.map((d) => (
              <tr key={d}>
                <td><strong>{d}</strong></td>
                {cols.map((c) => (
                  <td key={c}>
                    <Editable
                      value={data.daily?.[d]?.[c]}
                      onChange={(v) => updateDaily(d, c, v)}
                      multiline
                    />
                  </td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </section>

      <section className="report-section">
        <h3 className="report-h3">SCERTS 영역별 주간 진전</h3>
        <table className="report-table">
          <tbody>
            <tr>
              <th style={{ width: '18%' }}>사회 의사소통</th>
              <td>
                <Editable
                  value={data.social}
                  onChange={(v) => update({ social: v })}
                  multiline
                  placeholder="시선·요청·차례 주고받기 등의 진전"
                />
              </td>
            </tr>
            <tr>
              <th>정서 조절</th>
              <td>
                <Editable
                  value={data.emo}
                  onChange={(v) => update({ emo: v })}
                  multiline
                  placeholder="조절 전략 사용, 회복 시간, 정서 표현"
                />
              </td>
            </tr>
            <tr>
              <th>교류 지원 (파트너 효과)</th>
              <td>
                <Editable
                  value={data.ts}
                  onChange={(v) => update({ ts: v })}
                  multiline
                  placeholder="파트너 전략이 효과적이었던 부분, 보완할 부분"
                />
              </td>
            </tr>
          </tbody>
        </table>
      </section>

      <section className="report-section">
        <h3 className="report-h3">주간 종합 요약</h3>
        <Editable
          value={data.summary}
          onChange={(v) => update({ summary: v })}
          multiline
          minLines={3}
          placeholder="이번 주의 전반적인 진전 및 변화를 종합적으로 기술하세요."
        />
      </section>

      <section className="report-section">
        <h3 className="report-h3">다음 주 조정 사항</h3>
        <Editable
          value={data.adjust}
          onChange={(v) => update({ adjust: v })}
          multiline
          minLines={3}
          placeholder="다음 주 목표 조정, 환경 수정, 파트너 전략 변경 등"
        />
      </section>

      <div className="no-print" style={{ marginTop: 16, textAlign: 'right' }}>
        <button className="btn-primary" onClick={printReport}>인쇄 / PDF</button>
      </div>
    </div>
  );
}

function WeeklyRecord({ ws, setWs }) {
  const data = ws.activities.weekly || { weekOf: '', social: '', emo: '', ts: '', adjust: '' };
  const update = (patch) => setWs((s) => ({
    ...s, activities: { ...s.activities, weekly: { ...s.activities.weekly, ...patch } },
  }));

  return (
    <div id="printable-report" className="printable">
      <ReportHeader title="SCERTS 주간 기록지" ws={ws} extras={[
        { label: '주차/기간', editable: true, value: data.weekOf, onChange: (v) => update({ weekOf: v }) },
      ]} />

      {[
        { key: 'social', title: '주간 사회 의사소통 진전' },
        { key: 'emo', title: '주간 정서 조절 진전' },
        { key: 'ts', title: '주간 교류 지원 (파트너 지원 효과)' },
        { key: 'adjust', title: '다음 주 조정 사항' },
      ].map((s) => (
        <section key={s.key} className="report-section">
          <h3 className="report-h3">{s.title}</h3>
          <Editable
            value={data[s.key]}
            onChange={(v) => update({ [s.key]: v })}
            multiline
            minLines={4}
          />
        </section>
      ))}

      <div className="no-print" style={{ marginTop: 16, textAlign: 'right' }}>
        <button className="btn-primary" onClick={printReport}>인쇄 / PDF</button>
      </div>
    </div>
  );
}

function ActivityPlan({ ws, setWs }) {
  const data = ws.activities.plan || { fields: {}, steps: '', goalsSocial: [], goalsEmo: [], partnerGoals: [], challenges: '' };
  const update = (patch) => setWs((s) => ({
    ...s, activities: { ...s.activities, plan: { ...s.activities.plan, ...patch } },
  }));
  const updateField = (k, v) => update({ fields: { ...data.fields, [k]: v } });
  const updateList = (key, idx, value) => {
    const arr = [...(data[key] || [])];
    arr[idx] = value;
    update({ [key]: arr });
  };

  // IEP에서 선정된 목표를 사회의사소통/정서조절로 자동 분리
  const importFromIEP = async () => {
    const stageData = STAGE_DATA[ws.meta.stage];
    if (!stageData) return;
    const socialGoals = [];
    const emoGoals = [];
    (ws.iep?.selectedGoals || []).forEach((g) => {
      let domainKey = null;
      Object.entries(stageData).forEach(([k, d]) => {
        d.groups.forEach((grp) => {
          grp.items.forEach((it) => {
            if (it.id === g.id) domainKey = k;
          });
        });
      });
      const goalText = `[${g.id}] ${g.customGoal || g.label}`;
      if (domainKey === 'joinAttention' || domainKey === 'symbolUse') socialGoals.push(goalText);
      else if (domainKey === 'mutualReg' || domainKey === 'selfReg') emoGoals.push(goalText);
    });
    const partnerGoals = (ws.iep?.partnerGoals || []).filter((p) => p && p.trim());

    // 교수 전략도 함께 가져오기
    const strategies = ws.iep?.strategies || {};
    const strategyText = [
      strategies.sc && `[사회의사소통] ${strategies.sc}`,
      strategies.er && `[정서조절] ${strategies.er}`,
      strategies.ts && `[교류지원] ${strategies.ts}`,
    ].filter(Boolean).join('\n');

    if (!await appConfirm(`IEP에서 다음 데이터를 자동 인용합니다:\n- 아동 목표 ${socialGoals.length + emoGoals.length}개\n- 파트너 목표 ${partnerGoals.length}개\n- 교수 전략 ${strategyText ? '있음' : '없음'}\n\n현재 활동 계획서의 목표 영역을 덮어씁니다. 진행하시겠습니까?`)) return;

    update({
      goalsSocial: socialGoals,
      goalsEmo: emoGoals,
      partnerGoals: partnerGoals,
      fields: { ...data.fields },
      // IEP 교수 전략을 단계/흐름 시작점에 자동 채움 (비어있을 때만)
      steps: data.steps || (strategyText ? `[IEP 교수 전략]\n${strategyText}\n\n[활동 단계 및 흐름]\n시작: ...\n본 활동: ...\n마무리: ...` : data.steps),
    });
  };

  return (
    <div id="printable-report" className="printable">
      <div className="no-print" style={{ marginBottom: 16, textAlign: 'right' }}>
        <button className="btn-ghost" onClick={importFromIEP}>📥 IEP에서 목표·전략 가져오기</button>
      </div>
      <ReportHeader title="SCERTS 활동 계획서" ws={ws} />

      <section className="report-section">
        <h3 className="report-h3">활동 정보</h3>
        <table className="report-table">
          <tbody>
            {ACTIVITY_PLAN.sections[0].items.map((it) => (
              <tr key={it.id}>
                <th style={{ width: '20%' }}>{it.label}</th>
                <td>
                  <Editable
                    value={data.fields[it.id]}
                    onChange={(v) => updateField(it.id, v)}
                    multiline
                  />
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>

      <section className="report-section">
        <h3 className="report-h3">활동 단계 및 흐름</h3>
        <Editable
          value={data.steps}
          onChange={(v) => update({ steps: v })}
          placeholder="단계별 흐름을 순서대로 기재 (시작 → 본 활동 → 마무리)"
          multiline
          minLines={5}
        />
      </section>

      {[
        { key: 'goalsSocial', title: '아동 목표 (사회 의사소통)', count: 4 },
        { key: 'goalsEmo', title: '아동 목표 (정서 조절)', count: 3 },
        { key: 'partnerGoals', title: '파트너 교류 지원 전략', count: 4 },
      ].map((s) => (
        <section key={s.key} className="report-section">
          <h3 className="report-h3">{s.title}</h3>
          <ol className="suggestion-list">
            {Array.from({ length: s.count }).map((_, i) => (
              <li key={i}>
                <Editable
                  value={(data[s.key] || [])[i]}
                  onChange={(v) => updateList(s.key, i, v)}
                  multiline
                />
              </li>
            ))}
          </ol>
        </section>
      ))}

      <section className="report-section">
        <h3 className="report-h3">예상되는 어려움 및 대응 전략</h3>
        <Editable
          value={data.challenges}
          onChange={(v) => update({ challenges: v })}
          multiline
          minLines={4}
        />
      </section>

      <div className="no-print" style={{ marginTop: 16, textAlign: 'right' }}>
        <button className="btn-primary" onClick={printReport}>인쇄 / PDF</button>
      </div>
    </div>
  );
}

// =====================================================================
// 단계별 발달 특징 박스 (보고서 상단 자동 삽입)
// =====================================================================
// =====================================================================
// 관찰 정보 요약 (IEP/중간보고서에 자동 인용)
// =====================================================================
function ObservationSummary({ ws }) {
  const data = ws.observation?.data || {};
  // 데이터가 비어있으면 표시 안 함
  const hasData = ws.observation?.plans?.some(
    (plan) => data[plan.id] && Object.keys(data[plan.id]).length > 0,
  );
  if (!hasData) return null;

  return (
    <section className="report-section">
      <h3 className="report-h3">진단 관찰 정보</h3>
      <p className="hint no-print" style={{ marginTop: 0 }}>
        SCERTS는 두 가지 이상의 자연스러운 상황·파트너에 걸친 일관성을 평가합니다.
      </p>
      <table className="report-table">
        <thead>
          <tr>
            <th style={{ width: '20%' }}>구분</th>
            {(ws.observation.plans || []).map((p, i) => (
              <th key={p.id}>관찰 #{i + 1}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {OBSERVATION_MAP.rows.filter((r) => r.type !== 'variants').map((row) => (
            <tr key={row.id}>
              <th style={{ background: '#ede6d5', textAlign: 'left' }}>{row.label}</th>
              {(ws.observation.plans || []).map((plan) => {
                const cellData = data[plan.id]?.[row.id];
                let display = '';
                if (cellData) {
                  if (row.type === 'text') display = cellData.value || '';
                  else if (row.type === 'datetime' && row.fields) {
                    display = row.fields.map((f) => cellData[f] ? `${f}: ${cellData[f]}` : '').filter(Boolean).join(' / ');
                  } else if (row.type === 'list') {
                    display = Object.values(cellData).filter(Boolean).join(', ');
                  }
                }
                return <td key={plan.id}>{display || <span style={{ color: '#b5a888' }}>—</span>}</td>;
              })}
            </tr>
          ))}
        </tbody>
      </table>
    </section>
  );
}

// =====================================================================
// 사회-정서 성장 지표 요약 (보고서에 자동 인용)
// =====================================================================
function SesIndicatorSummary({ values, title = '사회-정서 성장 지표' }) {
  const hasAny = values && Object.values(values).some((v) => typeof v === 'number' && v > 0);
  if (!hasAny) return null;

  return (
    <section className="report-section">
      <h3 className="report-h3">{title}</h3>
      <p className="hint no-print" style={{ marginTop: 0 }}>
        항목 채점이 미시적 능력이라면, 사회-정서 지표는 아동 전반의 발달 방향성을 보여줍니다.
      </p>
      <table className="report-table">
        <thead>
          <tr>
            <th style={{ width: '50%' }}>지표</th>
            <th style={{ width: '15%', textAlign: 'center' }}>점수 (0-10)</th>
            <th>발달 수준</th>
          </tr>
        </thead>
        <tbody>
          {SES_INDICATORS.map((ind) => {
            const v = values[ind.id] ?? 0;
            const range = SES_INTERPRETATION.ranges.find((r) => v >= r.min && v <= r.max);
            return (
              <tr key={ind.id}>
                <td><strong>{ind.label}</strong></td>
                <td style={{ textAlign: 'center', fontFamily: "'Gowun Batang', serif", fontWeight: 700 }}>
                  {v}/10
                </td>
                <td style={{ color: range?.color }}>
                  <strong>{range?.label}</strong> · {range?.meaning}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </section>
  );
}

// =====================================================================
// 가족 우선순위 보고서 출력 컴포넌트 (IEP/중간보고서용)
// =====================================================================
function FamilyPrioritiesReport({ ws }) {
  const fp = ws.familyPriorities || {};
  const hasContent = fp.profileAccurate || fp.additionalInfo || fp.focusOne || fp.threeMonthHope ||
                      (fp.focusGoalIds && fp.focusGoalIds.length > 0);
  if (!hasContent) return null;
  return (
    <section className="report-section">
      <h3 className="report-h3">가족의 견해 및 우선순위</h3>
      <table className="report-table">
        <tbody>
          {fp.profileAccurate && (
            <tr>
              <th style={{ width: '28%' }}>진단 프로파일의 정확성</th>
              <td>{fp.profileAccurate}</td>
            </tr>
          )}
          {fp.additionalInfo && (
            <tr>
              <th>추가 정보</th>
              <td>{fp.additionalInfo}</td>
            </tr>
          )}
          {fp.focusOne && (
            <tr>
              <th>가족의 1순위 집중 영역</th>
              <td><strong>{fp.focusOne}</strong></td>
            </tr>
          )}
          {fp.threeMonthHope && (
            <tr>
              <th>3개월 내 바라는 기술</th>
              <td>{fp.threeMonthHope}</td>
            </tr>
          )}
        </tbody>
      </table>
    </section>
  );
}

function StageProfileBox({ stage }) {
  if (!stage) return null;
  const profile = STAGE_PROFILE[stage];
  if (!profile) return null;
  return (
    <section className="stage-profile-box">
      <div className="stage-profile-header">
        <div className="stage-profile-eyebrow">단계별 발달 특징</div>
        <h3 className="stage-profile-title">{profile.headline}</h3>
        <div className="stage-profile-meta">
          <span>{profile.subtitle}</span>
          <span className="stage-profile-divider">·</span>
          <span>{profile.age}</span>
        </div>
      </div>
      <p className="stage-profile-summary">{profile.summary}</p>
      <div className="stage-profile-cols">
        <div className="stage-profile-col">
          <strong>이 단계의 핵심 특징</strong>
          <ul>{profile.features.map((f, i) => <li key={i}>{f}</li>)}</ul>
        </div>
        <div className="stage-profile-col">
          <strong>발달 우선순위</strong>
          <ul>{profile.priorities.map((p, i) => <li key={i}>{p}</li>)}</ul>
        </div>
      </div>
    </section>
  );
}

// =====================================================================
// SessionTabs — 진단 세션 (분기별 채점 기록) 관리 UI
// =====================================================================
function SessionTabs({ ws, addSession, switchSession, removeSession, updateSessionMeta, setSessionDesignation }) {
  const sessions = ws._allSessions || [];
  const activeId = ws._sessionId;

  const handleAdd = async () => {
    const today = new Date();
    const month = today.getMonth() + 1;
    const q = month <= 3 ? 1 : month <= 6 ? 2 : month <= 9 ? 3 : 4;
    const label = await appPrompt('새 진단 세션의 이름:', `${today.getFullYear()}-${q}Q`);
    if (label !== null) addSession(label.trim() || `${today.getFullYear()}-${q}Q`, q);
  };

  const handleRename = async (id, currentLabel) => {
    const next = await appPrompt('세션 이름을 수정하세요:', currentLabel);
    if (next !== null && next.trim()) updateSessionMeta(id, { label: next.trim() });
  };

  const handleRemove = async (id, label) => {
    if (sessions.length <= 1) {
      await appAlert('마지막 세션은 삭제할 수 없습니다.');
      return;
    }
    if (await appConfirm(`"${label}" 세션의 모든 점수를 삭제하시겠습니까?`)) {
      removeSession(id);
    }
  };

  const handleDesignate = (id, currentDes) => {
    // pre → post → null → pre 순환
    const next = currentDes === null ? 'pre' : currentDes === 'pre' ? 'post' : null;
    setSessionDesignation(id, next);
  };

  return (
    <div className="session-tabs-container no-print">
      <div className="session-tabs-header">
        <span className="session-tabs-label">📊 진단 세션</span>
        <span className="session-tabs-hint">분기별로 새 세션을 만들어 진전을 추적하세요. 두 세션을 사전/사후로 지정하면 비교 분석이 가능합니다.</span>
      </div>
      <div className="session-tabs">
        {sessions.map((s) => (
          <div
            key={s.id}
            className={`session-tab ${s.id === activeId ? 'active' : ''} ${s.designation ? 'designated ' + s.designation : ''}`}
          >
            <button
              className="session-tab-main"
              onClick={() => switchSession(s.id)}
              onDoubleClick={() => handleRename(s.id, s.label)}
              title={`더블클릭: 이름 변경 · 클릭: 전환`}
            >
              {s.designation === 'pre' && <span className="session-badge pre">사전</span>}
              {s.designation === 'post' && <span className="session-badge post">사후</span>}
              <span className="session-tab-name">{s.label}</span>
              <span className="session-tab-meta">
                {Object.keys(s.scores || {}).length}항목
              </span>
            </button>
            <button
              className="session-tab-designate"
              onClick={() => handleDesignate(s.id, s.designation)}
              title={`현재: ${s.designation || '미지정'} · 클릭하여 변경`}
            >
              ⚐
            </button>
            <button
              className="session-tab-remove"
              onClick={() => handleRemove(s.id, s.label)}
              title="세션 삭제"
            >×</button>
          </div>
        ))}
        <button className="session-tab-add" onClick={handleAdd}>+ 새 세션</button>
      </div>
    </div>
  );
}

// =====================================================================
// ProgressTimelineChart — 모든 진단 세션을 시간순으로 시각화
// =====================================================================
function ProgressTimelineChart({ ws, stageData }) {
  const sessions = useMemo(() => {
    const list = [...(ws._allSessions || [])];
    // 날짜순 정렬
    list.sort((a, b) => (a.date || '').localeCompare(b.date || ''));
    return list;
  }, [ws._allSessions]);

  // 영역별 점수 시계열 계산
  const seriesData = useMemo(() => {
    if (!stageData || sessions.length === 0) return null;
    const series = {};
    Object.entries(stageData).forEach(([key, domain]) => {
      series[key] = {
        label: domain.label,
        max: domain.maxScore,
        points: sessions.map((s) => {
          let sum = 0;
          domain.groups.forEach((g) => g.items.forEach((it) => {
            const v = (s.scores || {})[it.id];
            if (typeof v === 'number') sum += v;
          }));
          return { x: s.label, y: sum, date: s.date, sessionId: s.id, designation: s.designation };
        }),
      };
    });
    return series;
  }, [sessions, stageData]);

  if (sessions.length < 2) {
    return (
      <div className="empty-hint" style={{ padding: 20, textAlign: 'center' }}>
        진전 추적은 진단 세션이 <strong>2개 이상</strong> 있어야 표시됩니다.<br />
        진단 탭에서 새 세션을 추가하여 분기별로 진단을 누적해 보세요.
      </div>
    );
  }

  if (!seriesData) return null;

  // SVG 차트 크기
  const W = 720, H = 320;
  const padding = { top: 30, right: 100, bottom: 50, left: 50 };
  const innerW = W - padding.left - padding.right;
  const innerH = H - padding.top - padding.bottom;
  const n = sessions.length;
  const maxScore = Math.max(...Object.values(seriesData).map((s) => s.max));

  // 색상 매핑
  const colorMap = {
    joinAttention: '#2d4a3e',
    symbolUse: '#5a7d6f',
    mutualReg: '#c19a3a',
    selfReg: '#a17d2b',
    interpersonalSupport: '#7d4a3a',
    learningSupport: '#a07060',
  };

  const xStep = n > 1 ? innerW / (n - 1) : innerW;
  const xAt = (i) => padding.left + i * xStep;
  const yAt = (score, max) => padding.top + innerH - (score / max) * innerH;

  return (
    <div className="progress-timeline-wrap">
      <div className="timeline-header">
        <h3 className="report-h3" style={{ marginBottom: 4 }}>영역별 진전 추적</h3>
        <p className="hint">{sessions.length}개 진단 세션에 걸친 영역별 점수 변화입니다. ◆ 사전 / ▲ 사후 지정 세션은 표시됩니다.</p>
      </div>
      <svg viewBox={`0 0 ${W} ${H}`} className="timeline-chart">
        {/* 그리드 (4분할) */}
        {[0, 0.25, 0.5, 0.75, 1].map((t) => (
          <g key={t}>
            <line
              x1={padding.left} y1={padding.top + innerH * t}
              x2={padding.left + innerW} y2={padding.top + innerH * t}
              stroke="#e6e0cd" strokeDasharray={t === 0 || t === 1 ? '' : '3 3'}
            />
            <text x={padding.left - 8} y={padding.top + innerH * t} textAnchor="end" dominantBaseline="middle" className="timeline-axis-label">
              {Math.round((1 - t) * 100)}%
            </text>
          </g>
        ))}
        {/* X축 라벨 */}
        {sessions.map((s, i) => (
          <g key={s.id}>
            <text
              x={xAt(i)} y={padding.top + innerH + 20}
              textAnchor="middle" className="timeline-x-label"
            >
              {s.label}
            </text>
            {s.designation && (
              <text
                x={xAt(i)} y={padding.top + innerH + 36}
                textAnchor="middle" className="timeline-designation"
                fill={s.designation === 'pre' ? '#c19a3a' : '#2d4a3e'}
              >
                {s.designation === 'pre' ? '◆ 사전' : '▲ 사후'}
              </text>
            )}
          </g>
        ))}
        {/* 데이터 라인 (영역별) */}
        {Object.entries(seriesData).map(([key, ser]) => {
          const color = colorMap[key] || '#888';
          const points = ser.points.map((p, i) => `${xAt(i)},${yAt(p.y, ser.max)}`).join(' ');
          return (
            <g key={key}>
              <polyline points={points} fill="none" stroke={color} strokeWidth="2" />
              {ser.points.map((p, i) => (
                <circle
                  key={i}
                  cx={xAt(i)} cy={yAt(p.y, ser.max)} r="4"
                  fill={color} stroke="#fff" strokeWidth="1.5"
                />
              ))}
            </g>
          );
        })}
        {/* 범례 */}
        {Object.entries(seriesData).map(([key, ser], i) => {
          const color = colorMap[key] || '#888';
          const ly = padding.top + i * 18;
          return (
            <g key={key}>
              <line x1={W - padding.right + 10} y1={ly} x2={W - padding.right + 25} y2={ly} stroke={color} strokeWidth="3" />
              <text x={W - padding.right + 30} y={ly} dominantBaseline="middle" className="timeline-legend">
                {ser.label.replace(/\s*\(.*\)/, '')}
              </text>
            </g>
          );
        })}
      </svg>
    </div>
  );
}

// =====================================================================
// SES 진전 추적 (사회-정서 지표 시계열)
// =====================================================================
function SesProgressTimeline({ ws }) {
  const sessions = useMemo(() => {
    const list = [...(ws._allSessions || [])];
    list.sort((a, b) => (a.date || '').localeCompare(b.date || ''));
    return list.filter((s) => s.ses && Object.keys(s.ses).length > 0);
  }, [ws._allSessions]);

  if (sessions.length < 2) return null;

  const W = 720, H = 320;
  const padding = { top: 30, right: 220, bottom: 50, left: 50 };
  const innerW = W - padding.left - padding.right;
  const innerH = H - padding.top - padding.bottom;
  const n = sessions.length;
  const xStep = n > 1 ? innerW / (n - 1) : innerW;
  const xAt = (i) => padding.left + i * xStep;
  const yAt = (v) => padding.top + innerH - (v / 10) * innerH;

  const colors = ['#2d4a3e', '#c19a3a', '#7d4a3a', '#5a7d6f', '#a17d2b', '#a07060', '#3a6f5e', '#8a6630'];

  return (
    <div className="progress-timeline-wrap" style={{ marginTop: 24 }}>
      <h3 className="report-h3" style={{ marginBottom: 4 }}>사회-정서 성장 지표 진전</h3>
      <p className="hint">{sessions.length}개 세션의 8개 지표 변화입니다.</p>
      <svg viewBox={`0 0 ${W} ${H}`} className="timeline-chart">
        {[0, 0.25, 0.5, 0.75, 1].map((t) => (
          <line key={t}
            x1={padding.left} y1={padding.top + innerH * t}
            x2={padding.left + innerW} y2={padding.top + innerH * t}
            stroke="#e6e0cd" strokeDasharray={t === 0 || t === 1 ? '' : '3 3'} />
        ))}
        {[0, 5, 10].map((v) => (
          <text key={v} x={padding.left - 8} y={yAt(v)} textAnchor="end" dominantBaseline="middle" className="timeline-axis-label">{v}</text>
        ))}
        {sessions.map((s, i) => (
          <text key={s.id} x={xAt(i)} y={padding.top + innerH + 20} textAnchor="middle" className="timeline-x-label">
            {s.label}
          </text>
        ))}
        {SES_INDICATORS.map((ind, idx) => {
          const color = colors[idx % colors.length];
          const points = sessions.map((s, i) => `${xAt(i)},${yAt((s.ses && s.ses[ind.id]) || 0)}`).join(' ');
          return (
            <g key={ind.id}>
              <polyline points={points} fill="none" stroke={color} strokeWidth="1.8" />
              {sessions.map((s, i) => (
                <circle key={i} cx={xAt(i)} cy={yAt((s.ses && s.ses[ind.id]) || 0)} r="3" fill={color} stroke="#fff" strokeWidth="1" />
              ))}
              <line x1={W - padding.right + 10} y1={padding.top + idx * 16} x2={W - padding.right + 25} y2={padding.top + idx * 16} stroke={color} strokeWidth="2.5" />
              <text x={W - padding.right + 30} y={padding.top + idx * 16} dominantBaseline="middle" className="timeline-legend">
                {ind.label}
              </text>
            </g>
          );
        })}
      </svg>
    </div>
  );
}

// =====================================================================
// IEP 목표별 진전 추적 — 선정된 목표가 시간에 따라 어떻게 변하는가
// =====================================================================
function GoalProgressTable({ ws, stageData }) {
  const sessions = useMemo(() => {
    const list = [...(ws._allSessions || [])];
    list.sort((a, b) => (a.date || '').localeCompare(b.date || ''));
    return list;
  }, [ws._allSessions]);

  const selectedGoals = ws.iep?.selectedGoals || [];

  if (selectedGoals.length === 0) {
    return (
      <div className="empty-hint" style={{ padding: 16 }}>
        IEP에서 우선 목표를 선정하면 목표별 진전이 표시됩니다.
      </div>
    );
  }
  if (sessions.length < 2) return null;

  // 목표별 영역 정보 가져오기
  const itemDomainMap = {};
  Object.entries(stageData || {}).forEach(([dkey, domain]) => {
    domain.groups.forEach((g) => g.items.forEach((it) => {
      itemDomainMap[it.id] = { domain: domain.label, label: it.label };
    }));
  });

  return (
    <div className="goal-progress-table" style={{ marginTop: 24 }}>
      <h3 className="report-h3" style={{ marginBottom: 4 }}>IEP 우선 목표 진전</h3>
      <p className="hint">선정된 {selectedGoals.length}개 목표의 분기별 점수 변화입니다.</p>
      <table className="report-table" style={{ marginTop: 12 }}>
        <thead>
          <tr>
            <th style={{ width: '8%' }}>항목</th>
            <th style={{ width: '32%' }}>목표</th>
            {sessions.map((s) => (
              <th key={s.id} style={{ textAlign: 'center' }}>
                {s.label}
                {s.designation && <div style={{ fontSize: 10, fontWeight: 400 }}>{s.designation === 'pre' ? '사전' : '사후'}</div>}
              </th>
            ))}
            <th style={{ width: '8%', textAlign: 'center' }}>변화</th>
          </tr>
        </thead>
        <tbody>
          {selectedGoals.map((g) => {
            const info = itemDomainMap[g.id];
            const pts = sessions.map((s) => (s.scores || {})[g.id]);
            const first = pts.find((v) => typeof v === 'number');
            const last = [...pts].reverse().find((v) => typeof v === 'number');
            const delta = (typeof first === 'number' && typeof last === 'number') ? last - first : null;
            return (
              <tr key={g.id}>
                <td style={{ fontFamily: "'Gowun Batang', serif", color: '#2d4a3e' }}><strong>{g.id}</strong></td>
                <td>{g.customGoal || (info && info.label) || g.label || ''}</td>
                {pts.map((v, i) => (
                  <td key={i} style={{ textAlign: 'center' }}>
                    {typeof v === 'number' ? (
                      <span className={`mini-pip score-${v}`}>{v}</span>
                    ) : <span style={{ color: '#b5a888' }}>—</span>}
                  </td>
                ))}
                <td style={{ textAlign: 'center' }}>
                  {delta === null ? '—' : (
                    <span className={delta > 0 ? 'delta-up' : delta < 0 ? 'delta-down' : 'delta-same'}>
                      {delta > 0 ? `+${delta}` : delta}
                    </span>
                  )}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

// =====================================================================
// ActivityStats — 회기 일지 누적 통계
// 도달 평가 +/+−/− 카운트, 정체 목표 식별, 회기 빈도
// =====================================================================
// =====================================================================
// SCERTS SAP 요약지 — 분기별 4지점 영역별 점수 + IEP 목표 도달 한 페이지
// 보호자·팀 미팅 인쇄용 (SCERTS 진단 요약지 양식 기반)
// =====================================================================
function SapSummary({ ws }) {
  const stageData = STAGE_DATA[ws.meta.stage];
  const sessions = useMemo(() => {
    const list = [...(ws._allSessions || [])];
    list.sort((a, b) => (a.date || '').localeCompare(b.date || ''));
    return list;
  }, [ws._allSessions]);

  if (!stageData) {
    return <div className="empty-hint" style={{ padding: 24 }}>단계가 결정되어야 SAP 요약지가 생성됩니다.</div>;
  }
  if (sessions.length === 0) {
    return <div className="empty-hint" style={{ padding: 24 }}>진단 세션이 1개 이상 있어야 SAP 요약지가 생성됩니다.</div>;
  }

  // 각 세션별 영역 점수와 백분율 계산
  const sessionData = sessions.map((s) => {
    const domainScores = {};
    Object.entries(stageData).forEach(([key, d]) => {
      let sum = 0;
      d.groups.forEach((g) => g.items.forEach((it) => {
        const v = (s.scores || {})[it.id];
        if (typeof v === 'number') sum += v;
      }));
      domainScores[key] = { score: sum, max: d.maxScore, pct: d.maxScore ? Math.round((sum/d.maxScore)*100) : 0 };
    });
    return { session: s, domains: domainScores };
  });

  // 상위 영역 그룹 (SC, ER, TS) 합산
  const groupScore = (domains, keys) => {
    const sum = keys.reduce((a, k) => a + (domains[k]?.score || 0), 0);
    const max = keys.reduce((a, k) => a + (domains[k]?.max || 0), 0);
    return { sum, max, pct: max ? Math.round((sum/max)*100) : 0 };
  };

  return (
    <div id="printable-report" className="printable">
      <div className="no-print" style={{ textAlign: 'right', marginBottom: 16 }}>
        <button className="btn-primary" onClick={printReport}>📄 SAP 요약지 인쇄</button>
      </div>
      <ReportHeader title="SCERTS 진단 요약지 (SAP Summary)" ws={ws} />

      <section className="report-section">
        <h3 className="report-h3">진단 세션 요약</h3>
        <p className="hint" style={{ marginTop: 0 }}>
          {ws.meta.stage === 'social' ? '사회적 파트너' : ws.meta.stage === 'language' ? '언어 파트너' : '대화 파트너'} 단계의
          {sessions.length}개 진단 세션 누적 점수입니다.
        </p>

        <table className="sap-table">
          <thead>
            <tr>
              <th className="sap-area">영역</th>
              {sessionData.map(({ session }) => (
                <th key={session.id} className="sap-session-col">
                  <div className="sap-session-label">{session.label}</div>
                  <div className="sap-session-date">{session.date}</div>
                  {session.designation && (
                    <div className={`sap-session-badge sap-${session.designation}`}>
                      {session.designation === 'pre' ? '사전' : '사후'}
                    </div>
                  )}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {/* 사회 의사소통 그룹 */}
            <tr className="sap-group-row">
              <td colSpan={1 + sessionData.length}><strong>사회 의사소통 (Social Communication)</strong></td>
            </tr>
            <tr>
              <td className="sap-area-name">공동관심 (JA)</td>
              {sessionData.map(({ session, domains }) => (
                <td key={session.id} className="sap-score-cell">
                  <ScoreBlock score={domains.joinAttention} />
                </td>
              ))}
            </tr>
            <tr>
              <td className="sap-area-name">상징 사용 (SU)</td>
              {sessionData.map(({ session, domains }) => (
                <td key={session.id} className="sap-score-cell">
                  <ScoreBlock score={domains.symbolUse} />
                </td>
              ))}
            </tr>
            <tr className="sap-subtotal-row">
              <td className="sap-area-name"><strong>소계</strong></td>
              {sessionData.map(({ session, domains }) => {
                const g = groupScore(domains, ['joinAttention', 'symbolUse']);
                return <td key={session.id} className="sap-score-cell"><ScoreBlock score={g} bold /></td>;
              })}
            </tr>

            {/* 정서 조절 그룹 */}
            <tr className="sap-group-row">
              <td colSpan={1 + sessionData.length}><strong>정서 조절 (Emotional Regulation)</strong></td>
            </tr>
            <tr>
              <td className="sap-area-name">상호조절 (MR)</td>
              {sessionData.map(({ session, domains }) => (
                <td key={session.id} className="sap-score-cell">
                  <ScoreBlock score={domains.mutualReg} />
                </td>
              ))}
            </tr>
            <tr>
              <td className="sap-area-name">자기조절 (SR)</td>
              {sessionData.map(({ session, domains }) => (
                <td key={session.id} className="sap-score-cell">
                  <ScoreBlock score={domains.selfReg} />
                </td>
              ))}
            </tr>
            <tr className="sap-subtotal-row">
              <td className="sap-area-name"><strong>소계</strong></td>
              {sessionData.map(({ session, domains }) => {
                const g = groupScore(domains, ['mutualReg', 'selfReg']);
                return <td key={session.id} className="sap-score-cell"><ScoreBlock score={g} bold /></td>;
              })}
            </tr>

            {/* 교류 지원 그룹 */}
            <tr className="sap-group-row">
              <td colSpan={1 + sessionData.length}><strong>교류 지원 (Transactional Support)</strong></td>
            </tr>
            <tr>
              <td className="sap-area-name">대인관계 지원 (IS)</td>
              {sessionData.map(({ session, domains }) => (
                <td key={session.id} className="sap-score-cell">
                  <ScoreBlock score={domains.interpersonalSupport} />
                </td>
              ))}
            </tr>
            <tr>
              <td className="sap-area-name">학습 지원 (LS)</td>
              {sessionData.map(({ session, domains }) => (
                <td key={session.id} className="sap-score-cell">
                  <ScoreBlock score={domains.learningSupport} />
                </td>
              ))}
            </tr>
            <tr className="sap-subtotal-row">
              <td className="sap-area-name"><strong>소계</strong></td>
              {sessionData.map(({ session, domains }) => {
                const g = groupScore(domains, ['interpersonalSupport', 'learningSupport']);
                return <td key={session.id} className="sap-score-cell"><ScoreBlock score={g} bold /></td>;
              })}
            </tr>

            {/* 전체 총점 */}
            <tr className="sap-total-row">
              <td className="sap-area-name"><strong>전체 총점</strong></td>
              {sessionData.map(({ session, domains }) => {
                const g = groupScore(domains, Object.keys(stageData));
                return <td key={session.id} className="sap-score-cell"><ScoreBlock score={g} bold large /></td>;
              })}
            </tr>
          </tbody>
        </table>
      </section>

      {/* SES 지표 요약 */}
      {sessions.some((s) => Object.keys(s.ses || {}).length > 0) && (
        <section className="report-section">
          <h3 className="report-h3">사회-정서 성장 지표</h3>
          <table className="sap-table">
            <thead>
              <tr>
                <th className="sap-area">지표</th>
                {sessions.map((s) => (
                  <th key={s.id} className="sap-session-col">{s.label}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {SES_INDICATORS.map((ind) => (
                <tr key={ind.id}>
                  <td className="sap-area-name">{ind.label}</td>
                  {sessions.map((s) => {
                    const v = (s.ses || {})[ind.id];
                    return (
                      <td key={s.id} className="sap-score-cell" style={{ textAlign: 'center' }}>
                        {typeof v === 'number' ? (
                          <span style={{ fontFamily: "'Gowun Batang', serif", fontWeight: 700 }}>{v}/10</span>
                        ) : <span style={{ color: '#b5a888' }}>—</span>}
                      </td>
                    );
                  })}
                </tr>
              ))}
            </tbody>
          </table>
        </section>
      )}

      {/* IEP 우선 목표 진전 */}
      {(ws.iep?.selectedGoals || []).length > 0 && (
        <section className="report-section">
          <GoalProgressTable ws={ws} stageData={stageData} />
        </section>
      )}

      {/* 가족 우선순위 */}
      <FamilyPrioritiesReport ws={ws} />

      <ApprovalBlock />
    </div>
  );
}

function ScoreBlock({ score, bold, large }) {
  if (!score || score.max === 0) return <span style={{ color: '#b5a888' }}>—</span>;
  return (
    <div className={`sap-score-block ${bold ? 'sap-bold' : ''} ${large ? 'sap-large' : ''}`}>
      <div className="sap-score-frac">{score.score}/{score.max}</div>
      <div className="sap-score-pct">{score.pct}%</div>
    </div>
  );
}

// =====================================================================
// FamilySupportForm — SCERTS 가족 지원 양식
// 가족과의 협업 계획·전략·교육 기록 (Vol.2 Family Support Plan 기반)
// =====================================================================
function FamilySupportForm({ ws, setWs }) {
  const data = ws.familySupport || {
    meta: { weekOf: '', meetingDate: '', participants: '' },
    currentConcerns: '', childStrengths: '',
    familyGoals: ['', '', ''],
    homeStrategies: [
      { area: '의사소통', strategy: '', whenToUse: '', resourcesNeeded: '' },
      { area: '정서 조절', strategy: '', whenToUse: '', resourcesNeeded: '' },
      { area: '일상 활동', strategy: '', whenToUse: '', resourcesNeeded: '' },
    ],
    educationTopics: [],
    followUp: '', nextMeeting: '',
  };

  const update = (patch) => setWs((s) => ({ ...s, familySupport: { ...data, ...patch } }));
  const updateMeta = (k, v) => update({ meta: { ...data.meta, [k]: v } });
  const updateGoal = (idx, value) => {
    const arr = [...(data.familyGoals || ['', '', ''])];
    arr[idx] = value;
    update({ familyGoals: arr });
  };
  const updateStrategy = (idx, field, value) => {
    const arr = [...(data.homeStrategies || [])];
    arr[idx] = { ...arr[idx], [field]: value };
    update({ homeStrategies: arr });
  };
  const addStrategy = () => {
    update({ homeStrategies: [...(data.homeStrategies || []), { area: '', strategy: '', whenToUse: '', resourcesNeeded: '' }] });
  };
  const removeStrategy = (idx) => {
    update({ homeStrategies: (data.homeStrategies || []).filter((_, i) => i !== idx) });
  };
  const toggleTopic = (topic) => {
    const list = data.educationTopics || [];
    update({ educationTopics: list.includes(topic) ? list.filter((t) => t !== topic) : [...list, topic] });
  };

  // IEP에서 가족 우선순위 가져오기
  const importFromIep = async () => {
    const fp = ws.familyPriorities || {};
    if (!await appConfirm('IEP의 가족 우선순위에서 다음을 자동 인용합니다:\n- 가족 우선순위 → 가족 목표\n- 진단 강점 → 아동 강점\n\n현재 입력이 있으면 보존됩니다. 진행하시겠습니까?')) return;
    const goals = [
      fp.focusOne || '',
      fp.threeMonthHope || '',
      '',
    ];
    update({
      familyGoals: data.familyGoals.map((g, i) => g || goals[i] || ''),
      currentConcerns: data.currentConcerns || fp.additionalInfo || '',
    });
  };

  const educationOptions = [
    'SCERTS 모델 개요',
    '의도적 의사소통의 발달',
    '도전 행동의 이해와 대처',
    '시각적 지원 사용',
    '감각 통합 전략',
    '일상 활동 내 학습 기회',
    '형제자매 지원',
    '지역사회 자원 안내',
  ];

  return (
    <div id="printable-report" className="printable">
      <div className="no-print" style={{ marginBottom: 16, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <button className="btn-ghost" onClick={importFromIep}>📥 IEP에서 가족 우선순위 가져오기</button>
        <button className="btn-primary" onClick={printReport}>📄 가족 지원 계획서 인쇄</button>
      </div>
      <ReportHeader
        title="SCERTS 가족 지원 계획서"
        ws={ws}
        extras={[
          { label: '계획 주간', value: data.meta.weekOf, editable: true, onChange: (v) => updateMeta('weekOf', v) },
          { label: '면담 일자', value: data.meta.meetingDate, editable: true, onChange: (v) => updateMeta('meetingDate', v) },
          { label: '참여자', value: data.meta.participants, editable: true, onChange: (v) => updateMeta('participants', v) },
        ]}
      />

      <section className="report-section">
        <h3 className="report-h3">1. 현재 가족의 관심사 및 아동의 강점</h3>
        <table className="report-table">
          <tbody>
            <tr>
              <th style={{ width: '20%' }}>가족의 주된 관심사·우려</th>
              <td>
                <Editable
                  value={data.currentConcerns}
                  onChange={(v) => update({ currentConcerns: v })}
                  placeholder="현재 가정에서 가장 어려운 부분, 우선적으로 다루고 싶은 영역"
                  multiline minLines={3}
                />
              </td>
            </tr>
            <tr>
              <th>아동의 강점·흥미</th>
              <td>
                <Editable
                  value={data.childStrengths}
                  onChange={(v) => update({ childStrengths: v })}
                  placeholder="가정에서 관찰되는 아동의 강점, 동기 유발 요소"
                  multiline minLines={3}
                />
              </td>
            </tr>
          </tbody>
        </table>
      </section>

      <section className="report-section">
        <h3 className="report-h3">2. 가족이 우선시하는 목표 (3개월)</h3>
        <table className="report-table">
          <thead>
            <tr>
              <th style={{ width: '8%' }}>순위</th>
              <th>가족이 함께 다루고자 하는 목표</th>
            </tr>
          </thead>
          <tbody>
            {(data.familyGoals || ['', '', '']).map((g, i) => (
              <tr key={i}>
                <td style={{ textAlign: 'center', fontFamily: "'Gowun Batang', serif", fontWeight: 700 }}>{i + 1}</td>
                <td>
                  <Editable
                    value={g}
                    onChange={(v) => updateGoal(i, v)}
                    placeholder={`목표 ${i + 1}`}
                    multiline
                  />
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>

      <section className="report-section">
        <div className="section-title-row">
          <h3 className="report-h3">3. 가정 내 적용 전략</h3>
          <button className="btn-ghost btn-small no-print" onClick={addStrategy}>+ 전략 추가</button>
        </div>
        <table className="report-table">
          <thead>
            <tr>
              <th style={{ width: '15%' }}>영역</th>
              <th style={{ width: '35%' }}>구체적 전략</th>
              <th style={{ width: '25%' }}>적용 상황</th>
              <th style={{ width: '20%' }}>필요한 자료/지원</th>
              <th className="no-print" style={{ width: '5%' }}></th>
            </tr>
          </thead>
          <tbody>
            {(data.homeStrategies || []).map((st, i) => (
              <tr key={i}>
                <td>
                  <Editable value={st.area} onChange={(v) => updateStrategy(i, 'area', v)} placeholder="예: 의사소통" />
                </td>
                <td>
                  <Editable value={st.strategy} onChange={(v) => updateStrategy(i, 'strategy', v)} placeholder="구체적인 가정 내 전략" multiline examples={EXAMPLE_BANK.homeStrategy} />
                </td>
                <td>
                  <Editable value={st.whenToUse} onChange={(v) => updateStrategy(i, 'whenToUse', v)} placeholder="예: 식사 시간, 놀이 중" multiline examples={EXAMPLE_BANK.homeWhen} />
                </td>
                <td>
                  <Editable value={st.resourcesNeeded} onChange={(v) => updateStrategy(i, 'resourcesNeeded', v)} placeholder="시각 카드, 타이머 등" multiline examples={EXAMPLE_BANK.homeResources} />
                </td>
                <td className="no-print" style={{ textAlign: 'center' }}>
                  <button className="btn-icon" onClick={() => removeStrategy(i)} title="삭제">×</button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>

      <section className="report-section">
        <h3 className="report-h3">4. 가족 교육·정보 제공 주제</h3>
        <p className="hint" style={{ marginTop: 0 }}>이번 기간 동안 다룰 교육 주제를 선택하세요.</p>
        <div className="education-topics">
          {educationOptions.map((topic) => (
            <label key={topic} className={`topic-chip ${(data.educationTopics || []).includes(topic) ? 'selected' : ''}`}>
              <input
                type="checkbox"
                checked={(data.educationTopics || []).includes(topic)}
                onChange={() => toggleTopic(topic)}
              />
              <span>{topic}</span>
            </label>
          ))}
        </div>
      </section>

      <section className="report-section">
        <h3 className="report-h3">5. 후속 조치 및 다음 면담</h3>
        <table className="report-table">
          <tbody>
            <tr>
              <th style={{ width: '20%' }}>후속 조치 사항</th>
              <td>
                <Editable
                  value={data.followUp}
                  onChange={(v) => update({ followUp: v })}
                  placeholder="가정에서 시도해 볼 활동, 다음 면담까지 관찰할 점"
                  multiline minLines={3}
                />
              </td>
            </tr>
            <tr>
              <th>다음 면담 일정</th>
              <td>
                <Editable
                  value={data.nextMeeting}
                  onChange={(v) => update({ nextMeeting: v })}
                  placeholder="예: 2024-12-15, 화상 면담"
                />
              </td>
            </tr>
          </tbody>
        </table>
      </section>

      <ApprovalBlock />
    </div>
  );
}

// =====================================================================
// ProfSupportForm — SCERTS 전문가 협력 양식
// 다학제 팀의 협업·역할·소통 기록 (Vol.2 Professional Support Plan 기반)
// =====================================================================
function ProfSupportForm({ ws, setWs }) {
  const data = ws.profSupport || {
    meta: { weekOf: '', meetingDate: '', teamMembers: '' },
    sharedObservations: '', currentChallenges: '',
    collaborativeGoals: ['', '', ''],
    roleResponsibilities: [
      { role: '주 치료사', name: '', responsibilities: '' },
      { role: '담임 교사', name: '', responsibilities: '' },
      { role: '부모', name: '', responsibilities: '' },
    ],
    communicationPlan: '', caseConferenceNotes: '', nextReview: '',
  };

  const update = (patch) => setWs((s) => ({ ...s, profSupport: { ...data, ...patch } }));
  const updateMeta = (k, v) => update({ meta: { ...data.meta, [k]: v } });
  const updateGoal = (idx, value) => {
    const arr = [...(data.collaborativeGoals || ['', '', ''])];
    arr[idx] = value;
    update({ collaborativeGoals: arr });
  };
  const updateRole = (idx, field, value) => {
    const arr = [...(data.roleResponsibilities || [])];
    arr[idx] = { ...arr[idx], [field]: value };
    update({ roleResponsibilities: arr });
  };
  const addRole = () => {
    update({ roleResponsibilities: [...(data.roleResponsibilities || []), { role: '', name: '', responsibilities: '' }] });
  };
  const removeRole = (idx) => {
    update({ roleResponsibilities: (data.roleResponsibilities || []).filter((_, i) => i !== idx) });
  };

  return (
    <div id="printable-report" className="printable">
      <div className="no-print" style={{ marginBottom: 16, textAlign: 'right' }}>
        <button className="btn-primary" onClick={printReport}>📄 전문가 협력 계획서 인쇄</button>
      </div>
      <ReportHeader
        title="SCERTS 전문가 협력 계획서"
        ws={ws}
        extras={[
          { label: '계획 주간', value: data.meta.weekOf, editable: true, onChange: (v) => updateMeta('weekOf', v) },
          { label: '회의 일자', value: data.meta.meetingDate, editable: true, onChange: (v) => updateMeta('meetingDate', v) },
          { label: '팀 구성원', value: data.meta.teamMembers, editable: true, onChange: (v) => updateMeta('teamMembers', v) },
        ]}
      />

      <section className="report-section">
        <h3 className="report-h3">1. 팀 공유 관찰 및 현재 과제</h3>
        <table className="report-table">
          <tbody>
            <tr>
              <th style={{ width: '20%' }}>공유된 관찰 내용</th>
              <td>
                <Editable
                  value={data.sharedObservations}
                  onChange={(v) => update({ sharedObservations: v })}
                  placeholder="각 환경(가정/학교/치료실)에서 일관되게 관찰된 패턴"
                  multiline minLines={3}
                />
              </td>
            </tr>
            <tr>
              <th>현재 협업 과제</th>
              <td>
                <Editable
                  value={data.currentChallenges}
                  onChange={(v) => update({ currentChallenges: v })}
                  placeholder="환경 간 전이, 일관성 유지에서 어려움이 있는 부분"
                  multiline minLines={3}
                />
              </td>
            </tr>
          </tbody>
        </table>
      </section>

      <section className="report-section">
        <h3 className="report-h3">2. 팀 공동 목표</h3>
        <table className="report-table">
          <thead>
            <tr>
              <th style={{ width: '8%' }}>순위</th>
              <th>모든 환경에서 일관되게 다룰 목표</th>
            </tr>
          </thead>
          <tbody>
            {(data.collaborativeGoals || ['', '', '']).map((g, i) => (
              <tr key={i}>
                <td style={{ textAlign: 'center', fontFamily: "'Gowun Batang', serif", fontWeight: 700 }}>{i + 1}</td>
                <td>
                  <Editable value={g} onChange={(v) => updateGoal(i, v)} placeholder={`공동 목표 ${i + 1}`} multiline />
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>

      <section className="report-section">
        <div className="section-title-row">
          <h3 className="report-h3">3. 역할 분담 및 책임</h3>
          <button className="btn-ghost btn-small no-print" onClick={addRole}>+ 역할 추가</button>
        </div>
        <table className="report-table">
          <thead>
            <tr>
              <th style={{ width: '18%' }}>역할</th>
              <th style={{ width: '18%' }}>담당자</th>
              <th>구체적 책임 및 활동</th>
              <th className="no-print" style={{ width: '5%' }}></th>
            </tr>
          </thead>
          <tbody>
            {(data.roleResponsibilities || []).map((r, i) => (
              <tr key={i}>
                <td>
                  <Editable value={r.role} onChange={(v) => updateRole(i, 'role', v)} placeholder="예: 언어치료사" />
                </td>
                <td>
                  <Editable value={r.name} onChange={(v) => updateRole(i, 'name', v)} placeholder="이름" />
                </td>
                <td>
                  <Editable value={r.responsibilities} onChange={(v) => updateRole(i, 'responsibilities', v)} placeholder="구체적인 책임과 활동 내용" multiline />
                </td>
                <td className="no-print" style={{ textAlign: 'center' }}>
                  <button className="btn-icon" onClick={() => removeRole(i)} title="삭제">×</button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>

      <section className="report-section">
        <h3 className="report-h3">4. 소통 및 정보 공유 계획</h3>
        <table className="report-table">
          <tbody>
            <tr>
              <th style={{ width: '20%' }}>소통 방법 및 주기</th>
              <td>
                <Editable
                  value={data.communicationPlan}
                  onChange={(v) => update({ communicationPlan: v })}
                  placeholder="예: 주간 알림장, 월 1회 화상 회의, 분기별 사례 회의"
                  multiline minLines={3}
                />
              </td>
            </tr>
            <tr>
              <th>사례 회의 기록</th>
              <td>
                <Editable
                  value={data.caseConferenceNotes}
                  onChange={(v) => update({ caseConferenceNotes: v })}
                  placeholder="이전 회의의 주요 결정사항 및 후속 조치"
                  multiline minLines={4}
                />
              </td>
            </tr>
            <tr>
              <th>다음 검토 일정</th>
              <td>
                <Editable
                  value={data.nextReview}
                  onChange={(v) => update({ nextReview: v })}
                  placeholder="예: 2024-12-20, 사례 회의"
                />
              </td>
            </tr>
          </tbody>
        </table>
      </section>

      <ApprovalBlock />
    </div>
  );
}

// =====================================================================
// DataIntegrityCheck — 진단 점수의 발달적 일관성 검증
// 토대 항목이 0점인데 상위 항목이 2점인 경우 등 자동 감지
// =====================================================================
function DataIntegrityCheck({ ws }) {
  const issues = useMemo(() => {
    if (!ws.meta.stage) return [];
    const stageData = STAGE_DATA[ws.meta.stage];
    const tree = JA_DEVELOPMENT_TREE[ws.meta.stage] || {};
    const scores = ws.assessment?.scores || {};
    const found = [];

    // 1. 발달 의존성 검증: 선행 항목이 0점인데 후행 항목이 1점 이상
    Object.entries(tree).forEach(([itemId, prereqs]) => {
      const itemScore = scores[itemId];
      if (typeof itemScore !== 'number' || itemScore === 0) return;
      prereqs.forEach((pid) => {
        const pScore = scores[pid];
        if (pScore === 0) {
          found.push({
            type: 'dependency',
            severity: itemScore === 2 ? 'high' : 'medium',
            message: `${itemId}이(가) ${itemScore}점인데, 선행 항목 ${pid}이(가) 0점입니다.`,
            hint: '선행 항목이 안정되지 않은 상태에서 후행 항목이 높게 나오면 재확인이 필요합니다.',
          });
        }
      });
    });

    // 2. 영역 내 일관성: 같은 그룹 내 점수 편차가 큰 경우
    Object.entries(stageData || {}).forEach(([dkey, domain]) => {
      domain.groups.forEach((g) => {
        const scoresInGroup = g.items
          .map((it) => scores[it.id])
          .filter((v) => typeof v === 'number');
        if (scoresInGroup.length < 3) return;
        const max = Math.max(...scoresInGroup);
        const min = Math.min(...scoresInGroup);
        if (max === 2 && min === 0 && scoresInGroup.filter((s) => s === 0).length >= 2) {
          found.push({
            type: 'group_variance',
            severity: 'low',
            message: `${domain.label} - ${g.label}에서 2점과 0점이 함께 있습니다 (n=${scoresInGroup.length}).`,
            hint: '같은 그룹 내 점수 편차가 크면 채점 기준 재검토를 권장합니다.',
          });
        }
      });
    });

    // 3. 진단 완료도
    const totalItems = Object.values(stageData || {}).reduce(
      (a, d) => a + d.groups.reduce((b, g) => b + g.items.length, 0), 0,
    );
    const scoredCount = Object.keys(scores).filter((k) => typeof scores[k] === 'number').length;
    const completionPct = totalItems > 0 ? Math.round((scoredCount / totalItems) * 100) : 0;

    if (totalItems > 0 && completionPct < 50 && scoredCount > 0) {
      found.push({
        type: 'completion',
        severity: 'low',
        message: `진단 완료도가 ${completionPct}%입니다 (${scoredCount}/${totalItems}).`,
        hint: '신뢰할 수 있는 자동 분석을 위해 70% 이상의 진단 완료를 권장합니다.',
      });
    }

    return found;
  }, [ws.meta.stage, ws.assessment]);

  if (issues.length === 0) {
    return (
      <div className="integrity-clean">
        <span className="integrity-clean-icon">✓</span>
        <strong>발달적 일관성 확인 완료</strong>
        <span style={{ color: '#6b6452', marginLeft: 8 }}>현재 채점 결과에서 검토가 필요한 패턴이 발견되지 않았습니다.</span>
      </div>
    );
  }

  return (
    <div className="integrity-issues">
      <div className="integrity-header">
        <strong>⚠ {issues.length}개 항목 검토 권장</strong>
        <span className="integrity-hint">진단 신뢰도를 높이기 위해 다음 패턴을 확인해 보세요.</span>
      </div>
      {issues.map((iss, i) => (
        <div key={i} className={`integrity-item severity-${iss.severity}`}>
          <div className="integrity-msg">
            <span className={`integrity-severity sev-${iss.severity}`}>
              {iss.severity === 'high' ? '높음' : iss.severity === 'medium' ? '중간' : '낮음'}
            </span>
            {iss.message}
          </div>
          <div className="integrity-hint-text">{iss.hint}</div>
        </div>
      ))}
    </div>
  );
}

function ActivityStats({ ws }) {
  const logs = ws.activities?.logI || [];

  const stats = useMemo(() => {
    if (logs.length === 0) return null;

    // 목표별 도달 평가 누적
    const goalStats = {};  // {goalText: { '+': n, '+/-': n, '-': n, total }}
    const partnerStats = {};

    const accumulateGoal = (rows, store) => {
      (rows || []).forEach((r) => {
        if (!r || !r.goal) return;
        const key = r.goal;
        if (!store[key]) store[key] = { plus: 0, partial: 0, minus: 0, total: 0, observations: [] };
        const rating = r.rating;
        if (rating === '+') store[key].plus++;
        else if (rating === '+/−' || rating === '+/-') store[key].partial++;
        else if (rating === '−' || rating === '-') store[key].minus++;
        if (rating) store[key].total++;
        if (r.observed) store[key].observations.push(r.observed);
      });
    };

    logs.forEach((log) => {
      accumulateGoal(log.goalsSocial, goalStats);
      accumulateGoal(log.goalsEmo, goalStats);
      accumulateGoal(log.partnerGoals, partnerStats);
    });

    // 회기 빈도 (날짜 분석)
    const datesByMonth = {};
    logs.forEach((log) => {
      if (!log.date) return;
      const ym = log.date.slice(0, 7);
      datesByMonth[ym] = (datesByMonth[ym] || 0) + 1;
    });

    // 도달률 계산 및 분류
    const goalList = Object.entries(goalStats).map(([goal, s]) => {
      const reachRate = s.total > 0 ? (s.plus + s.partial * 0.5) / s.total : 0;
      let status;
      if (s.total === 0) status = 'noData';
      else if (reachRate >= 0.7) status = 'mastered';
      else if (reachRate >= 0.4) status = 'progressing';
      else if (s.total >= 3 && reachRate < 0.3) status = 'stalled';
      else status = 'early';
      return { goal, ...s, reachRate, status };
    }).sort((a, b) => b.reachRate - a.reachRate);

    const partnerList = Object.entries(partnerStats).map(([goal, s]) => {
      const reachRate = s.total > 0 ? (s.plus + s.partial * 0.5) / s.total : 0;
      return { goal, ...s, reachRate };
    });

    return {
      totalSessions: logs.length,
      goalCount: goalList.length,
      goalList,
      partnerList,
      datesByMonth,
      masteredCount: goalList.filter((g) => g.status === 'mastered').length,
      stalledCount: goalList.filter((g) => g.status === 'stalled').length,
    };
  }, [logs]);

  if (!stats || stats.totalSessions === 0) {
    return (
      <div className="empty-hint" style={{ padding: 30, textAlign: 'center' }}>
        아직 기록된 회기가 없습니다.<br />
        '회기별 활동 일지' 탭에서 회기를 추가하면 통계가 자동으로 생성됩니다.
      </div>
    );
  }

  return (
    <div className="activity-stats">
      {/* 요약 카드 */}
      <div className="stats-summary-grid">
        <div className="stats-summary-card">
          <div className="stats-num">{stats.totalSessions}</div>
          <div className="stats-label">기록된 회기</div>
        </div>
        <div className="stats-summary-card">
          <div className="stats-num">{stats.goalCount}</div>
          <div className="stats-label">추적 중인 목표</div>
        </div>
        <div className="stats-summary-card mastered">
          <div className="stats-num">{stats.masteredCount}</div>
          <div className="stats-label">숙달 단계 목표</div>
        </div>
        <div className="stats-summary-card stalled">
          <div className="stats-num">{stats.stalledCount}</div>
          <div className="stats-label">정체된 목표</div>
        </div>
      </div>

      {/* 정체된 목표 알림 */}
      {stats.stalledCount > 0 && (
        <div className="info-box" style={{ borderColor: '#b54a3a', background: '#fef0e0' }}>
          <strong>⚠ 정체된 목표 {stats.stalledCount}개 발견</strong><br />
          최소 3회기 이상 기록되었으나 도달률이 30% 미만인 목표입니다.
          전략·환경 변경을 고려해 보세요.
        </div>
      )}

      {/* 아동 목표별 통계 */}
      <section className="report-section">
        <h3 className="report-h3">아동 목표별 도달 통계</h3>
        <table className="report-table stats-table">
          <thead>
            <tr>
              <th style={{ width: '40%' }}>목표</th>
              <th style={{ textAlign: 'center' }}>+</th>
              <th style={{ textAlign: 'center' }}>+/−</th>
              <th style={{ textAlign: 'center' }}>−</th>
              <th style={{ textAlign: 'center' }}>도달률</th>
              <th style={{ textAlign: 'center' }}>상태</th>
            </tr>
          </thead>
          <tbody>
            {stats.goalList.length === 0 && (
              <tr><td colSpan={6} style={{ textAlign: 'center', padding: 20, color: '#6b6452' }}>아직 평가가 기록된 목표가 없습니다.</td></tr>
            )}
            {stats.goalList.map((g, i) => (
              <tr key={i} className={`stats-row stats-row-${g.status}`}>
                <td>{g.goal}</td>
                <td style={{ textAlign: 'center' }}>
                  {g.plus > 0 && <span className="rating-cell plus">{g.plus}</span>}
                </td>
                <td style={{ textAlign: 'center' }}>
                  {g.partial > 0 && <span className="rating-cell partial">{g.partial}</span>}
                </td>
                <td style={{ textAlign: 'center' }}>
                  {g.minus > 0 && <span className="rating-cell minus">{g.minus}</span>}
                </td>
                <td style={{ textAlign: 'center', fontFamily: "'Gowun Batang', serif", fontWeight: 700 }}>
                  {g.total > 0 ? `${Math.round(g.reachRate * 100)}%` : '—'}
                </td>
                <td style={{ textAlign: 'center' }}>
                  <span className={`status-badge status-${g.status}`}>
                    {g.status === 'mastered' && '🟢 숙달'}
                    {g.status === 'progressing' && '🟡 진전 중'}
                    {g.status === 'stalled' && '🔴 정체'}
                    {g.status === 'early' && '⚪ 초기'}
                    {g.status === 'noData' && '— 미평가'}
                  </span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>

      {/* 파트너 목표별 통계 */}
      {stats.partnerList.length > 0 && (
        <section className="report-section">
          <h3 className="report-h3">파트너 교류 지원 전략 효과</h3>
          <table className="report-table stats-table">
            <thead>
              <tr>
                <th style={{ width: '60%' }}>전략</th>
                <th style={{ textAlign: 'center' }}>회기 적용</th>
                <th style={{ textAlign: 'center' }}>효과</th>
              </tr>
            </thead>
            <tbody>
              {stats.partnerList.map((p, i) => (
                <tr key={i}>
                  <td>{p.goal}</td>
                  <td style={{ textAlign: 'center' }}>{p.total}회</td>
                  <td style={{ textAlign: 'center', fontFamily: "'Gowun Batang', serif", fontWeight: 700 }}>
                    {p.total > 0 ? `${Math.round(p.reachRate * 100)}%` : '—'}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </section>
      )}

      {/* 월별 회기 분포 */}
      <section className="report-section">
        <h3 className="report-h3">월별 회기 분포</h3>
        <div className="month-distribution">
          {Object.entries(stats.datesByMonth)
            .sort(([a], [b]) => a.localeCompare(b))
            .map(([month, count]) => (
              <div key={month} className="month-bar">
                <div className="month-label">{month}</div>
                <div className="month-bar-bar">
                  <div className="month-bar-fill" style={{ width: `${Math.min(100, count * 12)}%` }}>
                    {count}회
                  </div>
                </div>
              </div>
            ))
          }
          {Object.keys(stats.datesByMonth).length === 0 && (
            <div className="empty-hint" style={{ padding: 16 }}>날짜가 기록된 회기가 없습니다.</div>
          )}
        </div>
      </section>
    </div>
  );
}

// =====================================================================
// BackupPanel — 자동 백업 슬롯 표시 및 복원
// =====================================================================
function BackupPanel({ onRestore, onClose }) {
  const [backups, setBackups] = useState(loadBackups);

  const refresh = () => setBackups(loadBackups());

  const handleDelete = async (id) => {
    if (!await appConfirm('이 백업을 삭제하시겠습니까?')) return;
    removeBackup(id);
    refresh();
  };

  const formatTimeAgo = (ts) => {
    const diff = Date.now() - ts;
    const m = Math.floor(diff / 60000);
    if (m < 1) return '방금 전';
    if (m < 60) return `${m}분 전`;
    const h = Math.floor(m / 60);
    if (h < 24) return `${h}시간 전`;
    const d = Math.floor(h / 24);
    return `${d}일 전`;
  };

  return (
    <div className="backup-panel-overlay" onClick={onClose}>
      <div className="backup-panel" onClick={(e) => e.stopPropagation()}>
        <div className="backup-panel-header">
          <h2>자동 백업 슬롯</h2>
          <button className="backup-close-btn" onClick={onClose}>×</button>
        </div>
        <p className="hint" style={{ margin: '0 20px 16px' }}>
          5분 간격으로 자동 저장된 백업 슬롯 (최대 {MAX_BACKUPS}개)입니다.
          실수로 데이터를 잃었거나 이전 상태로 되돌리고 싶을 때 사용하세요.
        </p>

        {backups.length === 0 && (
          <div className="empty-hint" style={{ margin: '0 20px 20px' }}>
            아직 자동 백업이 없습니다. 작업하면서 자동으로 누적됩니다.
          </div>
        )}

        <div className="backup-list">
          {backups.map((b, i) => (
            <div key={b.id} className="backup-item">
              <div className="backup-item-info">
                <div className="backup-item-time">
                  <strong>{formatTimeAgo(b.timestamp)}</strong>
                  <span className="backup-item-date">{new Date(b.timestamp).toLocaleString('ko-KR')}</span>
                </div>
                <div className="backup-item-meta">
                  {b.childCount}명 · 최근 활성: {b.activeChildName || '(이름 없음)'}
                </div>
              </div>
              <div className="backup-item-actions">
                <button className="btn-ghost btn-small" onClick={() => { onRestore(b); onClose(); }}>복원</button>
                <button className="btn-icon" onClick={() => handleDelete(b.id)} title="삭제">×</button>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

// =====================================================================
// EmptyStateGuide — 빈 상태에서 사용자 안내
// =====================================================================
function EmptyStateGuide({ onStart }) {
  return (
    <section className="empty-state-guide">
      <div className="esg-icon">🌱</div>
      <h2 className="esg-title">SCERTS 자동화에 오신 것을 환영합니다</h2>
      <p className="esg-sub">
        진단부터 보고서까지, 한 화면에서 임상 워크플로우를 진행합니다.
      </p>
      <div className="esg-steps">
        <div className="esg-step">
          <div className="esg-step-num">1</div>
          <div className="esg-step-body">
            <div className="esg-step-title">아동 정보 입력</div>
            <div className="esg-step-desc">아래에 아동 이름과 기본 정보를 입력하세요.</div>
          </div>
        </div>
        <div className="esg-step">
          <div className="esg-step-num">2</div>
          <div className="esg-step-body">
            <div className="esg-step-title">단계 결정</div>
            <div className="esg-step-desc">사회적/언어/대화 파트너 중 어느 단계인지 결정 기록지에서 확인합니다.</div>
          </div>
        </div>
        <div className="esg-step">
          <div className="esg-step-num">3</div>
          <div className="esg-step-body">
            <div className="esg-step-title">질문지 + 진단 채점</div>
            <div className="esg-step-desc">보호자 질문지에 답하고 항목별 채점을 진행하면, 다음 단계가 자동으로 채워집니다.</div>
          </div>
        </div>
        <div className="esg-step">
          <div className="esg-step-num">4</div>
          <div className="esg-step-body">
            <div className="esg-step-title">IEP · 중간보고서 자동 생성</div>
            <div className="esg-step-desc">진단 결과로 IEP가 자동 추천되고, 분기마다 새 세션을 추가하면 진전이 시각화됩니다.</div>
          </div>
        </div>
      </div>
      <button className="btn-primary esg-cta" onClick={onStart}>아동 정보부터 시작하기</button>
      <div className="esg-tips">
        <strong>💡 알아두면 좋은 점</strong>
        <ul>
          <li>모든 작업은 자동 저장됩니다. 닫았다 다시 열어도 그대로입니다.</li>
          <li>5분 간격으로 자동 백업되어 실수 시 복원할 수 있습니다.</li>
          <li>여러 아동을 한 시스템에서 관리할 수 있습니다 (우측 상단 드롭다운).</li>
          <li>Ctrl/Cmd+Z로 되돌리기, Ctrl/Cmd+Shift+Z로 다시 실행이 가능합니다.</li>
        </ul>
      </div>
    </section>
  );
}

// =====================================================================
// CommunicationScheduleForm — SCERTS 의사소통 일과 양식
// 하루 일과 중 자연스러운 의사소통 기회 분석 (SCERTS Vol.2 Communication Schedule)
// =====================================================================
function CommunicationScheduleForm({ ws, setWs, showToast }) {
  const data = ws.communicationSchedule || {
    meta: { observedBy: '', observedAt: '', setting: '' },
    activities: [
      { id: 'a_arrival', time: '08:30-09:00', name: '등원', opportunities: '', currentBehavior: '', supports: '', goals: '' },
      { id: 'a_circle', time: '09:00-09:30', name: '오전 모임', opportunities: '', currentBehavior: '', supports: '', goals: '' },
      { id: 'a_free', time: '09:30-10:30', name: '자유 놀이', opportunities: '', currentBehavior: '', supports: '', goals: '' },
      { id: 'a_snack', time: '10:30-11:00', name: '간식', opportunities: '', currentBehavior: '', supports: '', goals: '' },
      { id: 'a_outdoor', time: '11:00-12:00', name: '실외 활동', opportunities: '', currentBehavior: '', supports: '', goals: '' },
      { id: 'a_lunch', time: '12:00-13:00', name: '점심 / 휴식', opportunities: '', currentBehavior: '', supports: '', goals: '' },
      { id: 'a_dismiss', time: '13:00-13:30', name: '하원 준비', opportunities: '', currentBehavior: '', supports: '', goals: '' },
    ],
    summary: '', keyOpportunities: '',
  };

  const update = (patch) => setWs((s) => ({
    ...s, communicationSchedule: { ...data, ...patch },
  }));
  const updateMeta = (k, v) => update({ meta: { ...data.meta, [k]: v } });
  const updateActivity = (id, field, value) => {
    update({
      activities: (data.activities || []).map((a) => a.id === id ? { ...a, [field]: value } : a),
    });
  };
  const addActivity = () => {
    update({
      activities: [...(data.activities || []), {
        id: 'a_' + Date.now(),
        time: '', name: '', opportunities: '',
        currentBehavior: '', supports: '', goals: '',
      }],
    });
  };
  const removeActivity = async (id) => {
    if (!await appConfirm('이 일과 행을 삭제하시겠습니까?')) return;
    update({ activities: (data.activities || []).filter((a) => a.id !== id) });
  };
  const moveActivity = (idx, direction) => {
    const arr = [...(data.activities || [])];
    const newIdx = idx + direction;
    if (newIdx < 0 || newIdx >= arr.length) return;
    [arr[idx], arr[newIdx]] = [arr[newIdx], arr[idx]];
    update({ activities: arr });
  };

  // IEP 우선 목표를 가져와 채워 넣기
  const importIepGoals = async () => {
    const goals = (ws.iep?.selectedGoals || [])
      .map((g) => g.customGoal || g.label)
      .filter(Boolean)
      .slice(0, 8)
      .join('\n• ');
    if (!goals) {
      if (showToast) showToast('IEP에서 선정된 목표가 없습니다');
      return;
    }
    if (!await appConfirm(`IEP 우선 목표 ${(ws.iep?.selectedGoals || []).length}개를 "주요 의사소통 기회" 필드에 추가합니다.\n진행하시겠습니까?`)) return;
    update({
      keyOpportunities: data.keyOpportunities
        ? `${data.keyOpportunities}\n\n[IEP 우선 목표]\n• ${goals}`
        : `[IEP 우선 목표]\n• ${goals}`,
    });
    if (showToast) showToast('IEP 목표가 추가되었습니다');
  };

  return (
    <div id="printable-report" className="printable">
      <div className="no-print" style={{ marginBottom: 16, display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 12, flexWrap: 'wrap' }}>
        <button className="btn-ghost" onClick={importIepGoals}>📥 IEP 우선 목표 가져오기</button>
        <button className="btn-primary" onClick={printReport}>📄 의사소통 일과 분석 인쇄</button>
      </div>
      <ReportHeader
        title="SCERTS 의사소통 일과 분석"
        ws={ws}
        extras={[
          { label: '관찰자', value: data.meta.observedBy, editable: true, onChange: (v) => updateMeta('observedBy', v) },
          { label: '관찰 일자', value: data.meta.observedAt, editable: true, onChange: (v) => updateMeta('observedAt', v) },
          { label: '환경', value: data.meta.setting, editable: true, onChange: (v) => updateMeta('setting', v) },
        ]}
      />

      <div className="info-box no-print">
        <strong>의사소통 일과 분석이란?</strong><br />
        하루 일과를 시간대별로 나누어, 각 활동에서 <em>자연스럽게 발생하는 의사소통 기회</em>를 파악합니다.
        분리된 치료 시간에서가 아니라, 일상 일과 속에서 의사소통이 일어날 수 있는 모든 순간을 찾아내고
        해당 시점에 어떤 파트너 지원이 필요한지 계획하는 것이 SCERTS 모델의 핵심입니다.
      </div>

      <section className="report-section">
        <div className="section-title-row">
          <h3 className="report-h3">하루 일과별 의사소통 기회 분석</h3>
          <button className="btn-ghost btn-small no-print" onClick={addActivity}>+ 일과 추가</button>
        </div>
        <table className="comm-schedule-table">
          <thead>
            <tr>
              <th style={{ width: '10%' }}>시간</th>
              <th style={{ width: '13%' }}>활동</th>
              <th style={{ width: '20%' }}>자연스러운 의사소통 기회</th>
              <th style={{ width: '18%' }}>현재 아동의 표현 양상</th>
              <th style={{ width: '20%' }}>필요한 파트너 지원</th>
              <th style={{ width: '15%' }}>발달 목표 연계</th>
              <th className="no-print" style={{ width: '4%' }}></th>
            </tr>
          </thead>
          <tbody>
            {(data.activities || []).map((a, idx) => (
              <tr key={a.id}>
                <td>
                  <Editable value={a.time} onChange={(v) => updateActivity(a.id, 'time', v)} placeholder="예: 09:00" />
                </td>
                <td>
                  <Editable value={a.name} onChange={(v) => updateActivity(a.id, 'name', v)} placeholder="활동명" />
                </td>
                <td>
                  <Editable value={a.opportunities} onChange={(v) => updateActivity(a.id, 'opportunities', v)}
                    placeholder="예: 요구하기, 선택하기, 인사하기, 거부하기"
                    multiline />
                </td>
                <td>
                  <Editable value={a.currentBehavior} onChange={(v) => updateActivity(a.id, 'currentBehavior', v)}
                    placeholder="현재 어떻게 표현하는가"
                    multiline />
                </td>
                <td>
                  <Editable value={a.supports} onChange={(v) => updateActivity(a.id, 'supports', v)}
                    placeholder="시각 단서, 모델링, 촉구 등"
                    multiline />
                </td>
                <td>
                  <Editable value={a.goals} onChange={(v) => updateActivity(a.id, 'goals', v)}
                    placeholder="IEP 목표 ID 또는 영역"
                    multiline />
                </td>
                <td className="no-print" style={{ textAlign: 'center', verticalAlign: 'middle' }}>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
                    <button className="btn-icon-tiny" onClick={() => moveActivity(idx, -1)} title="위로" disabled={idx === 0}>↑</button>
                    <button className="btn-icon-tiny" onClick={() => moveActivity(idx, 1)} title="아래로" disabled={idx === (data.activities || []).length - 1}>↓</button>
                    <button className="btn-icon" onClick={() => removeActivity(a.id)} title="삭제">×</button>
                  </div>
                </td>
              </tr>
            ))}
            {(data.activities || []).length === 0 && (
              <tr>
                <td colSpan={7} style={{ textAlign: 'center', padding: 30, color: '#6b6452' }}>
                  '+ 일과 추가' 버튼을 눌러 하루 일과를 추가하세요.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </section>

      <section className="report-section">
        <h3 className="report-h3">주요 의사소통 기회 및 우선 영역</h3>
        <Editable
          value={data.keyOpportunities}
          onChange={(v) => update({ keyOpportunities: v })}
          placeholder="하루 일과에서 가장 빈번한 의사소통 기회, 우선적으로 다룰 영역을 정리하세요. (IEP 목표 가져오기 버튼으로 빠른 추가 가능)"
          multiline minLines={4}
        />
      </section>

      <section className="report-section">
        <h3 className="report-h3">종합 분석 및 권고</h3>
        <Editable
          value={data.summary}
          onChange={(v) => update({ summary: v })}
          placeholder="이 아동의 의사소통 일과 분석 결과에 대한 종합 의견과 권고를 작성하세요. 어떤 활동이 가장 풍부한 기회를 제공하는지, 어떤 활동에 추가 지원이 필요한지 등."
          multiline minLines={4}
        />
      </section>

      <ApprovalBlock />
    </div>
  );
}

// =====================================================================
// FbaForm — 도전 행동 기능적 분석 (Functional Behavior Assessment)
// SCERTS의 정서 조절 관점 통합 (각성·트리거·대체 행동)
// =====================================================================
function FbaForm({ ws, setWs, showToast }) {
  const data = ws.fba || {
    meta: { observedBy: '', observedAt: '', setting: '' },
    behavior: { operationalDefinition: '', intensity: '', frequency: '', duration: '', impact: '' },
    abc: [
      { id: 'abc1', date: '', setting: '', antecedent: '', behavior: '', consequence: '', notes: '' },
      { id: 'abc2', date: '', setting: '', antecedent: '', behavior: '', consequence: '', notes: '' },
      { id: 'abc3', date: '', setting: '', antecedent: '', behavior: '', consequence: '', notes: '' },
    ],
    functions: { escape: false, attention: false, tangible: false, sensory: false, regulation: false, communication: false, notes: '' },
    emotionalContext: { arousalLevel: '', triggers: '', protectiveFactors: '' },
    replacement: { replacementBehavior: '', teachingStrategy: '', reinforcement: '', environmentalChanges: '' },
    preventionPlan: '', crisisPlan: '', monitoringPlan: '',
  };

  const update = (patch) => setWs((s) => ({ ...s, fba: { ...data, ...patch } }));
  const updateMeta = (k, v) => update({ meta: { ...data.meta, [k]: v } });
  const updateBehavior = (k, v) => update({ behavior: { ...data.behavior, [k]: v } });
  const updateFunctions = (k, v) => update({ functions: { ...data.functions, [k]: v } });
  const updateEmotional = (k, v) => update({ emotionalContext: { ...data.emotionalContext, [k]: v } });
  const updateReplacement = (k, v) => update({ replacement: { ...data.replacement, [k]: v } });

  const updateAbc = (id, field, value) => {
    update({
      abc: (data.abc || []).map((a) => a.id === id ? { ...a, [field]: value } : a),
    });
  };
  const addAbc = () => {
    update({
      abc: [...(data.abc || []), {
        id: 'abc_' + Date.now(),
        date: '', setting: '', antecedent: '', behavior: '', consequence: '', notes: '',
      }],
    });
  };
  const removeAbc = async (id) => {
    if (!await appConfirm('이 ABC 사례를 삭제하시겠습니까?')) return;
    update({ abc: (data.abc || []).filter((a) => a.id !== id) });
  };

  // 기능 가설 자동 생성 (체크된 기능 기반)
  const hypothesisFromFunctions = useMemo(() => {
    const f = data.functions;
    const checked = [];
    if (f.escape) checked.push('회피 (과제·요구 회피)');
    if (f.attention) checked.push('관심 얻기');
    if (f.tangible) checked.push('사물·활동 얻기');
    if (f.sensory) checked.push('감각 자극');
    if (f.regulation) checked.push('정서 조절');
    if (f.communication) checked.push('의사소통 대체');
    return checked;
  }, [data.functions]);

  return (
    <div id="printable-report" className="printable">
      <div className="no-print" style={{ marginBottom: 16, textAlign: 'right' }}>
        <button className="btn-primary" onClick={printReport}>📄 도전 행동 분석 인쇄</button>
      </div>
      <ReportHeader
        title="도전 행동 기능적 분석 (FBA)"
        ws={ws}
        extras={[
          { label: '평가자', value: data.meta.observedBy, editable: true, onChange: (v) => updateMeta('observedBy', v) },
          { label: '평가 일자', value: data.meta.observedAt, editable: true, onChange: (v) => updateMeta('observedAt', v) },
          { label: '관찰 환경', value: data.meta.setting, editable: true, onChange: (v) => updateMeta('setting', v) },
        ]}
      />

      <div className="info-box no-print">
        <strong>SCERTS 관점의 도전 행동 분석</strong><br />
        도전 행동은 단순히 "줄여야 할 것"이 아니라 <em>아동이 자신을 조절하거나 무언가를 전달하려는 시도</em>로 봅니다.
        행동의 기능(왜 일어나는가)과 정서 조절 맥락(각성·트리거)을 함께 분석하여,
        대체 행동을 가르치고 환경을 변경하는 통합적 접근이 핵심입니다.
      </div>

      <section className="report-section">
        <h3 className="report-h3">1. 행동의 정의 및 양상</h3>
        <table className="report-table">
          <tbody>
            <tr>
              <th style={{ width: '20%' }}>조작적 정의</th>
              <td>
                <Editable value={data.behavior.operationalDefinition}
                  onChange={(v) => updateBehavior('operationalDefinition', v)}
                  placeholder="객관적이고 측정 가능한 형태로 행동을 정의하세요. 예: '바닥에 누워 발을 차며 5초 이상 우는 행동'"
                  multiline minLines={2} />
              </td>
            </tr>
            <tr>
              <th>강도</th>
              <td>
                <Editable value={data.behavior.intensity}
                  onChange={(v) => updateBehavior('intensity', v)}
                  placeholder="1(약함) ~ 5(매우 강함) 또는 서술적 설명" />
              </td>
            </tr>
            <tr>
              <th>빈도</th>
              <td>
                <Editable value={data.behavior.frequency}
                  onChange={(v) => updateBehavior('frequency', v)}
                  placeholder="예: 하루 평균 3-5회, 주 10회 등" />
              </td>
            </tr>
            <tr>
              <th>지속 시간</th>
              <td>
                <Editable value={data.behavior.duration}
                  onChange={(v) => updateBehavior('duration', v)}
                  placeholder="평균 지속 시간 및 회복까지 걸리는 시간" />
              </td>
            </tr>
            <tr>
              <th>영향</th>
              <td>
                <Editable value={data.behavior.impact}
                  onChange={(v) => updateBehavior('impact', v)}
                  placeholder="아동 본인·또래·가족·학습에 미치는 영향"
                  multiline minLines={2} />
              </td>
            </tr>
          </tbody>
        </table>
      </section>

      <section className="report-section">
        <div className="section-title-row">
          <h3 className="report-h3">2. ABC 분석 (선행 - 행동 - 후속)</h3>
          <button className="btn-ghost btn-small no-print" onClick={addAbc}>+ 사례 추가</button>
        </div>
        <p className="hint" style={{ marginTop: 0 }}>최소 3건 이상의 사례를 기록하여 패턴을 파악하세요.</p>
        {(data.abc || []).length === 0 && (
          <div className="empty-hint">+ 사례 추가 버튼을 눌러 ABC 사례를 기록하세요.</div>
        )}
        {(data.abc || []).map((abc, idx) => (
          <div key={abc.id} className="abc-case-card">
            <div className="abc-case-header">
              <strong>사례 #{idx + 1}</strong>
              <button className="btn-icon no-print" onClick={() => removeAbc(abc.id)} title="삭제">×</button>
            </div>
            <div className="abc-meta-row">
              <Editable value={abc.date} onChange={(v) => updateAbc(abc.id, 'date', v)} placeholder="날짜 (예: 2024-10-15)" />
              <Editable value={abc.setting} onChange={(v) => updateAbc(abc.id, 'setting', v)} placeholder="환경/상황" />
            </div>
            <table className="report-table abc-table">
              <thead>
                <tr>
                  <th style={{ width: '33%', background: '#fef7e6', color: '#6b5320' }}>A · 선행 사건</th>
                  <th style={{ width: '33%', background: '#fef0e0', color: '#6e2a1a' }}>B · 행동</th>
                  <th style={{ width: '34%', background: '#d9e8df', color: '#2d4a3e' }}>C · 후속 결과</th>
                </tr>
              </thead>
              <tbody>
                <tr>
                  <td>
                    <Editable value={abc.antecedent} onChange={(v) => updateAbc(abc.id, 'antecedent', v)}
                      placeholder="행동 직전 무슨 일이 있었는가? (요구·전이·환경 자극 등)"
                      multiline minLines={3} />
                  </td>
                  <td>
                    <Editable value={abc.behavior} onChange={(v) => updateAbc(abc.id, 'behavior', v)}
                      placeholder="구체적인 행동 양상"
                      multiline minLines={3} />
                  </td>
                  <td>
                    <Editable value={abc.consequence} onChange={(v) => updateAbc(abc.id, 'consequence', v)}
                      placeholder="행동 직후 무슨 일이 일어났는가? (파트너 반응 포함)"
                      multiline minLines={3} />
                  </td>
                </tr>
                {abc.notes !== undefined && (
                  <tr>
                    <td colSpan={3}>
                      <Editable value={abc.notes} onChange={(v) => updateAbc(abc.id, 'notes', v)}
                        placeholder="추가 메모 (선택)"
                        multiline />
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        ))}
      </section>

      <section className="report-section">
        <h3 className="report-h3">3. 행동의 기능 가설</h3>
        <p className="hint" style={{ marginTop: 0 }}>해당하는 모든 기능을 선택하세요 (복수 선택 가능).</p>
        <div className="fba-function-grid">
          <label className={`fba-function-chip ${data.functions.escape ? 'selected' : ''}`}>
            <input type="checkbox" checked={data.functions.escape} onChange={(e) => updateFunctions('escape', e.target.checked)} />
            <div>
              <strong>회피 (Escape)</strong>
              <div className="fba-fn-desc">과제, 요구, 환경, 사람으로부터 벗어남</div>
            </div>
          </label>
          <label className={`fba-function-chip ${data.functions.attention ? 'selected' : ''}`}>
            <input type="checkbox" checked={data.functions.attention} onChange={(e) => updateFunctions('attention', e.target.checked)} />
            <div>
              <strong>관심 얻기 (Attention)</strong>
              <div className="fba-fn-desc">파트너의 주의를 끌기 위한 행동</div>
            </div>
          </label>
          <label className={`fba-function-chip ${data.functions.tangible ? 'selected' : ''}`}>
            <input type="checkbox" checked={data.functions.tangible} onChange={(e) => updateFunctions('tangible', e.target.checked)} />
            <div>
              <strong>사물 얻기 (Tangible)</strong>
              <div className="fba-fn-desc">원하는 사물·활동을 얻기 위함</div>
            </div>
          </label>
          <label className={`fba-function-chip ${data.functions.sensory ? 'selected' : ''}`}>
            <input type="checkbox" checked={data.functions.sensory} onChange={(e) => updateFunctions('sensory', e.target.checked)} />
            <div>
              <strong>감각 자극 (Sensory)</strong>
              <div className="fba-fn-desc">자동적 감각 입력 추구 또는 회피</div>
            </div>
          </label>
          <label className={`fba-function-chip ${data.functions.regulation ? 'selected' : ''}`}>
            <input type="checkbox" checked={data.functions.regulation} onChange={(e) => updateFunctions('regulation', e.target.checked)} />
            <div>
              <strong>정서 조절 (Regulation)</strong>
              <div className="fba-fn-desc">과각성/저각성 상태를 조절하려는 시도</div>
            </div>
          </label>
          <label className={`fba-function-chip ${data.functions.communication ? 'selected' : ''}`}>
            <input type="checkbox" checked={data.functions.communication} onChange={(e) => updateFunctions('communication', e.target.checked)} />
            <div>
              <strong>의사소통 대체 (Communication)</strong>
              <div className="fba-fn-desc">전통적 의사소통 수단의 부재로 인한 대체 행동</div>
            </div>
          </label>
        </div>
        {hypothesisFromFunctions.length > 0 && (
          <div className="fba-hypothesis-summary">
            <strong>선택된 기능:</strong> {hypothesisFromFunctions.join(', ')}
          </div>
        )}
        <Editable value={data.functions.notes}
          onChange={(v) => updateFunctions('notes', v)}
          placeholder="기능 가설에 대한 추가 설명 (선택)"
          multiline minLines={2} />
      </section>

      <section className="report-section">
        <h3 className="report-h3">4. 정서 조절 맥락 (SCERTS 관점)</h3>
        <table className="report-table">
          <tbody>
            <tr>
              <th style={{ width: '20%' }}>각성 수준</th>
              <td>
                <Editable value={data.emotionalContext.arousalLevel}
                  onChange={(v) => updateEmotional('arousalLevel', v)}
                  placeholder="행동 직전 각성 상태 (저각성/적정/과각성). 예: 새 상황 직후 과각성 → 5분 이상 지속" />
              </td>
            </tr>
            <tr>
              <th>트리거</th>
              <td>
                <Editable value={data.emotionalContext.triggers}
                  onChange={(v) => updateEmotional('triggers', v)}
                  placeholder="행동을 유발하는 자극 패턴 (사람·환경·시간·생리적 상태)"
                  multiline minLines={2} />
              </td>
            </tr>
            <tr>
              <th>보호 요인</th>
              <td>
                <Editable value={data.emotionalContext.protectiveFactors}
                  onChange={(v) => updateEmotional('protectiveFactors', v)}
                  placeholder="행동 발생을 줄이는 요인 (선호 활동, 특정 파트너, 시각 단서 등)"
                  multiline minLines={2} />
              </td>
            </tr>
          </tbody>
        </table>
      </section>

      <section className="report-section">
        <h3 className="report-h3">5. 대체 행동 및 중재 계획</h3>
        <table className="report-table">
          <tbody>
            <tr>
              <th style={{ width: '20%' }}>기능적으로 동등한 대체 행동</th>
              <td>
                <Editable value={data.replacement.replacementBehavior}
                  onChange={(v) => updateReplacement('replacementBehavior', v)}
                  placeholder="같은 기능을 수행하되 사회적으로 수용 가능한 행동. 예: 손 들기, '쉬어요' 카드 제시"
                  multiline minLines={2} />
              </td>
            </tr>
            <tr>
              <th>교수 전략</th>
              <td>
                <Editable value={data.replacement.teachingStrategy}
                  onChange={(v) => updateReplacement('teachingStrategy', v)}
                  placeholder="대체 행동을 어떻게 가르칠 것인가 (모델링·촉구·기능적 의사소통 훈련 등)"
                  multiline minLines={2} />
              </td>
            </tr>
            <tr>
              <th>강화 계획</th>
              <td>
                <Editable value={data.replacement.reinforcement}
                  onChange={(v) => updateReplacement('reinforcement', v)}
                  placeholder="대체 행동 사용 시 강화 방법, 강화 스케줄"
                  multiline minLines={2} />
              </td>
            </tr>
            <tr>
              <th>환경 변경</th>
              <td>
                <Editable value={data.replacement.environmentalChanges}
                  onChange={(v) => updateReplacement('environmentalChanges', v)}
                  placeholder="물리적·사회적 환경 조정 (감각 자극 줄이기, 시각 일과표 도입 등)"
                  multiline minLines={2} />
              </td>
            </tr>
          </tbody>
        </table>
      </section>

      <section className="report-section">
        <h3 className="report-h3">6. 예방·위기·모니터링 계획</h3>
        <table className="report-table">
          <tbody>
            <tr>
              <th style={{ width: '20%' }}>예방 계획</th>
              <td>
                <Editable value={data.preventionPlan}
                  onChange={(v) => update({ preventionPlan: v })}
                  placeholder="행동이 발생하기 전 미리 적용하는 전략 (전이 예고, 휴식 시간 확보 등)"
                  multiline minLines={3} />
              </td>
            </tr>
            <tr>
              <th>위기 대응 계획</th>
              <td>
                <Editable value={data.crisisPlan}
                  onChange={(v) => update({ crisisPlan: v })}
                  placeholder="행동이 발생했을 때 안전을 보장하기 위한 단계별 대응. 모든 파트너가 동일하게 행동해야 합니다."
                  multiline minLines={3} />
              </td>
            </tr>
            <tr>
              <th>진전 모니터링</th>
              <td>
                <Editable value={data.monitoringPlan}
                  onChange={(v) => update({ monitoringPlan: v })}
                  placeholder="얼마나 자주, 어떻게 기록하고 평가할 것인가 (빈도·강도 일일 기록지 등)"
                  multiline minLines={2} />
              </td>
            </tr>
          </tbody>
        </table>
      </section>

      <ApprovalBlock />
    </div>
  );
}

function ApprovalBlock({ reportDate }) {
  const dateStr = reportDate
    ? reportDate.replace(/-/g, '. ').replace(/\.\s*$/, '.')
    : '20    .    .    .';
  return (
    <section className="report-section approval-section page-break-before">
      <h3 className="report-h3">SCERTS 중재 계획안 승인서</h3>
      <p className="approval-consent">
        본인은 위 SCERTS 중재 계획안의 내용에 대해 충분한 설명을 듣고 이해하였으며,
        해당 계획에 따라 아동의 중재를 진행하는 것에 동의합니다.
      </p>
      <table className="approval-table">
        <thead>
          <tr>
            <th style={{ width: '22%' }}>직위</th>
            <th>성명 · 서명</th>
            <th style={{ width: '26%' }}>날짜</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td>학부모(보호자)</td>
            <td className="signature-cell">서명 또는 (인)</td>
            <td className="signature-cell">20&nbsp;&nbsp;.&nbsp;&nbsp;.&nbsp;&nbsp;.</td>
          </tr>
          <tr>
            <td>담당 교사</td>
            <td>민 다 혜 (서명)</td>
            <td className="signature-cell">{dateStr}</td>
          </tr>
          <tr>
            <td>책임자(BCBA)</td>
            <td>민 다 혜 (서명)</td>
            <td className="signature-cell">{dateStr}</td>
          </tr>
        </tbody>
      </table>
      <div className="approval-footer">
        <div className="approval-footer-copyright">
          본 보고서는 SCERTS® 모델(Prizant et al., 2006, Brookes Publishing / 한국어판 학지사, 2019)에 근거하여 작성되었습니다.<br />
          © 검단ABA언어행동연구소 · 민다혜 (BCBA). 본 자료는 검단ABA언어행동연구소의 지적재산이며, 무단 복제·배포·재판매·온라인 게시를 엄격히 금지합니다.
        </div>
      </div>
    </section>
  );
}

// =====================================================================
// 공통: 인라인 편집 가능한 텍스트
// =====================================================================
function Editable({ value, onChange, placeholder, multiline, minLines = 2, examples }) {
  // examples: 문자열 배열. 있으면 칸 위에 "💡 예시" 버튼을 띄우고,
  // 누르면 예시를 칸에 채운다(빈 칸일 때만 채우고, 내용 있으면 덮어쓰기 확인 없이
  // 추가하지 않음 — 사용자가 직접 지우고 다시 누르면 됨).
  const [showEx, setShowEx] = useState(false);
  const hasEx = Array.isArray(examples) && examples.length > 0;
  return (
    <div className="editable-wrap">
      {hasEx && (
        <div className="ex-bar no-print">
          <button
            type="button"
            className="ex-btn"
            onClick={() => setShowEx((v) => !v)}
            title="예시 문구를 보고 골라 넣을 수 있습니다"
          >💡 예시 {showEx ? '닫기' : '보기'}</button>
          {showEx && (
            <div className="ex-list">
              {examples.map((ex, i) => (
                <button
                  type="button"
                  key={i}
                  className="ex-item"
                  onClick={() => { onChange(ex); setShowEx(false); }}
                  title="클릭하면 이 문구가 칸에 채워집니다 (이후 수정 가능)"
                >{ex}</button>
              ))}
            </div>
          )}
        </div>
      )}
      <textarea
        className={`editable ${multiline ? 'multi' : 'single'}`}
        value={value || ''}
        onChange={(e) => onChange(e.target.value)}
        placeholder={placeholder}
        rows={multiline ? minLines : 1}
      />
    </div>
  );
}

// =====================================================================
// FOOTER
// =====================================================================
function Footer() {
  return (
    <footer className="footer no-print">
      <div>
        <strong>SCERTS 자동화 시스템</strong> · 검단ABA언어행동연구소
      </div>
      <div className="footer-sub">
        SCERTS® Model © 2006 Prizant, Wetherby, Rubin, Laurent, Rydell · Paul H. Brookes Publishing Co.
      </div>
    </footer>
  );
}

// =====================================================================
// STYLE — 임상 워크플로우에 어울리는 차분한 베이지/딥그린 톤
// =====================================================================
function Style() {
  return (
    <style>{`
@import url('https://fonts.googleapis.com/css2?family=Gowun+Batang:wght@400;700&family=IBM+Plex+Sans+KR:wght@300;400;500;600;700&display=swap');

* { box-sizing: border-box; }
html, body, #root { margin: 0; padding: 0; background: #f4efe4; }
body {
  font-family: 'IBM Plex Sans KR', -apple-system, system-ui, sans-serif;
  color: #2a2419;
  line-height: 1.55;
  -webkit-font-smoothing: antialiased;
}
.app-shell {
  min-height: 100vh;
  overflow-x: hidden;
  background:
    radial-gradient(ellipse at top, rgba(232, 220, 196, 0.5) 0%, transparent 50%),
    linear-gradient(180deg, #f4efe4 0%, #ede6d5 100%);
}

/* ── HEADER ─────────────────────────── */
.header {
  background: #fbf8f1;
  border-bottom: 1px solid #d9d1bd;
  position: sticky; top: 0; z-index: 50;
  box-shadow: 0 1px 0 rgba(0,0,0,0.02);
}
.header-inner {
  max-width: 1400px; margin: 0 auto;
  padding: 12px 24px;
  display: flex; align-items: center; gap: 18px;
  flex-wrap: wrap;
}
/* 좁은 화면에서 탭이 별도 줄로 떨어지게 */
.tabs {
  display: flex; gap: 4px; flex: 1 1 100%;
  justify-content: center; flex-wrap: wrap;
  order: 3;
}
@media (min-width: 1100px) {
  .tabs { flex: 1 1 auto; order: 0; }
}
.brand { display: flex; align-items: center; gap: 12px; flex-shrink: 0; }
.brand-mark {
  width: 42px; height: 42px;
  background: linear-gradient(135deg, #2d4a3e 0%, #1f3a30 100%);
  border-radius: 10px;
  display: flex; align-items: center; justify-content: center;
  box-shadow: 0 2px 8px rgba(45, 74, 62, 0.25);
}
.brand-mark-letter {
  font-family: 'Gowun Batang', serif;
  color: #f4efe4; font-size: 22px; font-weight: 700;
}
.brand-text { line-height: 1.2; }
.brand-title {
  font-weight: 700; font-size: 17px; letter-spacing: -0.01em;
}
.brand-sub {
  font-size: 12px; color: #6b6452;
  margin-top: 2px;
}
.tab {
  padding: 8px 14px;
  background: transparent;
  border: 1px solid transparent;
  font-family: inherit; font-size: 13.5px; font-weight: 500;
  color: #6b6452; cursor: pointer;
  border-radius: 8px; transition: all 0.15s;
}
.tab:hover:not(:disabled) {
  background: #ede6d5; color: #2a2419;
}
.tab.active {
  background: #2d4a3e; color: #f4efe4;
}
.tab:disabled { opacity: 0.4; cursor: not-allowed; }

/* ── 탭 상태 점/체크 ── */
.tab-dot { margin-left: 5px; font-size: 10px; vertical-align: middle; }
.tab-dot-need { color: #c0392b; }            /* 필수 미완 = 빨간 점 */
.tab-dot-done { color: #2d7a4f; }            /* 완료 = 초록 체크 */
.tab.tab-need {                              /* 필수 미완 탭 강조 */
  border-color: #e3b7b1;
  background: #fbf0ee;
  color: #a5392c;
}
.tab.tab-need:hover:not(:disabled) { background: #f6e2de; }
.tab.active.tab-need { background: #2d4a3e; color: #f4efe4; border-color: transparent; }

/* ── 단계 안내 배너 ── */
.step-banner {
  display: flex; align-items: center; gap: 10px;
  padding: 11px 14px; border-radius: 10px;
  font-size: 13.5px; line-height: 1.45;
  border: 1px solid #e4dcc8;
}
.step-banner .sb-badge {
  flex-shrink: 0;
  font-weight: 700; font-size: 12px;
  padding: 3px 9px; border-radius: 999px;
  white-space: nowrap;
}
.step-banner .sb-text { color: #4a4434; }
/* 작성자 배지 (오른쪽 정렬) */
.step-banner .sb-writer {
  flex-shrink: 0;
  margin-left: auto;
  font-size: 12px; font-weight: 700;
  padding: 3px 10px; border-radius: 999px;
  white-space: nowrap;
}
.sb-writer-parent { background: #fbeee0; color: #9a5b1f; border: 1px solid #eecfa6; }
.sb-writer-therapist { background: #e6eef0; color: #2a5560; border: 1px solid #b9d2d8; }

/* ── 빈 상태 (담당 아동 0명) ── */
.empty-state {
  text-align: center;
  padding: 80px 24px;
  max-width: 480px; margin: 0 auto;
}
.empty-state-icon { font-size: 56px; margin-bottom: 16px; }
.empty-state-title {
  font-family: 'Gowun Batang', serif;
  font-size: 24px; font-weight: 700; color: #2d4a3e;
  margin: 0 0 10px;
}
.empty-state-desc { font-size: 14px; color: #6b6452; line-height: 1.6; margin: 0 0 24px; }
.empty-state-btn { font-size: 15px; padding: 12px 28px; }
.empty-state-sample { font-size: 13.5px; padding: 10px 20px; margin-top: 10px; }
.empty-state-hint { font-size: 12.5px; color: #9a917d; margin-top: 20px; }

/* ── 로그인 화면 ── */
.login-loading {
  min-height: 100vh; display: flex; align-items: center; justify-content: center;
  background: #f4efe4; color: #6b6452; font-family: 'IBM Plex Sans KR', sans-serif;
}
.login-screen {
  min-height: 100vh; display: flex; flex-direction: column; align-items: center; justify-content: center;
  background: #f4efe4; padding: 20px; font-family: 'IBM Plex Sans KR', sans-serif;
}
.login-box {
  width: 100%; max-width: 380px;
  background: #fff; border: 1px solid #e4dcc8; border-radius: 16px;
  padding: 32px 28px; box-shadow: 0 8px 30px rgba(45,74,62,0.10);
}
.login-brand { display: flex; align-items: center; gap: 12px; margin-bottom: 26px; }
.login-brand-mark {
  width: 44px; height: 44px; border-radius: 12px;
  background: #2d4a3e; color: #f4efe4;
  display: flex; align-items: center; justify-content: center;
  font-family: 'Gowun Batang', serif; font-size: 22px; font-weight: 700;
}
.login-brand-title { font-family: 'Gowun Batang', serif; font-size: 17px; font-weight: 700; color: #1f1a13; }
.login-brand-sub { font-size: 12px; color: #8a8270; margin-top: 2px; }
.login-fields { display: flex; flex-direction: column; }
.login-label { font-size: 12.5px; font-weight: 600; color: #4a4434; margin-bottom: 5px; margin-top: 12px; }
.login-input {
  padding: 11px 13px; border: 1px solid #d9d1bd; border-radius: 9px;
  font-family: inherit; font-size: 14.5px; background: #fff;
}
.login-input:focus { outline: none; border-color: #2d4a3e; }
.login-error { color: #c0392b; font-size: 12.5px; margin-top: 10px; line-height: 1.5; }
.login-btn {
  margin-top: 20px; padding: 13px; border: none; border-radius: 10px;
  background: #2d4a3e; color: #f4efe4; font-family: inherit;
  font-size: 15px; font-weight: 700; cursor: pointer; transition: background 0.15s;
}
.login-btn:hover { background: #243c32; }
.login-hint { margin-top: 18px; font-size: 11.5px; color: #9a917d; line-height: 1.6; text-align: center; }
.login-help-link {
  display: block; width: 100%; margin-top: 14px; padding: 10px;
  background: #fff; border: 1px solid #d9d1bd; border-radius: 9px;
  color: #2d4a3e; font-family: inherit; font-size: 13px; font-weight: 600;
  cursor: pointer; text-align: center;
}
.login-help-link:hover { background: #f4efe4; border-color: #2d4a3e; }

/* 로그인 화면 저작권 footer */
.login-copyright {
  margin-top: 14px; text-align: center; font-size: 11px; color: #9a917d; line-height: 1.6;
  max-width: 380px; width: 100%; padding: 0 16px; box-sizing: border-box;
}
.login-copyright-more {
  background: none; border: none; padding: 0; color: #2d4a3e;
  font-family: inherit; font-size: 11px; font-weight: 600; text-decoration: underline;
  cursor: pointer;
}
.login-copyright-more:hover { color: #c19a3a; }

/* 저작권 다이얼로그 */
.copyright-dialog { max-width: 560px; width: 100%; max-height: 85vh; overflow-y: auto; }
.copyright-h2 { font-family: 'Gowun Batang', serif; font-size: 19px; color: #2d4a3e; margin: 0 0 18px; }
.copyright-section { margin-bottom: 14px; }
.copyright-block-title { font-weight: 700; color: #2d4a3e; font-size: 13.5px; margin-bottom: 6px; }
.copyright-cite { font-size: 12.5px; color: #4a4434; line-height: 1.7; margin: 0; padding: 10px 14px; background: #f9f6ef; border-radius: 8px; }
.copyright-disclaimer { font-size: 12.5px; color: #4a4434; line-height: 1.7; margin: 0; }
.copyright-divider { height: 1px; background: #e4dcc8; margin: 18px 0; }
.copyright-owner { font-size: 13px; color: #2a2419; line-height: 1.8; margin: 0; padding: 12px 14px; background: #fdf3d8; border-left: 3px solid #c19a3a; border-radius: 6px; }

/* 도움말 다이얼로그 */
.help-dialog { max-width: 720px; width: 100%; max-height: 88vh; overflow-y: auto; }
.help-guide { font-family: inherit; line-height: 1.7; color: #2a2419; }
.help-section { margin-bottom: 22px; }
.help-h2 { font-family: 'Gowun Batang', serif; font-size: 20px; color: #2d4a3e; margin: 0 0 6px; }
.help-h3 { font-family: 'Gowun Batang', serif; font-size: 16px; color: #2d4a3e; margin: 16px 0 10px; padding-top: 12px; border-top: 1px solid #e4dcc8; }
.help-intro { color: #6b6452; font-size: 13.5px; margin: 0; }
.help-block { background: #f9f6ef; border: 1px solid #e4dcc8; border-radius: 10px; padding: 12px 16px; margin: 10px 0; }
.help-block-title { font-weight: 700; color: #2d4a3e; font-size: 13.5px; margin-bottom: 6px; }
.help-ul { margin: 6px 0; padding-left: 20px; font-size: 13.5px; }
.help-ul li { margin-bottom: 5px; }
.help-step { background: #fff; border: 1px solid #e4dcc8; border-radius: 10px; padding: 13px 16px; margin: 10px 0; }
.help-step-head { font-size: 14.5px; margin-bottom: 6px; display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }
.help-step p { font-size: 13.5px; margin: 6px 0; }
.help-note { background: #fef9e8; padding: 8px 12px; border-radius: 7px; font-size: 12.5px !important; color: #7a5a1c; margin-top: 8px !important; }
.help-legend { margin: 10px 0; display: flex; gap: 8px; flex-wrap: wrap; }
.help-badge { display: inline-block; padding: 3px 9px; border-radius: 12px; font-size: 11.5px; font-weight: 600; white-space: nowrap; }
.help-badge.badge-teacher { background: #eef3ef; color: #2d4a3e; border: 1px solid #cfe0d4; }
.help-badge.badge-parent { background: #fef0e8; color: #8a4a1c; border: 1px solid #f0c8a8; }
.help-badge.badge-auto { background: #fdf3d8; color: #7a5a1c; border: 1px solid #e8c878; }
.help-actions { display: flex; justify-content: flex-end; margin-top: 18px; padding-top: 14px; border-top: 1px solid #e4dcc8; }
/* 헤더 로그인 정보 */
.header-saved { font-size: 11.5px; color: #8a8270; white-space: nowrap; }
.concurrent-banner {
  display: flex; align-items: center; gap: 10px; flex-wrap: wrap;
  padding: 10px 20px; background: #fef0e0; border-top: 1px solid #f0c8a8;
  color: #8a4a1c; font-size: 13px; line-height: 1.5;
}
.concurrent-btn {
  padding: 6px 12px; border-radius: 7px; border: 1px solid #c19a3a;
  background: #fff; color: #8a5a1c; font-family: inherit; font-size: 12px;
  font-weight: 600; cursor: pointer; white-space: nowrap;
}
.concurrent-btn.refresh { background: #c19a3a; color: #fff; }
.concurrent-btn.dismiss { background: #fff; }

/* 에러 화면 */
.error-screen {
  min-height: 100vh; display: flex; flex-direction: column; align-items: center; justify-content: center;
  background: #f4efe4; padding: 20px; font-family: 'IBM Plex Sans KR', sans-serif;
}
.error-box {
  width: 100%; max-width: 480px; background: #fff;
  border: 1px solid #e4dcc8; border-radius: 16px; padding: 36px 30px;
  box-shadow: 0 8px 30px rgba(45,74,62,0.10); text-align: center;
}
.error-icon { font-size: 48px; margin-bottom: 10px; }
.error-title { font-family: 'Gowun Batang', serif; font-size: 20px; color: #2d4a3e; margin: 0 0 14px; }
.error-msg { font-size: 13.5px; color: #4a4434; line-height: 1.7; margin: 0 0 16px; }
.error-details { margin: 14px 0; padding: 10px 12px; background: #f9f6ef; border-radius: 8px; text-align: left; }
.error-details summary { font-size: 12.5px; color: #6b6452; cursor: pointer; }
.error-details code { display: block; margin-top: 8px; font-size: 11px; color: #8a2e23; word-break: break-all; }
.error-actions { display: flex; gap: 10px; justify-content: center; margin: 18px 0 10px; }
.error-hint { font-size: 11.5px; color: #9a917d; margin: 0; }

/* 모바일/태블릿 반응형 */
@media (max-width: 900px) {
  .header-actions { flex-wrap: wrap; gap: 6px; }
  .header-auth { flex-wrap: wrap; gap: 6px; margin-left: 0; padding-left: 8px; }
  .header-saved { font-size: 10.5px; }
  .tabs { flex-wrap: wrap; }
  .progress-cards { grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); }
  .help-dialog, .account-panel, .admin-dash, .copyright-dialog { max-width: 95vw; }
  .template-menu { width: calc(100vw - 40px); max-width: 360px; right: auto; left: 0; }
}
@media (max-width: 600px) {
  .header-inner { padding: 10px 12px; }
  .brand-mark-letter { font-size: 18px; }
  .brand-title { font-size: 15px; }
  .header-auth-name { font-size: 12px; }
  .btn-small { padding: 6px 9px; font-size: 11.5px; }
  .main { padding: 12px; }
  .report-meta th, .report-meta td { font-size: 12px; padding: 6px 8px; }
  .approval-table th, .approval-table td { font-size: 12px; padding: 6px 8px; }
  .empty-state { padding: 40px 18px; }
  .login-box { padding: 26px 22px; }
  .login-brand-title { font-size: 15px; }
  .login-brand-sub { font-size: 11px; }
  .home, .main { padding-left: 12px !important; padding-right: 12px !important; }
  .hero-title { font-size: 26px; }
  .hero-sub { font-size: 13.5px; }
  .report-section { padding: 14px !important; }
  .report-h3 { font-size: 16px !important; }
}
.header-auth { display: flex; align-items: center; gap: 8px; margin-left: 8px; padding-left: 12px; border-left: 1px solid #e0d8c4; }
.header-auth-name { font-size: 13px; font-weight: 600; color: #2d4a3e; white-space: nowrap; }
.btn-logout { font-size: 12.5px; }

/* ── 관리자 계정 관리 패널 ── */
.account-panel { max-width: 540px; width: 100%; }
.account-panel-head { display: flex; align-items: center; justify-content: space-between; margin-bottom: 16px; }
.account-panel-title { font-family: 'Gowun Batang', serif; font-size: 19px; font-weight: 700; color: #2d4a3e; margin: 0; }
.account-panel-count { font-size: 13px; color: #8a8270; font-weight: 600; }
.account-add { background: #f9f6ef; border: 1px solid #e4dcc8; border-radius: 12px; padding: 16px; margin-bottom: 16px; }
.account-add-title { font-size: 13.5px; font-weight: 700; color: #2d4a3e; margin-bottom: 10px; }
.account-add-row { display: flex; gap: 8px; flex-wrap: wrap; }
.account-add-row .account-input { flex: 1 1 140px; min-width: 0; }
.account-add-row .btn-primary { flex-shrink: 0; }
@media (max-width: 600px) {
  .account-add-row { flex-direction: column; }
  .account-add-row .account-input,
  .account-add-row .btn-primary { width: 100%; flex: 1 1 auto; }
}
.account-input { padding: 9px 12px; border: 1px solid #d9d1bd; border-radius: 8px; font-family: inherit; font-size: 14px; min-width: 0; }
.account-input:focus { outline: none; border-color: #2d4a3e; }
.account-input-sm { flex: 0 1 160px; }
.account-add-hint { font-size: 11.5px; color: #8a7a4f; margin-top: 8px; line-height: 1.5; }
.account-msg { padding: 10px 13px; background: #eef6ef; border: 1px solid #bcdcc6; border-radius: 8px; font-size: 13px; color: #2d5540; margin-bottom: 14px; line-height: 1.5; }
.account-list { display: flex; flex-direction: column; gap: 8px; max-height: 320px; overflow-y: auto; }
.account-empty { text-align: center; color: #9a917d; font-size: 13px; padding: 20px; }
.account-item { display: flex; align-items: center; justify-content: space-between; gap: 10px; padding: 11px 14px; background: #fff; border: 1px solid #e4dcc8; border-radius: 10px; flex-wrap: wrap; }
.account-item-info { display: flex; flex-direction: column; gap: 2px; }
.account-item-name { font-size: 14px; font-weight: 600; color: #2a2419; }
.account-item-meta { font-size: 11.5px; color: #9a917d; }
.account-item-actions, .account-item-edit { display: flex; gap: 6px; align-items: center; flex-wrap: wrap; }
.account-item-edit .account-input { min-width: 0; flex: 1 1 140px; }
@media (max-width: 600px) {
  .account-item-edit { width: 100%; }
  .account-item-edit .account-input { width: 100%; flex: 1 1 100%; }
}
.account-del-btn { color: #c0392b; }
.account-del-warn { font-size: 12px; color: #8a2e23; }

/* ── 관리자 전체 조회 대시보드 ── */
.admin-dash { max-width: 680px; width: 100%; }
.admin-dash-controls { display: flex; gap: 8px; margin-bottom: 14px; }
.admin-dash-list { display: flex; flex-direction: column; gap: 14px; max-height: 440px; overflow-y: auto; }
.admin-teacher-block { border: 1px solid #e4dcc8; border-radius: 12px; overflow: hidden; }
.admin-teacher-head { display: flex; align-items: center; justify-content: space-between; padding: 10px 14px; background: #f4f1e8; }
.admin-teacher-name { font-size: 14px; font-weight: 700; color: #2d4a3e; }
.admin-teacher-count { font-size: 12px; color: #8a8270; }
.admin-child-empty { padding: 12px 14px; font-size: 12.5px; color: #9a917d; }
.admin-child-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(150px, 1fr)); gap: 8px; padding: 12px; }
.admin-child-card {
  display: flex; flex-direction: column; gap: 3px; padding: 11px 13px;
  background: #fff; border: 1px solid #e0d8c4; border-radius: 9px;
  cursor: pointer; text-align: left; font-family: inherit; transition: all 0.12s;
}
.admin-child-card:hover { border-color: #2d4a3e; background: #faf9f5; }
.admin-child-name { font-size: 14px; font-weight: 600; color: #2a2419; }
.admin-child-birth { font-size: 11px; color: #9a917d; }
.admin-child-stage { font-size: 11.5px; color: #2d4a3e; }

/* ── 관리자 조회 모드 배너 ── */
.viewing-banner {
  display: flex; align-items: center; justify-content: space-between; gap: 12px;
  padding: 10px 20px; background: #fef3e0; border-bottom: 1px solid #eecf9e;
  flex-wrap: wrap;
}
.viewing-banner-text { font-size: 13px; color: #8a5a1f; }
.viewing-banner-btn {
  padding: 7px 14px; border: 1px solid #c19a3a; border-radius: 8px;
  background: #fff; color: #8a5a1f; font-family: inherit; font-size: 12.5px;
  font-weight: 600; cursor: pointer; white-space: nowrap;
}
.viewing-banner-btn:hover { background: #c19a3a; color: #fff; }

/* ── 보고서 유형 토글 (중간/종결) ── */
.report-type-toggle {
  display: flex; align-items: center; gap: 8px; flex-wrap: wrap;
  padding: 12px 16px; margin-bottom: 14px;
  background: #f4f1e8; border: 1px solid #ddd6c5; border-radius: 10px;
}
.report-type-toggle .rtt-label { font-size: 13px; font-weight: 700; color: #2d4a3e; }
.rtt-btn {
  font-family: inherit; font-size: 13px; font-weight: 600;
  padding: 6px 16px; border-radius: 999px; cursor: pointer;
  background: #fff; color: #6b6452; border: 1px solid #d9d1bd;
  transition: all 0.12s;
}
.rtt-btn:hover { border-color: #c19a3a; }
.rtt-btn.active { background: #2d4a3e; color: #f4efe4; border-color: #2d4a3e; }
.rtt-hint { font-size: 12px; color: #8a7a4f; flex-basis: 100%; }

/* ── 종결 모드 섹션 ── */
.closing-reason-grid { display: flex; flex-wrap: wrap; gap: 8px; margin-bottom: 10px; }
.closing-reason-opt {
  display: flex; align-items: center; gap: 6px;
  padding: 7px 13px; border: 1px solid #d9d1bd; border-radius: 8px;
  font-size: 13.5px; cursor: pointer; background: #fff; transition: all 0.12s;
}
.closing-reason-opt:hover { border-color: #c19a3a; }
.closing-reason-opt.sel { background: #2d4a3e; color: #f4efe4; border-color: #2d4a3e; }
.closing-reason-print { display: none; }
.closing-goal-table .closing-status-sel {
  width: 100%; padding: 5px 7px; border: 1px solid #d9d1bd;
  border-radius: 6px; font-family: inherit; font-size: 13px; background: #fff;
}
.closing-status-print { display: none; }
.closing-empty { text-align: center; color: #9a917d; font-size: 13px; padding: 14px; }
.closing-row-del {
  background: none; border: none; color: #c0392b; font-size: 18px;
  cursor: pointer; line-height: 1; padding: 2px 6px;
}

/* 인쇄 전용 표시: 화면에서는 숨기고 buildReportHTML가 만든 정적 문서에서만 보임 */
.print-only { display: none; }
@media print {
  .closing-reason-print, .closing-status-print { display: inline !important; }
  .print-only { display: inline !important; }
  .no-print { display: none !important; }
}

/* ── 부모 카톡 연동 박스 ── */
.kakao-box {
  background: #fef7e6; border: 1px solid #eecf9e; border-radius: 12px;
  padding: 16px 18px; margin-bottom: 4px;
}
.kakao-box-title { font-size: 15px; font-weight: 700; color: #2d4a3e; margin-bottom: 4px; }
.kakao-box-desc { font-size: 13px; color: #6b5a30; margin-bottom: 12px; }
.kakao-box-steps { display: flex; flex-direction: column; gap: 12px; }
.kakao-step { display: flex; gap: 11px; align-items: flex-start; }
.kakao-step-num {
  flex-shrink: 0; width: 22px; height: 22px; border-radius: 50%;
  background: #c19a3a; color: #fff; font-size: 12px; font-weight: 700;
  display: flex; align-items: center; justify-content: center; margin-top: 2px;
}
.kakao-step-hint { font-size: 12px; color: #8a7a4f; margin-top: 5px; line-height: 1.45; }
/* 필수 미완 — 주의(빨강 계열) */
.step-banner.sb-need { background: #fbf0ee; border-color: #e9c4be; }
.step-banner.sb-need .sb-badge { background: #c0392b; color: #fff; }
.step-banner.sb-need .sb-text { color: #8a2e23; font-weight: 600; }
/* 필수 완료 — 초록 */
.step-banner.sb-done { background: #eef6ef; border-color: #bcdcc6; }
.step-banner.sb-done .sb-badge { background: #2d7a4f; color: #fff; }
/* 자동 — 금색 */
.step-banner.sb-auto { background: #f9f3e3; border-color: #e2cf9e; }
.step-banner.sb-auto .sb-badge { background: #c19a3a; color: #fff; }
/* 선택 — 회색 */
.step-banner.sb-opt { background: #f4f2ec; border-color: #ddd6c5; }
.step-banner.sb-opt .sb-badge { background: #8a8270; color: #fff; }

.header-actions { display: flex; gap: 8px; }

.btn-primary, .btn-ghost, .btn-danger {
  padding: 8px 14px;
  font-family: inherit; font-size: 13px; font-weight: 500;
  border-radius: 7px; cursor: pointer;
  transition: all 0.15s;
  border: 1px solid transparent;
}
.btn-primary {
  background: #2d4a3e; color: #f4efe4; border-color: #2d4a3e;
}
.btn-primary:hover { background: #1f3a30; }
.btn-ghost {
  background: transparent; color: #2a2419;
  border-color: #c4b994;
}
.btn-ghost:hover { background: #fbf8f1; border-color: #2d4a3e; }
.btn-danger { background: #b54a3a; color: #fff; border-color: #b54a3a; }
.btn-danger:hover { background: #993d2f; }

/* ── MAIN ─────────────────────────── */
.main {
  max-width: 1320px;
  margin: 0 auto;
  padding: 32px 28px 80px;
}

/* ── HOME ─────────────────────────── */
.home { display: grid; gap: 24px; }
.hero {
  padding: 32px 4px 8px;
}
.eyebrow {
  text-transform: uppercase; letter-spacing: 0.18em;
  font-size: 11px; font-weight: 600;
  color: #2d4a3e; margin-bottom: 10px;
}
.hero-title {
  font-family: 'Gowun Batang', serif;
  font-size: 34px; line-height: 1.35; letter-spacing: -0.02em;
  margin: 0 0 14px; font-weight: 700;
  color: #1f1a13;
}
.hero-sub {
  font-size: 15px; color: #6b6452;
  max-width: 720px; margin: 0;
}

.card {
  background: #fbf8f1;
  border: 1px solid #d9d1bd;
  border-radius: 14px;
  padding: 28px;
  box-shadow: 0 1px 2px rgba(0,0,0,0.02);
}
.section-title {
  font-family: 'Gowun Batang', serif;
  font-size: 22px; font-weight: 700;
  margin: 0 0 8px; letter-spacing: -0.01em;
  color: #1f1a13;
}
.section-optional-tag {
  font-family: 'IBM Plex Sans KR', sans-serif;
  font-size: 12px; font-weight: 600;
  color: #8a8270; background: #efece3;
  border: 1px solid #ddd6c5; border-radius: 999px;
  padding: 2px 9px; margin-left: 8px;
  vertical-align: middle;
}
.hint {
  font-size: 13px; color: #6b6452;
  margin: 0 0 20px;
}
.form-grid {
  display: grid;
  grid-template-columns: repeat(3, 1fr);
  gap: 16px;
}
.field { display: flex; flex-direction: column; gap: 6px; }
.field-label {
  font-size: 12px; font-weight: 600;
  color: #6b6452; letter-spacing: 0.02em;
}
.field input, .field textarea {
  padding: 10px 12px;
  background: #fff;
  border: 1px solid #d9d1bd;
  border-radius: 7px;
  font-family: inherit; font-size: 14px;
  transition: border-color 0.15s;
}
.field input:focus, .field textarea:focus {
  outline: none;
  border-color: #2d4a3e;
  box-shadow: 0 0 0 3px rgba(45, 74, 62, 0.1);
}

.progress-grid {
  display: grid;
  grid-template-columns: repeat(5, 1fr);
  gap: 12px;
  margin-top: 6px;
}
.activity-link {
  margin-top: 14px;
  padding: 12px 16px;
  background: #fef7e6;
  border: 1px solid #c19a3a;
  border-radius: 8px;
  display: flex; justify-content: space-between; align-items: center;
  font-size: 13px;
}
.activity-link .link-btn:disabled {
  opacity: 0.4; cursor: not-allowed;
}
.progress-card {
  text-align: left;
  background: #fff;
  border: 1px solid #d9d1bd;
  border-radius: 10px;
  padding: 16px;
  cursor: pointer;
  font-family: inherit;
  transition: all 0.15s;
}
.progress-card:hover:not(.disabled) {
  border-color: #2d4a3e;
  transform: translateY(-1px);
  box-shadow: 0 4px 12px rgba(45, 74, 62, 0.08);
}
.progress-card.disabled { opacity: 0.5; cursor: not-allowed; }
.progress-step {
  font-size: 10px; font-weight: 700; letter-spacing: 0.15em;
  color: #2d4a3e; margin-bottom: 6px;
}
.progress-title {
  font-size: 16px; font-weight: 600;
  margin-bottom: 4px;
}
.progress-value {
  font-size: 13px; color: #6b6452;
  margin-bottom: 6px;
}
.progress-status {
  font-size: 11px; font-weight: 500;
  color: #2d4a3e;
}
.pc-status-done { color: #2d7a4f; font-weight: 700; }
.pc-status-todo { color: #9a917d; }
.pc-status-progress { color: #c19a3a; font-weight: 600; }
.progress-card.pc-done { border-color: #bcdcc6; background: #f5faf6; }
.progress-card.pc-done .progress-step { color: #2d7a4f; }
.archive-link {
  margin-top: 20px;
  padding: 14px 16px;
  background: #ede6d5;
  border-radius: 8px;
  display: flex; justify-content: space-between; align-items: center;
  font-size: 13px;
}
.link-btn {
  background: transparent; border: none;
  color: #2d4a3e; font-weight: 600; font-size: 13px;
  font-family: inherit; cursor: pointer;
}

/* ── DECISION TAB ─────────────────────── */
.tab-content { display: grid; gap: 20px; }
.decision-block {
  margin-top: 24px;
  padding: 20px;
  background: #fff;
  border: 1px solid #e6e0cd;
  border-radius: 10px;
}
.decision-title {
  font-size: 16px; font-weight: 600;
  margin: 0 0 14px;
  color: #1f1a13;
}
.check-row {
  display: flex; align-items: flex-start;
  gap: 12px; padding: 10px 0;
  cursor: pointer;
  border-bottom: 1px dashed #ede6d5;
}
.check-row:last-of-type { border-bottom: none; }
.check-row input[type="checkbox"] {
  margin-top: 4px;
  width: 18px; height: 18px;
  accent-color: #2d4a3e;
  cursor: pointer;
}
.check-id {
  font-family: 'Gowun Batang', serif;
  font-weight: 700; color: #2d4a3e;
  min-width: 28px; padding-top: 1px;
}
.check-label {
  font-size: 14px; line-height: 1.55;
  flex: 1;
}
.decision-hint {
  margin-top: 12px;
  font-size: 12px; color: #6b6452;
  font-style: italic;
}
.recommend-box {
  margin-top: 24px;
  padding: 18px 22px;
  background: linear-gradient(135deg, #2d4a3e 0%, #1f3a30 100%);
  color: #f4efe4;
  border-radius: 10px;
}
.recommend-label {
  font-size: 11px; letter-spacing: 0.16em;
  text-transform: uppercase; opacity: 0.8;
}
.recommend-value {
  font-family: 'Gowun Batang', serif;
  font-size: 26px; font-weight: 700;
  margin: 4px 0 8px;
}
.recommend-hint {
  font-size: 12.5px; opacity: 0.85;
  margin: 0;
}
.stage-choose {
  margin-top: 20px;
  display: grid;
  grid-template-columns: repeat(3, 1fr);
  gap: 12px;
}
.stage-btn {
  position: relative;
  padding: 18px 14px;
  background: #fff;
  border: 1.5px solid #d9d1bd;
  border-radius: 10px;
  cursor: pointer;
  font-family: inherit;
  text-align: center;
  transition: all 0.15s;
}
.stage-btn:hover {
  border-color: #2d4a3e;
  transform: translateY(-1px);
}
.stage-btn.active {
  background: #2d4a3e; color: #fff;
  border-color: #2d4a3e;
}
.stage-btn.recommended:not(.active) {
  border-color: #c19a3a;
  background: #fef7e6;
}
.stage-btn-label {
  font-weight: 600; font-size: 15px;
}
.stage-btn-badge {
  position: absolute;
  top: -8px; right: -8px;
  background: #c19a3a;
  color: #fff;
  font-size: 10px; font-weight: 700;
  padding: 3px 8px; border-radius: 10px;
  letter-spacing: 0.05em;
}

/* ── ASSESSMENT TAB ───────────────────── */
.assess-header {
  display: flex; justify-content: space-between;
  align-items: flex-start; gap: 16px;
  flex-wrap: wrap; margin-bottom: 16px;
}
.assess-actions { display: flex; gap: 8px; flex-wrap: wrap; }
.quarter-row {
  display: flex; gap: 6px; margin-bottom: 18px;
}
.quarter-btn {
  padding: 8px 16px;
  background: #fff;
  border: 1px solid #d9d1bd;
  border-radius: 7px;
  cursor: pointer;
  font-family: inherit; font-size: 13px;
  transition: all 0.15s;
}
.quarter-btn.active {
  background: #2d4a3e; color: #fff; border-color: #2d4a3e;
}
.legend {
  display: flex; flex-direction: column; gap: 6px;
  padding: 14px 18px;
  background: #ede6d5;
  border-radius: 8px;
  margin-bottom: 22px;
}
.legend-item { display: flex; align-items: center; gap: 10px; }
.legend-score {
  width: 24px; height: 24px;
  border-radius: 50%;
  display: flex; align-items: center; justify-content: center;
  font-weight: 700; font-size: 13px;
  color: #fff;
}
.legend-score.score-0 { background: #d4d0c4; color: #6b6452; }
.legend-score.score-1 { background: #c19a3a; }
.legend-score.score-2 { background: #2d4a3e; }
.legend-label { font-size: 13px; }

.domain-tabs {
  display: grid; gap: 14px;
  margin-bottom: 22px;
}
.domain-group {
  padding: 14px 16px;
  background: #ede6d5;
  border-radius: 10px;
}
.domain-group-title {
  font-size: 11px; font-weight: 700;
  text-transform: uppercase; letter-spacing: 0.14em;
  color: #2d4a3e; margin-bottom: 10px;
}
.domain-buttons {
  display: grid;
  grid-template-columns: repeat(2, 1fr);
  gap: 8px;
}
.domain-btn {
  padding: 12px 14px;
  background: #fbf8f1;
  border: 1px solid transparent;
  border-radius: 8px;
  display: flex; justify-content: space-between;
  align-items: center;
  cursor: pointer;
  font-family: inherit;
  transition: all 0.15s;
}
.domain-btn:hover { background: #fff; border-color: #d9d1bd; }
.domain-btn.active {
  background: #2d4a3e; color: #fff;
  border-color: #2d4a3e;
}
.domain-btn-label { font-size: 14px; font-weight: 500; }
.domain-btn-score {
  font-family: 'Gowun Batang', serif;
  font-weight: 700; font-size: 14px;
  opacity: 0.85;
}

.domain-detail {
  padding: 22px;
  background: #fff;
  border: 1px solid #e6e0cd;
  border-radius: 10px;
}
.domain-detail-header {
  display: flex; justify-content: space-between;
  align-items: baseline;
  padding-bottom: 14px; margin-bottom: 18px;
  border-bottom: 2px solid #2d4a3e;
}
.domain-detail-header h3 {
  font-family: 'Gowun Batang', serif;
  margin: 0; font-size: 19px;
}
.domain-detail-score {
  font-family: 'Gowun Batang', serif;
  font-size: 17px; font-weight: 700;
  color: #2d4a3e;
}

.score-group { margin-bottom: 22px; }
.score-group-title {
  font-size: 14px; font-weight: 600;
  margin: 0 0 10px;
  padding: 6px 10px;
  background: #ede6d5;
  border-radius: 6px;
  color: #1f1a13;
}
.score-row {
  display: grid;
  grid-template-columns: 60px 1fr auto;
  gap: 12px; align-items: center;
  padding: 8px 6px;
  border-bottom: 1px dashed #ede6d5;
}
.score-row:hover { background: #fdfaf2; }
.score-id {
  font-family: 'Gowun Batang', serif;
  font-weight: 700; color: #2d4a3e;
  font-size: 13px;
}
.score-label { font-size: 13.5px; }
.score-buttons { display: flex; gap: 4px; }
.score-pip {
  width: 32px; height: 32px;
  border: 1px solid #d9d1bd;
  background: #fff;
  border-radius: 7px;
  font-family: inherit; font-weight: 700;
  cursor: pointer;
  transition: all 0.12s;
}
.score-pip:hover { border-color: #2d4a3e; }
.score-pip.active.score-0 { background: #d4d0c4; color: #fff; border-color: #d4d0c4; }
.score-pip.active.score-1 { background: #c19a3a; color: #fff; border-color: #c19a3a; }
.score-pip.active.score-2 { background: #2d4a3e; color: #fff; border-color: #2d4a3e; }
.score-clear {
  width: 28px; height: 32px;
  background: transparent; border: none;
  color: #b5a888; cursor: pointer;
  font-size: 14px;
}
.score-clear:hover { color: #b54a3a; }

.ses-section, .notes-section {
  margin-top: 24px;
  padding: 22px;
  background: #fff;
  border: 1px solid #e6e0cd;
  border-radius: 10px;
}
.ses-section h3, .notes-section h3 {
  font-family: 'Gowun Batang', serif;
  margin: 0 0 16px; font-size: 17px;
}
.ses-row {
  display: grid;
  grid-template-columns: 200px 1fr 70px;
  gap: 14px; align-items: center;
  padding: 8px 0;
}
.ses-label { font-size: 14px; }
.ses-row input[type="range"] {
  accent-color: #2d4a3e;
}
.ses-value {
  font-family: 'Gowun Batang', serif;
  font-weight: 700; font-size: 14px;
  color: #2d4a3e;
  text-align: right;
}
.notes-section textarea {
  width: 100%;
  padding: 12px;
  border: 1px solid #d9d1bd;
  border-radius: 7px;
  font-family: inherit; font-size: 14px;
  resize: vertical;
}
.notes-section textarea:focus {
  outline: none; border-color: #2d4a3e;
  box-shadow: 0 0 0 3px rgba(45, 74, 62, 0.1);
}

/* ── IEP / INTERIM ─────────────────────── */
.iep-header {
  display: flex; justify-content: space-between;
  align-items: flex-start; gap: 16px;
  flex-wrap: wrap;
  margin-bottom: 20px;
}
.iep-actions { display: flex; gap: 8px; flex-wrap: wrap; }

.printable {
  background: #fff;
  border: 1px solid #e6e0cd;
  border-radius: 8px;
  padding: 40px 44px;
}
.report-header {
  border-bottom: 3px double #2d4a3e;
  padding-bottom: 24px;
  margin-bottom: 28px;
}
.report-brand { text-align: center; margin-bottom: 14px; }
.report-mark {
  font-family: 'Gowun Batang', serif;
  font-size: 24px; font-weight: 700;
  letter-spacing: 0.15em;
  color: #2d4a3e;
}
.report-mark-sub {
  font-size: 11px; letter-spacing: 0.18em;
  color: #6b6452; margin-top: 4px;
}
.report-title {
  font-family: 'Gowun Batang', serif;
  text-align: center;
  font-size: 26px; font-weight: 700;
  margin: 12px 0 22px;
  letter-spacing: -0.01em;
}
.report-meta {
  width: 100%; border-collapse: collapse;
  font-size: 13px;
}
.report-meta th, .report-meta td {
  border: 1px solid #c4b994;
  padding: 8px 12px;
  text-align: left;
}
.report-meta th {
  background: #ede6d5;
  font-weight: 600;
  width: 14%;
}

.report-section { margin-bottom: 32px; }
.report-h3 {
  font-family: 'Gowun Batang', serif;
  font-size: 18px; font-weight: 700;
  margin: 0 0 14px;
  padding: 6px 12px;
  border-left: 4px solid #2d4a3e;
  background: #f4efe4;
}
.report-table {
  width: 100%; border-collapse: collapse;
  font-size: 13px;
}
.report-table th, .report-table td {
  border: 1px solid #c4b994;
  padding: 10px 12px;
  vertical-align: top;
  text-align: left;
}
.report-table th {
  background: #2d4a3e; color: #fff;
  font-weight: 600;
}
.td-area {
  background: #ede6d5;
  width: 14%;
}

.level-blocks { display: grid; gap: 12px; }
.level-block {
  padding: 14px 18px;
  border: 1px solid #c4b994;
  border-radius: 8px;
  background: #fdfaf2;
}
.level-block-label {
  font-weight: 600; font-size: 13px;
  color: #2d4a3e; margin-bottom: 6px;
}

/* ── 예시 보기 버튼/목록 ── */
.editable-wrap { width: 100%; }
.ex-bar { margin-bottom: 4px; }
.ex-btn {
  font-family: inherit; font-size: 11.5px; font-weight: 600;
  color: #8a6d1f; background: #f9f3e3;
  border: 1px solid #e2cf9e; border-radius: 999px;
  padding: 2px 10px; cursor: pointer; transition: all 0.12s;
}
.ex-btn:hover { background: #f2e8cd; }
.ex-list {
  margin-top: 5px; display: flex; flex-direction: column; gap: 4px;
  padding: 6px; background: #fbf7ec;
  border: 1px solid #e8ddc2; border-radius: 8px;
}
.ex-item {
  text-align: left; font-family: inherit; font-size: 12.5px; line-height: 1.45;
  color: #4a4434; background: #fff;
  border: 1px solid #e4dcc8; border-radius: 6px;
  padding: 6px 9px; cursor: pointer; transition: all 0.12s;
}
.ex-item:hover { border-color: #c19a3a; background: #fffdf6; }

.editable {
  width: 100%;
  background: transparent;
  border: 1px dashed transparent;
  font-family: inherit;
  font-size: 13.5px;
  line-height: 1.55;
  padding: 6px 8px;
  border-radius: 4px;
  color: inherit;
  resize: vertical;
  transition: all 0.15s;
}
.editable.single { resize: none; }
.editable:hover {
  border-color: #d9d1bd;
  background: #fdfaf2;
}
.editable:focus {
  outline: none;
  border-color: #2d4a3e;
  border-style: solid;
  background: #fff;
  box-shadow: 0 0 0 3px rgba(45, 74, 62, 0.08);
}

.goal-recommend {
  display: flex; flex-wrap: wrap; gap: 6px;
  padding: 14px;
  background: #fdfaf2;
  border: 1px dashed #c4b994;
  border-radius: 8px;
  margin-bottom: 18px;
}
.goal-chip {
  display: inline-flex; align-items: center; gap: 6px;
  padding: 6px 10px;
  background: #fff;
  border: 1px solid #d9d1bd;
  border-radius: 16px;
  font-family: inherit; font-size: 12px;
  cursor: pointer;
  transition: all 0.12s;
}
.goal-chip:hover { border-color: #2d4a3e; }
.goal-chip.selected {
  background: #2d4a3e; color: #fff; border-color: #2d4a3e;
}
.goal-chip-id {
  font-family: 'Gowun Batang', serif;
  font-weight: 700; color: #2d4a3e;
  font-size: 11px;
}
.goal-chip.selected .goal-chip-id { color: #c19a3a; }
.goal-chip-score {
  padding: 1px 6px;
  border-radius: 8px;
  font-size: 10px; font-weight: 700;
  background: #ede6d5;
  color: #2d4a3e;
}
.goal-chip-score.score-0 { background: #d4d0c4; color: #fff; }
.goal-chip-score.score-1 { background: #c19a3a; color: #fff; }
.goal-chip.selected .goal-chip-score { background: rgba(255,255,255,0.2); color: #fff; }

.goal-table {
  width: 100%; border-collapse: collapse;
  font-size: 13px;
}
.goal-table th, .goal-table td {
  border: 1px solid #c4b994;
  padding: 8px 12px;
  vertical-align: top;
}
.goal-table th {
  background: #2d4a3e; color: #fff;
  text-align: left; font-weight: 600;
}
.goal-id-tag {
  display: inline-block;
  font-family: 'Gowun Batang', serif;
  font-weight: 700; font-size: 11px;
  color: #2d4a3e;
  padding: 2px 6px;
  background: #ede6d5;
  border-radius: 4px;
  margin-bottom: 4px;
}
.empty-cell {
  color: #b5a888; font-style: italic;
  font-size: 12px;
}
.empty-hint {
  padding: 14px;
  background: #fdfaf2;
  border: 1px dashed #c4b994;
  border-radius: 8px;
  color: #6b6452; font-size: 13px;
}

.compare-table {
  width: 100%; border-collapse: collapse;
  margin-top: 18px;
  font-size: 13px;
}
.compare-table th, .compare-table td {
  border: 1px solid #c4b994;
  padding: 10px 14px;
  text-align: center;
}
.compare-table th {
  background: #2d4a3e; color: #fff; font-weight: 600;
}
.compare-table td:first-child { text-align: left; font-weight: 600; }
.delta-up { color: #2d4a3e; font-weight: 700; }
.delta-down { color: #b54a3a; font-weight: 700; }

.chart-wrap {
  padding: 20px;
  background: #fdfaf2;
  border: 1px solid #c4b994;
  border-radius: 8px;
  margin-bottom: 16px;
}
.comparison-chart { width: 100%; height: auto; }
.bar-pre { fill: #c19a3a; }
.bar-post { fill: #2d4a3e; }
.bar-value {
  font-family: 'Gowun Batang', serif;
  font-size: 11px; font-weight: 700;
  fill: #2a2419;
}
.bar-label {
  font-size: 11px; fill: #2a2419;
  font-weight: 500;
}
.bar-delta {
  font-size: 11px; font-weight: 700;
  fill: #6b6452;
}
.bar-delta.up { fill: #2d4a3e; }
.bar-delta.down { fill: #b54a3a; }
.chart-axis-text { font-size: 10px; fill: #6b6452; }
.chart-legend-text { font-size: 11px; fill: #2a2419; }

.suggestion-list {
  padding-left: 24px;
}
.suggestion-list li {
  padding: 4px 0;
}

.approval-section { margin-top: 40px; }
.approval-consent {
  font-size: 13px; color: #4a4434; line-height: 1.6;
  margin: 0 auto 16px; max-width: 80%; text-align: center;
  padding: 11px 14px; background: #f9f6ef;
  border: 1px solid #e4dcc8; border-radius: 8px;
}
.approval-table {
  width: 80%; margin: 0 auto;
  border-collapse: collapse;
  font-size: 13px;
}
.approval-table th, .approval-table td {
  border: 1px solid #2d4a3e;
  padding: 14px;
  text-align: center;
}
.approval-table th {
  background: #2d4a3e; color: #fff;
}
.signature-cell { height: 60px; color: #b5a888; font-style: italic; }
.approval-footer {
  text-align: center;
  margin-top: 24px;
  font-size: 12px;
  color: #6b6452;
}
.approval-footer-copyright {
  font-size: 10.5px;
  line-height: 1.6;
  color: #8a8270;
  max-width: 620px;
  margin: 0 auto;
}

/* ── ARCHIVE ─────────────────────── */
.archive-list { list-style: none; padding: 0; margin: 0; }
.archive-item {
  display: flex;
  justify-content: space-between; align-items: center;
  padding: 14px 18px;
  background: #fff;
  border: 1px solid #e6e0cd;
  border-radius: 8px;
  margin-bottom: 10px;
}
.archive-meta { flex: 1; }
.archive-name {
  display: flex; align-items: center; gap: 10px;
  font-size: 15px; margin-bottom: 4px;
}
.archive-tag {
  display: inline-block;
  padding: 2px 8px;
  font-size: 10px; font-weight: 700;
  letter-spacing: 0.08em;
  border-radius: 4px;
}
.tag-iep { background: #2d4a3e; color: #fff; }
.tag-interim { background: #c19a3a; color: #fff; }
.archive-stage { font-size: 12px; color: #6b6452; }
.archive-date { font-size: 12px; color: #6b6452; }
.archive-actions { display: flex; gap: 6px; }

/* ── TOAST ─────────────────────── */
.toast {
  position: fixed;
  bottom: 30px; left: 50%;
  transform: translateX(-50%);
  background: #1f1a13; color: #f4efe4;
  padding: 12px 20px;
  border-radius: 8px;
  font-size: 14px; font-weight: 500;
  box-shadow: 0 8px 24px rgba(0,0,0,0.18);
  z-index: 100;
  animation: toastIn 0.2s ease;
}
@keyframes toastIn {
  from { opacity: 0; transform: translateX(-50%) translateY(8px); }
  to { opacity: 1; transform: translateX(-50%) translateY(0); }
}

/* ── FOOTER ─────────────────────── */
.footer {
  max-width: 1320px;
  margin: 0 auto;
  padding: 20px 28px 32px;
  font-size: 12px; color: #6b6452;
  text-align: center;
}
.footer-sub {
  font-size: 10.5px; margin-top: 6px;
  opacity: 0.8;
}

/* ── INTERVIEW TAB ─────────────────────── */
.interview-intro {
  font-size: 13.5px;
  line-height: 1.7;
  padding: 14px 18px;
  background: #fdfaf2;
  border-left: 4px solid #c19a3a;
  border-radius: 4px;
  margin: 0 0 18px;
  color: #2a2419;
}
.interview-meta-table input.interview-input {
  width: 100%; border: none; background: transparent;
  font-family: inherit; font-size: 13.5px;
  padding: 4px 0;
}
.interview-meta-table input.interview-input:focus {
  outline: none; background: #fdfaf2; padding: 4px 6px;
  border-radius: 4px;
}
.interview-nav {
  display: flex; gap: 6px; flex-wrap: wrap;
  margin: 0 0 22px;
  padding: 12px;
  background: #ede6d5;
  border-radius: 10px;
}
.interview-nav-btn {
  padding: 8px 14px;
  background: #fbf8f1;
  border: 1px solid transparent;
  border-radius: 7px;
  font-family: inherit; font-size: 13px;
  cursor: pointer;
  transition: all 0.15s;
}
.interview-nav-btn:hover { background: #fff; border-color: #d9d1bd; }
.interview-nav-btn.active {
  background: #2d4a3e; color: #fff;
  border-color: #2d4a3e;
}
.interview-section.screen-hidden { display: none; }
.interview-questions { display: grid; gap: 22px; }

.iq-row {
  padding: 16px 18px;
  background: #fdfaf2;
  border: 1px solid #e6e0cd;
  border-radius: 8px;
}
.iq-q {
  font-size: 14px; font-weight: 500;
  line-height: 1.6;
  margin-bottom: 12px;
  color: #1f1a13;
}
.iq-idx {
  font-family: 'Gowun Batang', serif;
  color: #2d4a3e;
  font-weight: 700;
  margin-right: 4px;
}
.iq-text {
  width: 100%;
  padding: 8px 10px;
  background: #fff;
  border: 1px solid #d9d1bd;
  border-radius: 6px;
  font-family: inherit; font-size: 13.5px;
  line-height: 1.5;
  resize: vertical;
}
.iq-text:focus {
  outline: none; border-color: #2d4a3e;
  box-shadow: 0 0 0 3px rgba(45, 74, 62, 0.08);
}
.iq-checklist {
  display: grid; gap: 8px;
}
.iq-check-item {
  display: flex; align-items: flex-start;
  gap: 8px;
  font-size: 13.5px;
  cursor: pointer;
}
.iq-check-item input[type="checkbox"] {
  margin-top: 3px;
  width: 16px; height: 16px;
  accent-color: #2d4a3e;
  cursor: pointer;
  flex-shrink: 0;
}
.iq-check-with-text {
  display: grid; gap: 4px;
  padding-top: 4px;
}
.iq-extra-input {
  margin-left: 24px;
  padding: 6px 10px;
  background: #fff;
  border: 1px solid #d9d1bd;
  border-radius: 6px;
  font-family: inherit; font-size: 13px;
}
.iq-frequency-table, .iq-emotion-table, .iq-emotion-pair-table, .iq-scale-table {
  width: 100%;
  border-collapse: collapse;
  font-size: 13px;
}
.iq-frequency-table th, .iq-frequency-table td {
  border: 1px solid #c4b994;
  padding: 8px;
  text-align: center;
}
.iq-frequency-table th {
  background: #ede6d5;
  font-weight: 600; font-size: 12px;
}
.iq-frequency-table td:first-child { text-align: left; }
.iq-freq-cell input[type="radio"] {
  width: 18px; height: 18px;
  accent-color: #2d4a3e;
  cursor: pointer;
}
.iq-emotion-table td, .iq-emotion-pair-table th, .iq-emotion-pair-table td {
  border: 1px solid #c4b994;
  padding: 10px 12px;
  vertical-align: top;
}
.iq-emotion-pair-table th {
  background: #ede6d5;
  text-align: left; font-weight: 600;
}
.iq-emo-label {
  font-weight: 600;
  color: #2d4a3e;
  margin-bottom: 4px;
}
.iq-recovery { display: grid; gap: 12px; }
.iq-recovery-block { padding: 0; }
.iq-recovery-label {
  font-size: 13.5px;
  margin-bottom: 6px;
  color: #1f1a13;
  padding-left: 4px;
}
.iq-scale-table td {
  border: 1px solid #c4b994;
  padding: 8px;
}
.iq-scale-label {
  font-size: 13px;
  padding-left: 12px;
}
.iq-scale-cell {
  text-align: center;
  width: 50px;
}

/* ── OBSERVATION TAB ─────────────────────── */
.obs-table {
  width: 100%;
  border-collapse: collapse;
  font-size: 13px;
}
.obs-table th, .obs-table td {
  border: 1px solid #c4b994;
  padding: 12px 14px;
  vertical-align: top;
  text-align: left;
}
.obs-table th {
  background: #2d4a3e;
  color: #fff;
  font-weight: 600;
}
.obs-label-cell {
  background: #ede6d5;
}
.obs-note {
  font-size: 11.5px;
  color: #6b6452;
  margin-top: 6px;
  line-height: 1.4;
}
.obs-data-cell { background: #fdfaf2; }
.obs-fields { display: grid; gap: 8px; }
.obs-field-label {
  font-size: 11px;
  font-weight: 600;
  color: #6b6452;
  text-transform: uppercase;
  letter-spacing: 0.06em;
  margin-bottom: 2px;
}
.obs-variants { display: grid; gap: 4px; }
.obs-variant-row {
  display: flex; gap: 12px;
  padding: 3px 0;
}
.obs-variant-opt {
  display: flex; align-items: center; gap: 6px;
  font-size: 12px;
  cursor: pointer;
  flex: 1;
}
.obs-variant-opt input[type="radio"] {
  accent-color: #2d4a3e;
  cursor: pointer;
}
.obs-list { display: grid; gap: 6px; }
.obs-list-item {
  display: flex; align-items: center; gap: 8px;
}
.obs-list-num {
  font-family: 'Gowun Batang', serif;
  font-weight: 700;
  color: #2d4a3e;
  width: 20px;
}
.obs-list-input {
  flex: 1;
  padding: 6px 10px;
  background: #fff;
  border: 1px solid #d9d1bd;
  border-radius: 6px;
  font-family: inherit; font-size: 13px;
}

/* ── ACTIVITY TAB ─────────────────────── */
.activity-nav {
  display: flex; gap: 6px;
  margin: 0 0 24px;
  padding: 12px;
  background: #ede6d5;
  border-radius: 10px;
  flex-wrap: wrap;
}
.activity-nav-btn {
  padding: 9px 16px;
  background: #fbf8f1;
  border: 1px solid transparent;
  border-radius: 7px;
  font-family: inherit; font-size: 13px;
  cursor: pointer;
  transition: all 0.15s;
}
.activity-nav-btn:hover { background: #fff; border-color: #d9d1bd; }
.activity-nav-btn.active {
  background: #2d4a3e; color: #fff;
  border-color: #2d4a3e;
}
.logI-tabs {
  display: flex; gap: 6px; flex-wrap: wrap;
  margin-bottom: 20px;
  padding-bottom: 16px;
  border-bottom: 1px dashed #d9d1bd;
}
.logI-tab {
  padding: 7px 14px;
  background: #fff;
  border: 1px solid #d9d1bd;
  border-radius: 7px;
  font-family: inherit; font-size: 13px;
  cursor: pointer;
  transition: all 0.15s;
}
.logI-tab:hover { border-color: #2d4a3e; }
.logI-tab.active {
  background: #2d4a3e; color: #fff; border-color: #2d4a3e;
}
.logI-tab.add {
  background: #fef7e6;
  border-color: #c19a3a;
  color: #6b5320;
  font-weight: 600;
}
.logI-tab.add:hover { background: #fce8b8; }
.rating-select {
  padding: 6px 10px;
  font-family: inherit;
  font-size: 13.5px;
  background: #fff;
  border: 1px solid #d9d1bd;
  border-radius: 6px;
  width: 80px;
}
.rating-select:focus {
  outline: none;
  border-color: #2d4a3e;
}

/* ── ASSESSMENT MODE TOGGLE & ANALYSIS ─────────────────────── */
.assess-mode-toggle {
  display: grid;
  grid-template-columns: repeat(3, 1fr);
  gap: 10px;
  margin: 0 0 24px;
}
.assess-mode-btn {
  text-align: left;
  padding: 16px 18px;
  background: #fbf8f1;
  border: 1.5px solid #d9d1bd;
  border-radius: 10px;
  cursor: pointer;
  font-family: inherit;
  transition: all 0.15s;
}
.assess-mode-btn:hover {
  border-color: #2d4a3e;
  transform: translateY(-1px);
}
.assess-mode-btn.active {
  background: #2d4a3e;
  color: #fff;
  border-color: #2d4a3e;
}
.assess-mode-btn.active .assess-mode-desc { opacity: 0.85; }
.assess-mode-label {
  font-weight: 600;
  font-size: 14px;
  margin-bottom: 4px;
}
.assess-mode-desc {
  font-size: 12px;
  color: #6b6452;
}
.assess-mode-btn.active .assess-mode-desc { color: #e7e0c8; }

.observation-inner { display: grid; gap: 16px; }
.info-box {
  padding: 16px 20px;
  background: #fef7e6;
  border-left: 4px solid #c19a3a;
  border-radius: 6px;
  font-size: 13.5px;
  line-height: 1.6;
}
.info-box em {
  font-style: italic;
  color: #6b5320;
}

.analysis-inner { display: grid; gap: 28px; }
.analysis-block { padding: 0; }
.analysis-h3 {
  font-family: 'Gowun Batang', serif;
  font-size: 18px;
  font-weight: 700;
  margin: 0 0 14px;
  color: #1f1a13;
}
.profile-card {
  padding: 20px 22px;
  background: linear-gradient(135deg, #fdfaf2 0%, #fef7e6 100%);
  border: 1px solid #c4b994;
  border-radius: 10px;
}
.profile-subtitle {
  font-size: 12px;
  font-weight: 600;
  color: #6b5320;
  letter-spacing: 0.06em;
  text-transform: uppercase;
  margin-bottom: 10px;
}
.profile-summary {
  font-size: 14px;
  line-height: 1.7;
  margin: 0 0 14px;
}
.profile-features ul {
  margin: 8px 0 0;
  padding-left: 22px;
}
.profile-features li {
  font-size: 13.5px;
  padding: 3px 0;
}

.mrsr-bars {
  display: grid;
  gap: 14px;
  margin-bottom: 18px;
}
.mrsr-bar {
  display: grid;
  grid-template-columns: 200px 1fr 60px;
  align-items: center;
  gap: 14px;
}
.mrsr-bar-label {
  font-size: 13.5px;
  font-weight: 600;
}
.mrsr-bar-track {
  height: 22px;
  background: #ede6d5;
  border-radius: 12px;
  overflow: hidden;
}
.mrsr-bar-fill {
  height: 100%;
  border-radius: 12px;
  transition: width 0.3s ease;
}
.mrsr-bar-fill.mr { background: linear-gradient(90deg, #c19a3a 0%, #d4a843 100%); }
.mrsr-bar-fill.sr { background: linear-gradient(90deg, #2d4a3e 0%, #3b5f50 100%); }
.mrsr-bar-pct {
  font-family: 'Gowun Batang', serif;
  font-weight: 700;
  text-align: right;
  color: #2d4a3e;
}
.pattern-card {
  padding: 18px 22px;
  background: #fff;
  border: 1px solid #c4b994;
  border-radius: 10px;
  border-left: 4px solid #2d4a3e;
}
.pattern-title {
  font-family: 'Gowun Batang', serif;
  font-size: 16px;
  font-weight: 700;
  color: #2d4a3e;
  margin-bottom: 8px;
}
.pattern-interpretation {
  font-size: 13.5px;
  line-height: 1.7;
  margin: 0 0 14px;
  color: #2a2419;
}
.strategy-list {
  margin: 6px 0 0;
  padding-left: 22px;
}
.strategy-list li {
  font-size: 13.5px;
  padding: 4px 0;
  line-height: 1.55;
}

.radar-wrap {
  display: flex;
  justify-content: center;
  padding: 16px;
  background: #fdfaf2;
  border: 1px solid #c4b994;
  border-radius: 10px;
}
.ses-radar {
  width: 100%;
  max-width: 440px;
  height: auto;
}
.radar-label {
  font-size: 11.5px;
  font-weight: 500;
  fill: #2a2419;
}
.radar-value {
  font-family: 'Gowun Batang', serif;
  font-size: 10.5px;
  font-weight: 700;
  fill: #2d4a3e;
}

/* ── 발달 의존성 경고 ─────────────────────── */
.score-row.has-warning {
  background: #fef0e0;
}
.prereq-warning {
  display: inline-block;
  margin-left: 10px;
  padding: 1px 8px;
  background: #b54a3a;
  color: #fff;
  font-size: 10.5px;
  font-weight: 600;
  border-radius: 10px;
  letter-spacing: 0.02em;
}

/* ── 단계별 특징 박스 (보고서 자동 삽입) ─────────────────────── */
.stage-profile-box {
  padding: 22px 26px;
  background: #fdfaf2;
  border: 1px solid #c4b994;
  border-left: 5px solid #2d4a3e;
  border-radius: 10px;
  margin-bottom: 28px;
}
.stage-profile-header {
  margin-bottom: 12px;
}
.stage-profile-eyebrow {
  font-size: 11px;
  font-weight: 700;
  letter-spacing: 0.18em;
  text-transform: uppercase;
  color: #2d4a3e;
  margin-bottom: 6px;
}
.stage-profile-title {
  font-family: 'Gowun Batang', serif;
  font-size: 22px;
  font-weight: 700;
  margin: 0 0 4px;
  color: #1f1a13;
}
.stage-profile-meta {
  font-size: 12.5px;
  color: #6b6452;
}
.stage-profile-divider { margin: 0 8px; opacity: 0.5; }
.stage-profile-summary {
  font-size: 14px;
  line-height: 1.7;
  margin: 12px 0 18px;
}
.stage-profile-cols {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 22px;
}
.stage-profile-col strong {
  display: block;
  font-size: 12.5px;
  font-weight: 700;
  color: #2d4a3e;
  margin-bottom: 8px;
  padding-bottom: 4px;
  border-bottom: 1px solid #c4b994;
}
.stage-profile-col ul {
  margin: 0;
  padding-left: 18px;
}
.stage-profile-col li {
  font-size: 13px;
  padding: 3px 0;
  line-height: 1.55;
}

/* ── 우선순위 칩 개선 ─────────────────────── */
.goal-chip.foundation {
  background: #fef7e6;
  border-color: #c19a3a;
}
.goal-chip.foundation .goal-chip-id { color: #6b5320; }
.goal-chip.prereq-unmet {
  opacity: 0.7;
  border-style: dashed;
}
.goal-rank {
  display: inline-block;
  font-family: 'Gowun Batang', serif;
  font-weight: 700;
  font-size: 11px;
  color: #fff;
  background: #2d4a3e;
  padding: 1px 7px;
  border-radius: 8px;
  margin-right: 2px;
}
.goal-chip.selected .goal-rank { background: #c19a3a; color: #fff; }
.goal-tag {
  font-size: 12px;
  margin-right: 2px;
}
.legend-tag {
  display: inline-block;
  margin: 0 4px;
  padding: 1px 8px;
  border-radius: 8px;
  font-size: 11px;
  font-weight: 600;
}
.legend-tag.found { background: #fef7e6; color: #6b5320; border: 1px solid #c19a3a; }
.legend-tag.prereq { background: #fef0e0; color: #6b3520; border: 1px solid #b54a3a; }
.legend-tag.partner-legend { background: #e8f0f7; color: #2a4a6b; border: 1px solid #5a7ba0; }
.goal-chip.partner-domain { background: #f1f6fb; border-color: #c2d4e6; }
.goal-chip.partner-domain.selected { background: #4a6b8a; border-color: #3a587a; color: #fff; }
.goal-chip.partner-domain.selected .goal-chip-id { color: #d9e6f2; }
.goal-tag.partner-tag { background: #2a4a6b; color: #fff; }
.legend-tag.family { background: #fde6e6; color: #6b2020; border: 1px solid #c14a4a; }

/* ── 가족 우선순위 (SCERTS 원전 양식) ───────────────────── */
.family-priorities-grid {
  display: grid;
  gap: 14px;
  margin-top: 16px;
}
.fp-question {
  padding: 14px 18px;
  background: #fff;
  border: 1px solid #e6e0cd;
  border-radius: 8px;
}
.fp-q-label {
  font-size: 13.5px;
  font-weight: 600;
  margin-bottom: 8px;
  color: #1f1a13;
  line-height: 1.55;
}
.fp-item-select {
  margin-top: 18px;
  padding: 16px 18px;
  background: #fef7e6;
  border: 1px dashed #c19a3a;
  border-radius: 8px;
}
.goal-chip.family-choice {
  background: #fde6e6;
  border-color: #c14a4a;
  color: #6b2020;
}
.goal-chip.family-choice.selected {
  background: #c14a4a;
  color: #fff;
  border-color: #c14a4a;
}
.goal-chip.family-choice .goal-chip-id { color: #6b2020; }
.goal-chip.family-choice.selected .goal-chip-id { color: #fde6e6; }

/* ── 다중 아동 - 헤더 셀렉터 ─────────── */
.child-selector { position: relative; }
.btn-child-selector {
  display: inline-flex; align-items: center; gap: 8px;
  padding: 7px 14px;
  background: #fdfaf2;
  border: 1px solid #c4b994;
  border-radius: 8px;
  font-family: inherit; font-size: 13px;
  cursor: pointer;
  transition: all 0.15s;
}
.btn-child-selector:hover { background: #fff; border-color: #2d4a3e; }
.child-name {
  font-weight: 600;
  color: #2d4a3e;
  max-width: 120px;
  white-space: nowrap; overflow: hidden; text-overflow: ellipsis;
}
.child-count {
  font-size: 11px;
  padding: 1px 7px;
  background: #2d4a3e; color: #fff;
  border-radius: 10px;
  font-weight: 500;
}
.child-dropdown-arrow { font-size: 11px; opacity: 0.6; }
.child-menu-backdrop {
  position: fixed; inset: 0; z-index: 50;
}
.child-menu {
  position: absolute; right: 0; top: calc(100% + 8px);
  z-index: 51;
  min-width: 260px;
  background: #fff;
  border: 1px solid #c4b994;
  border-radius: 10px;
  box-shadow: 0 8px 30px rgba(0,0,0,0.12);
  padding: 8px;
}
.child-menu-header {
  padding: 6px 10px 10px;
  font-size: 11px; font-weight: 700;
  letter-spacing: 0.12em;
  text-transform: uppercase;
  color: #6b6452;
  border-bottom: 1px solid #ede6d5;
  margin-bottom: 6px;
}
.child-menu-list {
  max-height: 280px; overflow-y: auto;
}
.child-menu-item {
  display: flex; align-items: center; gap: 4px;
  border-radius: 6px;
  transition: background 0.1s;
}
.child-menu-item:hover { background: #fdfaf2; }
.child-menu-item.active { background: #ede6d5; }
.child-menu-name {
  flex: 1; display: flex; align-items: center; gap: 8px;
  padding: 8px 10px;
  text-align: left;
  background: transparent; border: none; cursor: pointer;
  font-family: inherit; font-size: 13.5px;
  color: #1f1a13;
}
.child-menu-mark {
  font-size: 10px;
  color: #2d4a3e;
}
.child-menu-stage {
  margin-left: auto;
  font-size: 11px;
  padding: 1px 7px;
  background: #fef7e6;
  color: #6b5320;
  border-radius: 8px;
}
.child-menu-birth {
  font-size: 11px;
  color: #9a917d;
  margin-left: 6px;
  white-space: nowrap;
}
.child-card-birth {
  font-size: 12px;
  color: #9a917d;
  margin-top: 2px;
}
.child-menu-remove {
  width: 28px; height: 28px;
  border: none; background: transparent;
  border-radius: 4px;
  color: #b54a3a;
  cursor: pointer;
  font-size: 16px;
  opacity: 0.5;
}
.child-menu-remove:hover { opacity: 1; background: #fef0e0; }
.child-menu-add {
  width: 100%;
  margin-top: 6px;
  padding: 9px;
  background: #fef7e6;
  border: 1px dashed #c19a3a;
  border-radius: 7px;
  color: #6b5320; font-weight: 600;
  font-family: inherit; font-size: 13px;
  cursor: pointer;
}
.child-menu-add:hover { background: #fce8b8; }
.child-menu-sample {
  width: 100%; padding: 9px; margin-top: 4px;
  background: #eef3ef; border: 1px solid #cfe0d4; border-radius: 8px;
  color: #2d4a3e; font-family: inherit; font-size: 12.5px; font-weight: 600;
  cursor: pointer;
}
.child-menu-sample:hover { background: #dfeae1; }
.child-menu-sample-group { display: flex; flex-direction: column; gap: 4px; margin-top: 4px; padding-top: 8px; border-top: 1px solid #e4dcc8; }
.child-menu-sample-label { font-size: 11px; color: #8a8270; padding: 2px 4px 4px; }
.report-date-input {
  padding: 3px 7px; border: 1px solid #d9d1bd; border-radius: 6px;
  font-family: inherit; font-size: 13px; background: #fff;
}

/* ── 다중 아동 - 홈 카드 그리드 ─────── */
.section-title-row {
  display: flex; justify-content: space-between; align-items: center;
  margin-bottom: 14px;
}
.btn-small {
  padding: 6px 14px;
  font-size: 12.5px;
  border-radius: 7px;
}
.child-card-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(220px, 1fr));
  gap: 14px;
}
.child-card {
  position: relative;
  background: #fdfaf2;
  border: 1.5px solid #d9d1bd;
  border-radius: 12px;
  overflow: hidden;
  transition: all 0.15s;
  font-family: inherit;
}
.child-card:hover { transform: translateY(-2px); box-shadow: 0 4px 12px rgba(0,0,0,0.06); }
.child-card.active {
  border-color: #2d4a3e;
  background: #fff;
  box-shadow: 0 4px 16px rgba(45, 74, 62, 0.12);
}
.child-card-main {
  display: block;
  width: 100%;
  padding: 18px 18px 16px;
  background: transparent; border: none;
  text-align: left; cursor: pointer;
  font-family: inherit;
}
.child-card-name {
  font-family: 'Gowun Batang', serif;
  font-size: 18px; font-weight: 700;
  color: #1f1a13;
  margin-bottom: 4px;
}
.child-card-stage {
  font-size: 12px;
  color: #6b6452;
  padding-bottom: 12px;
  border-bottom: 1px dashed #d9d1bd;
  margin-bottom: 12px;
}
.child-card-stats {
  display: flex;
  gap: 16px;
}
.child-card-stat {
  display: flex; flex-direction: column;
  font-family: 'Gowun Batang', serif;
}
.stat-num {
  font-size: 18px;
  font-weight: 700;
  color: #2d4a3e;
}
.stat-label {
  font-size: 10.5px;
  color: #6b6452;
  font-family: 'IBM Plex Sans KR', sans-serif;
}
.child-card-active-mark {
  position: absolute;
  top: 12px; right: 12px;
  font-size: 10px;
  font-weight: 700;
  color: #2d4a3e;
  background: #fef7e6;
  padding: 2px 8px;
  border-radius: 10px;
}
.child-card-add {
  display: flex; flex-direction: column; align-items: center; justify-content: center;
  background: #fef7e6;
  border: 2px dashed #c19a3a;
  cursor: pointer;
  min-height: 130px;
}
.child-card-add:hover { background: #fce8b8; transform: translateY(-2px); }
.child-card-add-icon {
  font-size: 36px;
  font-weight: 300;
  color: #c19a3a;
  line-height: 1;
}
.child-card-add-label {
  margin-top: 6px;
  font-size: 13px;
  color: #6b5320;
  font-weight: 600;
}

/* ── 진단 세션 탭 ────────────────────── */
.session-tabs-container {
  margin-bottom: 20px;
  padding: 14px 16px;
  background: #fdfaf2;
  border: 1px solid #c4b994;
  border-radius: 10px;
}
.session-tabs-header {
  display: flex; align-items: center; gap: 12px;
  margin-bottom: 10px;
}
.session-tabs-label {
  font-weight: 700;
  font-size: 13px;
  color: #2d4a3e;
}
.session-tabs-hint {
  font-size: 11.5px;
  color: #6b6452;
}
.session-tabs {
  display: flex; gap: 6px; flex-wrap: wrap;
}
.session-tab {
  display: inline-flex; align-items: stretch;
  background: #fff;
  border: 1px solid #d9d1bd;
  border-radius: 7px;
  overflow: hidden;
}
.session-tab.active {
  border-color: #2d4a3e;
  box-shadow: 0 1px 4px rgba(45,74,62,0.15);
}
.session-tab.designated.pre { border-color: #c19a3a; }
.session-tab.designated.post { border-color: #2d4a3e; }
.session-tab-main {
  display: inline-flex; align-items: center; gap: 6px;
  padding: 6px 12px;
  background: transparent; border: none;
  cursor: pointer;
  font-family: inherit; font-size: 13px;
}
.session-tab.active .session-tab-main { background: #2d4a3e; color: #fff; }
.session-tab-name { font-weight: 500; }
.session-tab-meta {
  font-size: 11px;
  color: #6b6452;
  padding: 0 5px;
  background: #ede6d5;
  border-radius: 8px;
}
.session-tab.active .session-tab-meta { background: rgba(255,255,255,0.2); color: #fff; }
.session-badge {
  font-size: 10px;
  font-weight: 700;
  padding: 1px 6px;
  border-radius: 6px;
}
.session-badge.pre { background: #c19a3a; color: #fff; }
.session-badge.post { background: #2d4a3e; color: #fff; }
.session-tab.active .session-badge.pre { background: #fef7e6; color: #6b5320; }
.session-tab.active .session-badge.post { background: #fff; color: #2d4a3e; }
.session-tab-designate, .session-tab-remove {
  width: 26px;
  background: transparent;
  border: none;
  border-left: 1px solid #ede6d5;
  cursor: pointer;
  font-size: 13px;
  color: #6b6452;
}
.session-tab-designate:hover { background: #fef7e6; color: #6b5320; }
.session-tab-remove:hover { background: #fef0e0; color: #b54a3a; }
.session-tab.active .session-tab-designate,
.session-tab.active .session-tab-remove {
  border-left-color: rgba(255,255,255,0.2);
  color: rgba(255,255,255,0.7);
}
.session-tab-add {
  padding: 6px 12px;
  background: #fef7e6;
  border: 1px dashed #c19a3a;
  border-radius: 7px;
  color: #6b5320; font-weight: 600;
  font-family: inherit; font-size: 13px;
  cursor: pointer;
}
.session-tab-add:hover { background: #fce8b8; }

/* ── 진전 추적 시계열 차트 ───────────── */
.progress-timeline-wrap {
  padding: 16px;
  background: #fdfaf2;
  border: 1px solid #c4b994;
  border-radius: 10px;
}
.timeline-header { margin-bottom: 12px; }
.timeline-chart {
  width: 100%;
  height: auto;
  max-width: 100%;
}
.timeline-axis-label {
  font-size: 10.5px;
  fill: #6b6452;
  font-family: 'Gowun Batang', serif;
}
.timeline-x-label {
  font-size: 11px;
  fill: #2a2419;
  font-weight: 500;
}
.timeline-designation {
  font-size: 10px;
  font-weight: 700;
}
.timeline-legend {
  font-size: 11.5px;
  fill: #2a2419;
}
.goal-progress-table { padding: 0; }
.mini-pip {
  display: inline-block;
  min-width: 22px; padding: 2px 6px;
  border-radius: 50%;
  font-family: 'Gowun Batang', serif;
  font-weight: 700;
  font-size: 12px;
}
.mini-pip.score-0 { background: #fef0e0; color: #b54a3a; }
.mini-pip.score-1 { background: #fef7e6; color: #c19a3a; }
.mini-pip.score-2 { background: #d9e8df; color: #2d4a3e; }
.delta-up { color: #2d4a3e; font-weight: 700; }
.delta-down { color: #b54a3a; font-weight: 700; }
.delta-same { color: #6b6452; }

/* ── 활동 통계 ─────────────────────── */
.activity-stats { display: grid; gap: 20px; }
.stats-summary-grid {
  display: grid;
  grid-template-columns: repeat(4, 1fr);
  gap: 12px;
}
.stats-summary-card {
  padding: 18px 16px;
  background: #fdfaf2;
  border: 1px solid #c4b994;
  border-radius: 10px;
  text-align: center;
}
.stats-summary-card.mastered { background: #d9e8df; border-color: #2d4a3e; }
.stats-summary-card.stalled { background: #fef0e0; border-color: #b54a3a; }
.stats-num {
  font-family: 'Gowun Batang', serif;
  font-size: 30px;
  font-weight: 700;
  color: #2d4a3e;
  line-height: 1;
  margin-bottom: 6px;
}
.stats-summary-card.mastered .stats-num { color: #2d4a3e; }
.stats-summary-card.stalled .stats-num { color: #b54a3a; }
.stats-label {
  font-size: 12px;
  color: #6b6452;
  font-weight: 500;
}
.stats-table .rating-cell {
  display: inline-block;
  min-width: 22px;
  padding: 1px 8px;
  border-radius: 50%;
  font-family: 'Gowun Batang', serif;
  font-weight: 700;
  font-size: 12px;
}
.rating-cell.plus { background: #d9e8df; color: #2d4a3e; }
.rating-cell.partial { background: #fef7e6; color: #c19a3a; }
.rating-cell.minus { background: #fef0e0; color: #b54a3a; }
.status-badge {
  display: inline-block;
  padding: 2px 8px;
  border-radius: 10px;
  font-size: 11.5px;
  font-weight: 600;
}
.status-mastered { background: #d9e8df; color: #2d4a3e; }
.status-progressing { background: #fef7e6; color: #c19a3a; }
.status-stalled { background: #fef0e0; color: #b54a3a; }
.status-early { background: #ede6d5; color: #6b6452; }
.status-noData { color: #b5a888; }
.stats-row-stalled { background: #fef0e040; }
.stats-row-mastered { background: #d9e8df30; }

.month-distribution {
  display: grid; gap: 8px;
  padding: 12px 0;
}
.month-bar { display: grid; grid-template-columns: 80px 1fr; align-items: center; gap: 12px; }
.month-label { font-family: 'Gowun Batang', serif; font-weight: 600; font-size: 13px; }
.month-bar-bar {
  height: 24px;
  background: #ede6d5;
  border-radius: 12px;
  overflow: hidden;
}
.month-bar-fill {
  height: 100%;
  background: linear-gradient(90deg, #2d4a3e 0%, #3b5f50 100%);
  color: #fff;
  display: flex; align-items: center;
  padding: 0 12px;
  font-size: 11.5px;
  font-weight: 600;
  border-radius: 12px;
  min-width: 36px;
}

/* ── 보관함 검색·필터 ─────────────────── */
.archive-filter-bar {
  display: grid; gap: 10px;
  margin: 12px 0 18px;
  padding: 14px;
  background: #ede6d5;
  border-radius: 10px;
}
.archive-search {
  position: relative;
  display: flex; align-items: center;
}
.archive-search-icon {
  position: absolute; left: 12px;
  font-size: 14px;
  pointer-events: none;
}
.archive-search-input {
  width: 100%;
  padding: 10px 36px 10px 38px;
  background: #fff;
  border: 1px solid #d9d1bd;
  border-radius: 8px;
  font-family: inherit; font-size: 13.5px;
}
.archive-search-input:focus {
  outline: none; border-color: #2d4a3e;
  box-shadow: 0 0 0 3px rgba(45,74,62,0.1);
}
.archive-search-clear {
  position: absolute; right: 6px;
  width: 28px; height: 28px;
  background: transparent; border: none;
  font-size: 16px;
  cursor: pointer;
  color: #6b6452;
  border-radius: 4px;
}
.archive-search-clear:hover { background: #ede6d5; }
.archive-filter-group {
  display: flex; gap: 8px;
  flex-wrap: wrap;
}
.archive-filter-select {
  padding: 7px 12px;
  background: #fff;
  border: 1px solid #d9d1bd;
  border-radius: 7px;
  font-family: inherit; font-size: 12.5px;
  cursor: pointer;
}
.archive-filter-select:focus {
  outline: none; border-color: #2d4a3e;
}

/* ── SAP 요약지 ─────────────────────── */
.sap-table {
  width: 100%;
  border-collapse: collapse;
  font-size: 13px;
}
.sap-table th, .sap-table td {
  border: 1px solid #c4b994;
  padding: 10px 12px;
  vertical-align: middle;
}
.sap-table th {
  background: #2d4a3e;
  color: #fff;
  font-weight: 600;
  text-align: center;
}
.sap-area, .sap-area-name {
  text-align: left;
  font-weight: 500;
}
.sap-session-col {
  text-align: center;
  min-width: 110px;
}
.sap-session-label {
  font-weight: 600;
  font-size: 13.5px;
}
.sap-session-date {
  font-size: 11px;
  opacity: 0.85;
  margin-top: 2px;
}
.sap-session-badge {
  display: inline-block;
  margin-top: 4px;
  padding: 1px 8px;
  font-size: 10px;
  font-weight: 700;
  border-radius: 8px;
}
.sap-pre { background: #c19a3a; color: #fff; }
.sap-post { background: #fef7e6; color: #2d4a3e; }
.sap-group-row td {
  background: #ede6d5;
  font-size: 13px;
  padding: 8px 12px;
  color: #1f1a13;
}
.sap-area-name {
  padding-left: 22px;
  font-size: 12.5px;
}
.sap-score-cell { text-align: center; }
.sap-score-block {
  display: inline-block;
  text-align: center;
}
.sap-score-frac {
  font-family: 'Gowun Batang', serif;
  font-size: 13px;
  font-weight: 500;
  color: #1f1a13;
}
.sap-score-pct {
  font-size: 11px;
  color: #6b6452;
  margin-top: 1px;
}
.sap-bold .sap-score-frac { font-weight: 700; font-size: 14px; color: #2d4a3e; }
.sap-large .sap-score-frac { font-size: 17px; }
.sap-large .sap-score-pct { font-size: 13px; font-weight: 600; color: #2d4a3e; }
.sap-subtotal-row td {
  background: #fdfaf2;
  border-top: 2px solid #c4b994;
}
.sap-total-row td {
  background: #d9e8df;
  border-top: 2px solid #2d4a3e;
  border-bottom: 2px solid #2d4a3e;
  padding: 14px 12px;
}
.sap-total-row .sap-area-name {
  font-weight: 700;
  font-size: 14px;
  color: #2d4a3e;
}

/* ── 활동 일지 검색 ─────────────────── */
.logI-search {
  display: flex; align-items: center; gap: 4px;
  margin-bottom: 12px;
  padding: 10px 12px;
  background: #ede6d5;
  border-radius: 8px;
  position: relative;
}
.logI-search-count {
  font-size: 12px;
  color: #6b6452;
  font-weight: 600;
  padding-left: 10px;
  margin-left: auto;
  white-space: nowrap;
}

/* ── 협력 계획서 카드 ────────────────── */
.collab-card-grid {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 14px;
  margin-top: 12px;
}
.collab-card {
  padding: 22px 20px;
  background: #fdfaf2;
  border: 1.5px solid #c4b994;
  border-radius: 12px;
  text-align: left;
  cursor: pointer;
  font-family: inherit;
  transition: all 0.15s;
}
/* SCERTS 권장 카드 (가족 지원) — 금색 강조 + 배지 */
.collab-card-recommended {
  position: relative;
  border-color: #c19a3a;
  background: #fefaf0;
  box-shadow: 0 2px 10px rgba(193, 154, 58, 0.12);
}
.collab-card-recommended:hover { border-color: #a07f25; }
.collab-card-badge {
  position: absolute; top: -10px; left: 16px;
  font-size: 11px; font-weight: 700;
  color: #fff; background: #c19a3a;
  padding: 3px 10px; border-radius: 999px;
  letter-spacing: 0.02em;
}
.collab-card:hover {
  background: #fff;
  border-color: #2d4a3e;
  transform: translateY(-2px);
  box-shadow: 0 4px 16px rgba(0,0,0,0.06);
}
.collab-card-icon {
  font-size: 32px;
  margin-bottom: 10px;
  line-height: 1;
}
.collab-card-title {
  font-family: 'Gowun Batang', serif;
  font-size: 16px;
  font-weight: 700;
  color: #2d4a3e;
  margin-bottom: 4px;
}
.collab-card-desc {
  font-size: 12px;
  color: #6b6452;
  line-height: 1.5;
}

/* 가족 지원 양식 - 교육 주제 칩 */
.education-topics {
  display: flex; flex-wrap: wrap; gap: 8px;
}
.topic-chip {
  display: inline-flex; align-items: center; gap: 6px;
  padding: 6px 12px;
  background: #fff;
  border: 1px solid #d9d1bd;
  border-radius: 18px;
  font-size: 12.5px;
  cursor: pointer;
  transition: all 0.15s;
}
.topic-chip:hover { border-color: #c19a3a; }
.topic-chip.selected {
  background: #2d4a3e;
  border-color: #2d4a3e;
  color: #fff;
}
.topic-chip input { display: none; }

/* ── 데이터 무결성 ───────────────────── */
.integrity-clean {
  display: flex; align-items: center; gap: 8px;
  padding: 14px 16px;
  background: #d9e8df;
  border: 1px solid #2d4a3e;
  border-radius: 8px;
  font-size: 13.5px;
}
.integrity-clean-icon {
  display: inline-flex;
  width: 24px; height: 24px;
  background: #2d4a3e;
  color: #fff;
  border-radius: 50%;
  align-items: center; justify-content: center;
  font-weight: 700;
}
.integrity-issues {
  border: 1px solid #c19a3a;
  border-radius: 8px;
  overflow: hidden;
}
.integrity-header {
  display: flex; flex-direction: column;
  padding: 12px 16px;
  background: #fef7e6;
  border-bottom: 1px solid #c19a3a;
}
.integrity-hint {
  font-size: 12px;
  color: #6b6452;
  margin-top: 2px;
}
.integrity-item {
  padding: 12px 16px;
  border-bottom: 1px solid #ede6d5;
  background: #fff;
}
.integrity-item:last-child { border-bottom: none; }
.integrity-item.severity-high { background: #fef0e0; }
.integrity-item.severity-medium { background: #fef7e6; }
.integrity-msg {
  font-size: 13px;
  line-height: 1.5;
  margin-bottom: 4px;
}
.integrity-severity {
  display: inline-block;
  font-size: 10.5px;
  font-weight: 700;
  padding: 2px 7px;
  border-radius: 8px;
  margin-right: 8px;
}
.sev-high { background: #b54a3a; color: #fff; }
.sev-medium { background: #c19a3a; color: #fff; }
.sev-low { background: #ede6d5; color: #6b6452; }
.integrity-hint-text {
  font-size: 12px;
  color: #6b6452;
  font-style: italic;
}

.btn-icon {
  width: 24px; height: 24px;
  background: transparent;
  border: 1px solid transparent;
  border-radius: 4px;
  color: #b54a3a;
  cursor: pointer;
  font-size: 14px;
}
.btn-icon:hover { background: #fef0e0; border-color: #b54a3a; }

/* ── Undo/Redo 툴바 버튼 ─────────────── */
.btn-icon-toolbar {
  width: 32px; height: 32px;
  background: transparent;
  border: 1px solid #c4b994;
  border-radius: 7px;
  color: #2d4a3e;
  cursor: pointer;
  font-size: 18px;
  display: inline-flex; align-items: center; justify-content: center;
  transition: all 0.15s;
}
.btn-icon-toolbar:hover:not(:disabled) {
  background: #fff;
  border-color: #2d4a3e;
}
.btn-icon-toolbar:disabled {
  opacity: 0.35;
  cursor: not-allowed;
}

/* ── 내보내기 메뉴 ──────────────────── */
.export-menu-wrap { position: relative; }
.export-menu {
  position: absolute; right: 0; top: calc(100% + 8px);
  z-index: 51;
  min-width: 240px;
  background: #fff;
  border: 1px solid #c4b994;
  border-radius: 10px;
  box-shadow: 0 8px 30px rgba(0,0,0,0.12);
  padding: 6px;
}
.export-menu-item {
  display: block;
  width: 100%;
  padding: 10px 12px;
  background: transparent;
  border: none;
  border-radius: 6px;
  text-align: left;
  cursor: pointer;
  font-family: inherit;
}
.export-menu-item:hover { background: #fdfaf2; }
.export-menu-item strong {
  display: block;
  font-size: 13.5px;
  color: #2d4a3e;
  margin-bottom: 3px;
}
.export-menu-desc {
  font-size: 11.5px;
  color: #6b6452;
}

/* ── 백업 패널 ─────────────────────── */
/* ── 앱 다이얼로그 (커스텀 confirm/prompt/alert) ── */
.app-dialog-overlay {
  position: fixed; inset: 0;
  background: rgba(20, 16, 10, 0.55);
  display: flex; align-items: center; justify-content: center;
  z-index: 9999;
  padding: 20px;
}
.app-dialog {
  width: 100%; max-width: 440px;
  background: #fdfaf2;
  border: 1px solid #c4b994;
  border-radius: 14px;
  padding: 24px;
  box-shadow: 0 12px 48px rgba(0,0,0,0.25);
}
.app-dialog-message {
  font-size: 14px;
  line-height: 1.7;
  color: #1f1a13;
  white-space: pre-wrap;
  margin-bottom: 18px;
}
.app-dialog-input {
  width: 100%;
  padding: 10px 12px;
  border: 1px solid #c4b994;
  border-radius: 8px;
  font-family: inherit;
  font-size: 14px;
  margin-bottom: 18px;
  box-sizing: border-box;
}
.app-dialog-input:focus {
  outline: none;
  border-color: #2d4a3e;
  box-shadow: 0 0 0 3px rgba(45,74,62,0.12);
}
.app-dialog-actions {
  display: flex;
  justify-content: flex-end;
  gap: 10px;
}

.backup-panel-overlay {
  position: fixed; inset: 0;
  background: rgba(20, 16, 10, 0.55);
  display: flex; align-items: center; justify-content: center;
  z-index: 100;
  padding: 20px;
}
.backup-panel {
  width: 100%; max-width: 600px;
  max-height: 80vh;
  background: #fdfaf2;
  border: 1px solid #c4b994;
  border-radius: 14px;
  display: flex; flex-direction: column;
  overflow: hidden;
}
.backup-panel-header {
  display: flex; justify-content: space-between; align-items: center;
  padding: 18px 20px 14px;
  border-bottom: 1px solid #ede6d5;
}
.backup-panel-header h2 {
  margin: 0;
  font-family: 'Gowun Batang', serif;
  font-size: 18px;
  color: #2d4a3e;
}
.backup-close-btn {
  width: 32px; height: 32px;
  background: transparent;
  border: none;
  border-radius: 6px;
  font-size: 22px;
  color: #6b6452;
  cursor: pointer;
}
.backup-close-btn:hover { background: #ede6d5; }
.backup-list {
  flex: 1;
  overflow-y: auto;
  padding: 0 20px 20px;
}
.backup-item {
  display: flex; justify-content: space-between; align-items: center;
  padding: 14px 16px;
  background: #fff;
  border: 1px solid #ede6d5;
  border-radius: 8px;
  margin-bottom: 8px;
}
.backup-item-info { flex: 1; }
.backup-item-time {
  display: flex; align-items: baseline; gap: 10px;
  margin-bottom: 3px;
}
.backup-item-time strong {
  font-family: 'Gowun Batang', serif;
  font-size: 14px;
  color: #2d4a3e;
}
.backup-item-date {
  font-size: 11.5px;
  color: #6b6452;
}
.backup-item-meta {
  font-size: 12px;
  color: #6b6452;
}
.backup-item-actions {
  display: flex; gap: 6px;
}

/* ── 빈 상태 안내 ───────────────────── */
.empty-state-guide {
  background: linear-gradient(135deg, #fef7e6 0%, #fdfaf2 100%);
  border: 1px solid #c4b994;
  border-radius: 16px;
  padding: 36px 32px;
  margin-bottom: 22px;
  text-align: center;
}
.esg-icon {
  font-size: 56px;
  line-height: 1;
  margin-bottom: 12px;
}
.esg-title {
  font-family: 'Gowun Batang', serif;
  font-size: 24px;
  color: #2d4a3e;
  margin: 0 0 8px;
}
.esg-sub {
  font-size: 14px;
  color: #6b6452;
  margin: 0 0 28px;
}
.esg-steps {
  display: grid;
  grid-template-columns: repeat(2, 1fr);
  gap: 14px;
  margin-bottom: 24px;
  text-align: left;
}
.esg-step {
  display: flex; gap: 14px; align-items: flex-start;
  padding: 16px;
  background: #fff;
  border: 1px solid #ede6d5;
  border-radius: 10px;
}
.esg-step-num {
  width: 32px; height: 32px;
  flex-shrink: 0;
  display: flex; align-items: center; justify-content: center;
  background: #2d4a3e;
  color: #fff;
  font-family: 'Gowun Batang', serif;
  font-weight: 700;
  border-radius: 50%;
  font-size: 15px;
}
.esg-step-title {
  font-weight: 700;
  font-size: 14px;
  color: #2d4a3e;
  margin-bottom: 3px;
}
.esg-step-desc {
  font-size: 12.5px;
  color: #6b6452;
  line-height: 1.5;
}
.esg-cta {
  padding: 12px 32px;
  font-size: 14px;
  margin-bottom: 24px;
}
.esg-tips {
  text-align: left;
  padding: 16px 20px;
  background: #fff;
  border: 1px dashed #c4b994;
  border-radius: 10px;
  max-width: 600px;
  margin: 0 auto;
}
.esg-tips strong {
  display: block;
  font-size: 13px;
  color: #2d4a3e;
  margin-bottom: 8px;
}
.esg-tips ul {
  margin: 0; padding-left: 18px;
  font-size: 12.5px;
  color: #6b6452;
  line-height: 1.7;
}
.esg-tips li { margin-bottom: 2px; }

/* ── 회기 → 진단 자동 제안 ────────── */
.session-suggestion-bar {
  display: flex; justify-content: space-between; align-items: center;
  gap: 16px;
  margin: 14px 0 18px;
  padding: 14px 18px;
  background: linear-gradient(135deg, #fef7e6 0%, #fdfaf2 100%);
  border: 1.5px solid #c19a3a;
  border-radius: 10px;
  animation: gentle-pulse 3s ease-in-out infinite;
}
@keyframes gentle-pulse {
  0%, 100% { box-shadow: 0 0 0 0 rgba(193, 154, 58, 0); }
  50% { box-shadow: 0 0 0 6px rgba(193, 154, 58, 0.1); }
}
.ss-info {
  display: flex; align-items: flex-start; gap: 12px;
  flex: 1;
}
.ss-icon {
  font-size: 22px;
  line-height: 1.2;
}
.ss-info strong {
  display: block;
  font-size: 14px;
  color: #6b5320;
  margin-bottom: 3px;
}
.ss-hint {
  font-size: 11.5px;
  color: #6b6452;
  line-height: 1.5;
}
.equivalent-badge {
  display: inline-block;
  margin-left: 8px;
  padding: 1px 7px;
  background: #e3ecf5;
  border: 1px solid #6b8caf;
  border-radius: 10px;
  color: #3a5a7a;
  font-size: 10.5px;
  font-weight: 600;
  white-space: nowrap;
}

.score-row.has-suggestion {
  background: linear-gradient(90deg, transparent 0%, #fef7e620 80%);
  border-left: 3px solid #c19a3a;
  padding-left: 6px;
}
.session-suggestion-chip {
  display: inline-flex; align-items: center;
  margin-left: 10px;
  padding: 2px 9px;
  background: #fef7e6;
  border: 1px solid #c19a3a;
  border-radius: 12px;
  color: #6b5320;
  font-size: 11px;
  font-weight: 600;
  font-family: inherit;
  cursor: pointer;
  white-space: nowrap;
}
.session-suggestion-chip:hover {
  background: #c19a3a;
  color: #fff;
}

/* ── 회기 템플릿 메뉴 ────────────────── */
.logI-template-wrap {
  position: relative;
  display: inline-block;
}
.template-btn {
  background: #fef7e6 !important;
  border-color: #c19a3a !important;
  color: #6b5320 !important;
}
.template-btn:hover { background: #fce8b8 !important; }
.template-menu {
  position: absolute;
  right: 0; top: calc(100% + 6px);
  z-index: 50;
  width: 360px;
  max-height: 480px;
  overflow-y: auto;
  background: #fff;
  border: 1px solid #c4b994;
  border-radius: 10px;
  box-shadow: 0 8px 30px rgba(0,0,0,0.12);
  padding: 6px;
}
.template-menu-header {
  display: flex; flex-direction: column;
  padding: 10px 12px;
  border-bottom: 1px solid #ede6d5;
}
.template-menu-header strong {
  font-size: 13.5px;
  color: #2d4a3e;
  margin-bottom: 2px;
}
.template-menu-hint {
  font-size: 11px;
  color: #6b6452;
  line-height: 1.4;
}
.template-menu-save {
  display: block;
  width: 100%;
  margin: 8px 0;
  padding: 10px;
  background: #fef7e6;
  border: 1px dashed #c19a3a;
  border-radius: 7px;
  color: #6b5320;
  font-weight: 600;
  font-family: inherit;
  font-size: 13px;
  cursor: pointer;
}
.template-menu-save:hover { background: #fce8b8; }
.template-menu-divider {
  padding: 8px 12px 4px;
  font-size: 11px;
  font-weight: 700;
  letter-spacing: 0.06em;
  color: #6b6452;
  text-transform: uppercase;
}
.template-menu-empty {
  padding: 16px;
  text-align: center;
  color: #b5a888;
  font-size: 12.5px;
  font-style: italic;
}
.template-menu-item {
  display: flex; justify-content: space-between; align-items: center;
  padding: 10px 12px;
  border-radius: 7px;
  border: 1px solid #ede6d5;
  margin-bottom: 6px;
  background: #fdfaf2;
}
.template-menu-item:hover { background: #fff; }
.template-menu-info { flex: 1; }
.template-menu-info strong {
  display: block;
  font-size: 13.5px;
  color: #2d4a3e;
  margin-bottom: 3px;
}
.template-menu-meta {
  font-size: 11px;
  color: #6b6452;
}
.template-menu-actions {
  display: flex; gap: 4px;
}

/* ── 의사소통 일과 분석 ─────────────── */
.comm-schedule-table {
  width: 100%;
  border-collapse: collapse;
  font-size: 12.5px;
}
.comm-schedule-table th, .comm-schedule-table td {
  border: 1px solid #c4b994;
  padding: 8px 10px;
  vertical-align: top;
}
.comm-schedule-table th {
  background: #2d4a3e;
  color: #fff;
  font-weight: 600;
  text-align: center;
}
.comm-schedule-table tbody tr:nth-child(even) {
  background: #fdfaf2;
}
.btn-icon-tiny {
  width: 22px; height: 18px;
  background: transparent;
  border: 1px solid transparent;
  border-radius: 3px;
  color: #6b6452;
  cursor: pointer;
  font-size: 11px;
  display: inline-flex; align-items: center; justify-content: center;
}
.btn-icon-tiny:hover:not(:disabled) {
  background: #ede6d5;
  border-color: #c4b994;
}
.btn-icon-tiny:disabled {
  opacity: 0.3;
  cursor: not-allowed;
}

/* ── FBA - 도전 행동 분석 ─────────────── */
.abc-case-card {
  border: 1px solid #c4b994;
  border-radius: 10px;
  padding: 14px;
  margin-bottom: 16px;
  background: #fdfaf2;
}
.abc-case-header {
  display: flex; justify-content: space-between; align-items: center;
  margin-bottom: 10px;
}
.abc-case-header strong {
  font-family: 'Gowun Batang', serif;
  font-size: 14px;
  color: #2d4a3e;
}
.abc-meta-row {
  display: grid;
  grid-template-columns: 200px 1fr;
  gap: 10px;
  margin-bottom: 12px;
}
.abc-meta-row > * {
  padding: 6px 10px;
  background: #fff;
  border: 1px solid #d9d1bd;
  border-radius: 6px;
  font-size: 12.5px;
}
.abc-table th {
  font-size: 12.5px;
  padding: 8px;
}
.abc-table td {
  background: #fff;
  vertical-align: top;
}
.fba-function-grid {
  display: grid;
  grid-template-columns: repeat(3, 1fr);
  gap: 10px;
  margin: 12px 0 16px;
}
.fba-function-chip {
  display: flex; align-items: flex-start; gap: 10px;
  padding: 12px 14px;
  background: #fdfaf2;
  border: 1.5px solid #d9d1bd;
  border-radius: 10px;
  cursor: pointer;
  transition: all 0.15s;
  font-family: inherit;
}
.fba-function-chip:hover { border-color: #c4b994; }
.fba-function-chip.selected {
  background: #fef7e6;
  border-color: #c19a3a;
  box-shadow: 0 0 0 2px rgba(193, 154, 58, 0.15);
}
.fba-function-chip input { 
  margin-top: 2px;
  cursor: pointer;
  accent-color: #c19a3a;
}
.fba-function-chip strong {
  display: block;
  font-size: 13px;
  color: #2d4a3e;
  margin-bottom: 3px;
}
.fba-fn-desc {
  font-size: 11.5px;
  color: #6b6452;
  line-height: 1.45;
}
.fba-hypothesis-summary {
  padding: 10px 14px;
  background: #d9e8df;
  border: 1px solid #2d4a3e;
  border-radius: 8px;
  font-size: 13px;
  color: #2d4a3e;
  margin-bottom: 12px;
}
.fba-hypothesis-summary strong { color: #1a2e26; }

/* ── 4열 그리드 (협력 카드) ─────────────── */
.collab-card-grid {
  grid-template-columns: repeat(2, 1fr);
}
@media (min-width: 1000px) {
  .collab-card-grid {
    grid-template-columns: repeat(4, 1fr);
  }
}

/* ── RESPONSIVE ─────────────────────── */
@media (max-width: 900px) {
  .form-grid, .progress-grid, .domain-buttons,
  .stage-choose, .stage-profile-cols, .assess-mode-toggle,
  .stats-summary-grid, .child-card-grid, .collab-card-grid,
  .esg-steps, .fba-function-grid, .abc-meta-row { grid-template-columns: 1fr; }
  .hero-title { font-size: 26px; }
  .header-inner { padding: 12px 16px; }
  .main { padding: 20px 16px 60px; }
  .printable { padding: 24px 20px; }
  .mrsr-bar { grid-template-columns: 1fr; gap: 6px; }
}

/* ── PRINT ─────────────────────── */
@media print {
  @page { size: A4; margin: 16mm; }
  html, body { background: #fff !important; }

  /* ──────────────────────────────────────────────────────────────
     인쇄 격리 (앱 내부 한정)

     ★ 중요: body / body * 같은 전역 선택자는 절대 쓰지 않는다.
     인쇄 규칙을 .app-shell 안으로 가두어 보고서가 아닌 UI(헤더, 푸터,
     배너 등)만 숨기고 보고서가 페이지를 꽉 쓰게 만든다.
     ────────────────────────────────────────────────────────────── */

  /* 앱 내부 레이아웃 군더더기 제거 (보고서가 페이지를 꽉 쓰도록) */
  .app-shell { display: block !important; background: #fff !important; overflow-x: visible !important; }
  .app-shell > .main, .main { padding: 0 !important; max-width: 100% !important; }
  .tab-content, .tab-content > .card, .card.no-break {
    margin: 0 !important; padding: 0 !important;
    border: none !important; box-shadow: none !important;
    background: transparent !important;
  }

  /* 화면 상단 메뉴/헤더/푸터 등 보고서 아닌 UI는 숨김 */
  .header, .footer, .step-banner, .ex-bar, .no-print, .no-print * {
    display: none !important;
  }

  /* 보고서 컨테이너는 군더더기 제거하고 폭 100%로 */
  #printable-report, .printable {
    margin: 0 !important; padding: 0 !important;
    border: none !important; box-shadow: none !important;
    width: 100% !important; max-width: 100% !important;
  }
  .card { border: none; padding: 0; box-shadow: none; }
  #printable-report, .printable {
    border: none; padding: 0;
    box-shadow: none;
  }
  .report-section { break-inside: avoid; }
  .page-break-before { break-before: page; }
  .report-table, .compare-table, .goal-table, .approval-table {
    break-inside: avoid;
  }
  .editable {
    border: none !important;
    background: transparent !important;
    padding: 0 !important;
    resize: none;
  }
  .editable:focus, .editable:hover {
    box-shadow: none !important;
    background: transparent !important;
  }

  /* ── textarea 인쇄: 내용 높이에 맞춰 펼치고 스크롤 제거 ──
     화면에선 rows 고정+스크롤이지만, 인쇄 시 잘리거나(내용 길 때) 빈
     높이를 낭비하면(내용 짧을 때) 안 된다. height:auto + overflow:visible로
     자연스러운 텍스트 블록처럼 인쇄되게 한다. */
  textarea {
    height: auto !important;
    min-height: 0 !important;
    overflow: visible !important;
    resize: none !important;
    white-space: pre-wrap !important;
    word-break: break-word !important;
    page-break-inside: avoid;
    break-inside: avoid;
  }
  /* 내용이 비어있는 칸은 한 줄 높이만 유지(완전 0이면 표 칸이 무너짐) */
  textarea:placeholder-shown {
    min-height: 1.4em !important;
  }
  .empty-cell { display: none; }
  .chart-wrap { break-inside: avoid; page-break-inside: avoid; }
  .bar-pre { fill: #c19a3a !important; -webkit-print-color-adjust: exact; print-color-adjust: exact; }
  .bar-post { fill: #2d4a3e !important; -webkit-print-color-adjust: exact; print-color-adjust: exact; }
  .report-meta th, .report-table th, .goal-table th,
  .approval-table th, .td-area, .report-h3,
  .obs-table th, .obs-label-cell,
  .iq-emotion-pair-table th, .iq-frequency-table th,
  .sap-table th, .sap-group-row td, .sap-total-row td,
  .sap-pre, .sap-post {
    -webkit-print-color-adjust: exact;
    print-color-adjust: exact;
  }
  .sap-table { page-break-inside: avoid; }
  .sap-table td, .sap-table th {
    border: 1px solid #999 !important;
  }
  .interview-section.screen-hidden { display: block !important; }
  .interview-section { break-inside: avoid; }
  .iq-row {
    background: transparent !important;
    border: 1px solid #c4b994 !important;
    page-break-inside: avoid;
  }
  .iq-text, .iq-extra-input, .obs-list-input {
    border: 1px solid #999 !important;
    background: #fff !important;
  }
  .interview-intro {
    background: transparent !important;
    border-left: 3px solid #2d4a3e !important;
  }
  .rating-select {
    border: 1px solid #999 !important;
    background: #fff !important;
  }
}
    `}</style>
  );
}
