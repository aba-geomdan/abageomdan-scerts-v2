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
    // ★ 못 불러온 경우(인터넷·로그인 문제)는 '자료 없음'과 구분해서 알려 준다 → 옛 자료로 서버를 덮어쓰지 않게
    if (!user?.id) return { error: true };
    const url = `${SUPABASE_URL}/rest/v1/scerts_data?user_id=eq.${user.id}&key=eq.${encodeURIComponent(key)}&select=key,value`;
    const r = await fetch(url, { headers });
    if (!r.ok) return { error: true };
    const rows = await r.json();
    if (rows && rows.length > 0) {
      return { key: rows[0].key, value: rows[0].value };
    }
    return null;
  } catch (e) { return { error: true }; }
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
  // ★ 2글자는 성 없이 이름만 넣은 경우가 많아 그대로 쓴다 (준호 → 준호는 / 예전엔 '호는'으로 나왔음)
  if (name.length === 2) return name;
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
  // 격식체 → 평서체 (받침 있으면 '이다': 수준입니다 → 수준이다 / 없으면 '다': 상태입니다 → 상태다)
  //   '보입니다·줄입니다'처럼 '-이다'가 아닌 동사는 먼저 따로 바꾼다 (보인다·줄인다)
  //   (앞이 띄어쓰기일 때만: '정보입니다·확보입니다' 같은 명사는 건드리지 않음)
  //   '한 줄입니다·두 줄입니다'처럼 앞이 수를 나타내는 말이면 명사로 보고 건드리지 않음
  //   (옛 아이폰(iOS 16.3 이하)에서도 앱이 열리도록 '뒤돌아보기' 정규식은 쓰지 않고, 앞 단어를 직접 확인)
  const COUNT_WORDS = ['한', '두', '세', '네', '몇', '여러', '열'];
  t = t.replace(/(^|\s)(보|줄|높|늘|붙|먹|속|숨|녹|죽|끓|낮|좁|넓)입니다\./g, (m, sp, v, off, str) => {
    const prevWord = str.slice(0, off).trim().split(/\s+/).pop() || '';
    if (sp && COUNT_WORDS.includes(prevWord)) return m;
    return sp + v + '인다.';
  });
  t = t.replace(/(.)입니다\./g, (m, ch) => ch + (hasJongseong(ch) ? '이다.' : '다.'));
  //   '필요합니다·중요합니다'처럼 상태를 나타내는 말은 '-하다', 그 밖의 '-합니다'는 '-한다'
  t = t.replace(/(필요|중요|적절|가능|불가능|유용|충분|바람직|분명|확실|시급|용이|원활|부족|미흡|양호|우수|유사|동일|적합|부적절|효과적|안정적|일관적)합니다\./g, '$1하다.');
  t = t.replace(/습니다\./g, '다.').replace(/됩니다\./g, '된다.').replace(/합니다\./g, '한다.');
  return t;
}

// 긴 글을 n자 안에서 자를 때 문장 끝(마침표)에서 자르고, 마침표가 없으면 띄어쓰기에서 잘라 '…'를 붙인다
function clipText(text, n) {
  const s = String(text || '').trim();
  if (s.length <= n) return s;
  const head = s.slice(0, n);
  const dot = Math.max(head.lastIndexOf('. '), head.lastIndexOf('.\n'), head.endsWith('.') ? head.length - 1 : -1);
  if (dot >= n / 3) return head.slice(0, dot + 1);
  const sp = head.lastIndexOf(' ');
  return (sp > 0 ? head.slice(0, sp) : head) + '…';
}

// 따옴표로 묶은 말 뒤 조사 '을/를' (받침 있으면 '을')
function eulReul(text) {
  // 끝의 문장부호·괄호·따옴표는 빼고 마지막 글자를 본다 ("…것." → '것' → 을)
  const t = String(text || '').trim().replace(/[\s.,!?~…·)\]}>"'”’」』》〉]+$/, '');
  const last = t.slice(-1);
  // 숫자는 읽는 소리로: 0영 1일 3삼 6육 7칠 8팔 → 받침 있음 / 2이 4사 5오 9구 → 없음
  if (/[0-9]/.test(last)) return '013678'.includes(last) ? '을' : '를';
  return hasJongseong(t) ? '을' : '를';
}

// 정서 조절 패턴 판정 — 진단 분석·IEP·중간보고서가 모두 같은 기준을 쓰도록 한 곳에 모음
//   ★ 책 기준(1권 265쪽): 칸의 절반 이상 = 상대적 강점, 절반 미만 = 상대적 요구. 경계는 50% 하나
function classifyMrSr(mrP, srP) {
  const mrHigh = mrP >= 0.5;
  const srHigh = srP >= 0.5;
  if (mrHigh && !srHigh) return 'highMR_lowSR';
  if (!mrHigh && srHigh) return 'lowMR_highSR';
  if (!mrHigh && !srHigh) return 'lowMR_lowSR';
  return 'balanced';
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

  // 2-1) 선택칸(select)은 복제하면 고른 값이 사라지므로, 화면에서 고른 글자로 바꿔 넣는다
  //      (따로 인쇄용 글자(.print-only)가 옆에 있으면 선택칸만 지운다)
  const origSelects = report.querySelectorAll('select');
  clone.querySelectorAll('select').forEach((sel, i) => {
    const o = origSelects[i];
    if (sel.parentNode.querySelector('.print-only')) { sel.remove(); return; }
    const span = document.createElement('span');
    span.className = 'static-text';
    const opt = o && o.selectedIndex >= 0 ? o.options[o.selectedIndex] : null;
    span.textContent = o && o.value ? (opt ? opt.text : o.value) : '';
    sel.parentNode.replaceChild(span, sel);
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
// ★ 1권 부록 A '의사소통 단계 결정 기록지'(415쪽) 원문 그대로
const STAGE_DECISION = {
  q1: {
    title: '1. 다음의 모든 항목에 해당되는가?',
    items: [
      { id: '1a', label: '적어도 3개의 다양한 단어나 구(말, 수어, 그림, 문자 또는 기타 상징 체계)를 사용하는가?' },
      { id: '1b', label: '적어도 3개 이상의 단어나 구를 참조의 목적으로(즉, 구체적인 물건, 사람 또는 활동을 언급하기 위해서) 사용하는가?' },
      { id: '1c', label: '적어도 3개 이상의 단어나 구를 의사소통 의도로(즉, 의사소통을 할 목적으로 몸짓이나 눈맞춤을 하면서 단어나 구를 조합함으로써) 사용하는가?' },
      { id: '1d', label: '적어도 3개 이상의 단어나 구를 정기적으로(즉, 드물게 사용하는 것이 아니라 자주 사용함) 사용하는가?' },
    ],
    instruction: '□ 아니요 → 사회적 파트너 단계 양식을 사용할 것  □ 예 → 질문 2로 이동할 것',
  },
  q2: {
    title: '2. 다음의 모든 항목에 해당되는가?',
    items: [
      { id: '2a', label: '적어도 100개의 다양한 단어나 구(말, 수어, 그림, 문자 또는 기타 상징 체계)를 사용하는가?' },
      { id: '2b', label: '적어도 100개 이상의 단어나 구를 참조의 목적으로(즉, 구체적인 물건, 사람 또는 활동을 언급하기 위해서) 사용하는가?' },
      { id: '2c', label: '적어도 100개 이상의 단어나 구를 의사소통 의도로(즉, 의사소통을 할 목적으로 몸짓이나 눈맞춤을 하면서 단어나 구를 조합함으로써) 사용하는가?' },
      { id: '2d', label: '적어도 100개 이상의 단어나 구를 정기적으로(즉, 드물게 사용하는 것이 아니라 자주 사용함) 사용하는가?' },
      { id: '2e', label: '적어도 20개 이상의 창의적인 단어 조합(즉, 구를 정확하게 모방하는 것만이 아님)을 사용하는가?' },
    ],
    instruction: '□ 아니요 → 언어 파트너 단계 양식을 사용할 것  □ 예 → 대화 파트너 단계 양식을 사용할 것',
  },
};

// ── 채점 기준 공통 ─────────────────────────────────────────────────
// ★ 채점 기준 — 1권 부록 A SCERTS 주간 기록지(484쪽)의 '점수 산출 기준' 원문 그대로
//   사회적 파트너: 두 명의 파트너 / 언어 파트너·대화 파트너: 세 명의 파트너 (1권 <표 7-4> 253쪽과 같음)
const SCORING_LEGEND = [
  { score: 2, label: '', desc: '준거에 일관성 있게 도달(두 가지 상황에서 두 명의 파트너에 걸쳐 나타남)' },
  { score: 1, label: '', desc: '준거에 일관성 없이 도달하거나 보조를 받아서 수행함' },
  { score: 0, label: '', desc: '준거에 도달하지 못함' },
];

function partnerCountWord(stage) {
  return stage === 'social' ? '두' : '세';
}
function scoringLegendFor(stage) {
  const n = partnerCountWord(stage);
  return SCORING_LEGEND.map((l) => (l.score === 2
    ? { ...l, desc: `준거에 일관성 있게 도달(두 가지 상황에서 ${n} 명의 파트너에 걸쳐 나타남)` }
    : l));
}

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
// ★ 사회-정서 성장 지표 = 정해진 교수목표 5개의 점수 합(0~10점)
//   1권 <표 7-5>(258쪽), 265쪽 "각 지표는 5개 교수목표에 근거하며, 가능한 총점은 10점"
//   (2권 사례 재호의 '사회적 소속감 4점'으로 계산법 확인함)
const SES_ITEMS = {
  social: {
    happiness: ['JA3.2', 'JA5.4', 'MR1.1', 'MR2.4', 'SR1.7'],
    selfAwareness: ['JA4.4', 'JA7.1', 'MR2.6', 'MR3.3', 'SR4.1'],
    otherAwareness: ['JA1.3', 'JA5.4', 'SU2.7', 'MR2.4', 'MR2.5'],
    activeLearning: ['SU1.3', 'SU1.4', 'SU3.4', 'SU4.7', 'SR2.1'],
    flexibility: ['JA7.3', 'MR4.3', 'SR3.1', 'SR4.3', 'SR4.4'],
    cooperation: ['JA1.1', 'SU2.7', 'SU4.5', 'MR2.1', 'SR4.2'],
    independence: ['JA4.4', 'SU2.6', 'MR2.6', 'SR3.3', 'SR4.1'],
    belonging: ['JA1.4', 'JA2.1', 'JA5.1', 'MR2.3', 'SR1.4'],
  },
  language: {
    happiness: ['JA3.1', 'JA5.2', 'MR1.2', 'MR2.5', 'SR1.8'],
    selfAwareness: ['JA4.4', 'JA7.1', 'MR3.4', 'MR3.7', 'SR5.1'],
    otherAwareness: ['JA3.4', 'JA5.4', 'SU2.4', 'MR2.4', 'MR2.7'],
    activeLearning: ['SU1.4', 'SU3.4', 'MR2.7', 'MR3.3', 'SR4.1'],
    flexibility: ['JA7.2', 'SR2.3', 'SR4.1', 'SR5.4', 'SR5.5'],
    cooperation: ['JA5.7', 'SU2.3', 'SU4.1', 'SU5.6', 'SR1.5'],
    independence: ['JA4.4', 'MR2.6', 'MR3.5', 'SR5.1', 'SR5.3'],
    belonging: ['JA1.1', 'JA2.3', 'JA5.4', 'JA8.3', 'MR2.3'],
  },
  conversation: {
    happiness: ['JA2.1', 'JA3.2', 'JA5.6', 'MR1.5', 'SR1.6'],
    selfAwareness: ['JA1.2', 'JA5.6', 'SU1.4', 'SU5.2', 'MR1.3'],
    otherAwareness: ['JA1.4', 'JA4.3', 'JA4.5', 'JA4.7', 'JA5.6'],
    activeLearning: ['JA5.3', 'SU1.3', 'SU3.4', 'SR3.5', 'SR4.2'],
    flexibility: ['JA5.4', 'MR3.5', 'SR5.5', 'SR5.6', 'SR6.4'],
    cooperation: ['SU3.6', 'SU6.1', 'SU6.4', 'MR3.5', 'SR1.4'],
    independence: ['JA3.1', 'SU1.4', 'SR6.1', 'SR6.2', 'SR6.3'],
    belonging: ['JA4.7', 'JA4.8', 'SU3.7', 'MR2.3', 'MR3.4'],
  },
};

// 문항 점수로 성장 지표 계산. 채점한 문항이 하나도 없으면 null
function computeSes(stage, scores) {
  const map = SES_ITEMS[stage];
  const sc = scores || {};
  if (!map || !Object.values(sc).some((v) => typeof v === 'number')) return null;
  const values = {};
  const detail = {};
  Object.entries(map).forEach(([id, items]) => {
    let sum = 0, unscored = 0;
    const parts = items.map((it) => {
      const v = sc[it];
      if (typeof v === 'number') sum += v; else unscored += 1;
      return { id: it, score: typeof v === 'number' ? v : null };
    });
    values[id] = sum;
    detail[id] = { parts, unscored };
  });
  return { values, detail };
}

// 세션의 성장 지표: 문항 점수가 있으면 계산값, 하나도 없으면 예전에 손으로 정해 둔 값
function sesOf(session, stage) {
  if (!session) return {};
  const c = computeSes(session.stage || stage, session.scores);
  return c ? c.values : (session.ses || {});
}

// =====================================================================
// 사회적 파트너 단계 진단 항목
// =====================================================================
const SOCIAL_PARTNER = {
  // 사회 의사소통 - 공동관심 (JA) /54
  joinAttention: {
    label: '공동관심',
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
          { id: 'JA3.1', label: '얼굴 표정이나 발성을 이용하여 부정적인 정서 공유하기' },
          { id: 'JA3.2', label: '얼굴 표정이나 발성을 이용하여 긍정적인 정서 공유하기' },
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
    label: '상징 사용',
    code: 'SU',
    maxScore: 62,
    groups: [
      {
        title: '1. 익숙한 행동과 소리 모방을 통해 학습하기',
        items: [
          { id: 'SU1.1', label: '자신의 행동이나 소리를 반복하면서 차례 주고받기' },
          { id: 'SU1.2', label: '시범 후 즉시 유도하면 익숙한 행동이나 소리 모방하기' },
          { id: 'SU1.3', label: '시범 후 즉시 자발적으로 익숙한 행동이나 소리 모방하기' },
          { id: 'SU1.4', label: '시간이 경과된 후 자발적으로 익숙한 행동이나 소리 모방하기' },
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
          { id: 'SU2.6', label: '시각적 단서(사진이나 그림)에 반응하기' },
          { id: 'SU2.7', label: '얼굴 표정과 억양 단서에 반응하기' },
        ],
      },
      {
        title: '3. 놀이 중에 익숙한 사물을 관습적인 방식으로 사용하기',
        items: [
          { id: 'SU3.1', label: '사물에 대한 탐색 행동 보이기' },
          { id: 'SU3.2', label: '구성놀이에서 익숙한 사물 사용하기' },
          { id: 'SU3.3', label: '익숙한 사물을 관습적인 방식으로 자신에게 사용하기' },
          { id: 'SU3.4', label: '익숙한 사물을 관습적인 방식으로 다른 사람에게 사용하기' },
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
        title: '6. 2∼3개의 익숙한 단어 이해하기',
        items: [
          { id: 'SU6.1', label: '자신의 이름에 반응하기' },
          { id: 'SU6.2', label: '익숙한 사회적 게임에서 2∼3개의 단어에 반응하기' },
          { id: 'SU6.3', label: '2∼3개의 친숙한 사람, 신체부위, 사물 이름에 반응하기' },
          { id: 'SU6.4', label: '익숙한 일과에서 자주 사용되는 2∼3개의 구절에 반응하기' },
        ],
      },
    ],
  },

  // 정서 조절 - 상호조절 (MR) /38
  mutualReg: {
    label: '상호조절',
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
          { id: 'MR4.1', label: '활동으로부터 떨어져 있게 하는 방법으로 회복을 지원하는 파트너의 노력에 반응하기' },
          { id: 'MR4.2', label: '파트너의 행동 전략 사용에 반응하기' },
          { id: 'MR4.3', label: '상호작용이나 활동에 다시 참여하게 하기 위한 파트너의 시도에 반응하기' },
          { id: 'MR4.4', label: '파트너의 지원을 받아 극심한 조절장애로부터 회복되는 시간 단축하기' },
          { id: 'MR4.5', label: '파트너의 지원을 받아 극심한 조절장애 상태의 강도 줄이기' },
        ],
      },
    ],
  },

  // 자기조절 (SR) /40
  selfReg: {
    label: '자기조절',
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
        title: '2. 익숙한 활동 중에 각성 수준을 조절하기 위해 행동 전략 사용하기',
        items: [
          { id: 'SR2.1', label: '혼자 하는 활동 중에 각성 수준을 조절하기 위해 행동 전략 사용하기' },
          { id: 'SR2.2', label: '사회적 상호작용 중에 각성 수준을 조절하기 위해 행동 전략 사용하기' },
          { id: 'SR2.3', label: '각성 수준을 조절하기 위해 파트너가 시범 보인 행동 전략 사용하기' },
          { id: 'SR2.4', label: '장시간의 활동에 생산적으로 참여하기 위해 행동 전략 사용하기' },
        ],
      },
      {
        title: '3. 새롭고 변화하는 상황에서 정서 조절하기',
        items: [
          { id: 'SR3.1', label: '익숙한 일과에서 다른 사람의 행동 예상하기' },
          { id: 'SR3.2', label: '새롭고 변화하는 상황에 참여하기' },
          { id: 'SR3.3', label: '새롭고 변화하는 상황에서 각성 수준을 조절하기 위해 행동 전략 사용하기' },
          { id: 'SR3.4', label: '전이 중 각성 수준을 조절하기 위해 행동 전략 사용하기' },
        ],
      },
      {
        title: '4. 극심한 조절장애로부터 스스로 회복하기',
        items: [
          { id: 'SR4.1', label: '지나치게 자극적이거나 원하지 않는 활동으로부터 스스로 떠나기' },
          { id: 'SR4.2', label: '극심한 조절장애로부터 회복하기 위해 행동 전략 사용하기' },
          { id: 'SR4.3', label: '극심한 조절장애로부터 회복된 후 상호작용이나 활동에 다시 참여하기' },
          { id: 'SR4.4', label: '극심한 조절장애로부터 회복되는 시간 단축하기' },
          { id: 'SR4.5', label: '조절장애 상태의 강도 줄이기' },
        ],
      },
    ],
  },

  // 교류 지원 - 대인관계 지원 (IS) /66
  interpersonalSupport: {
    label: '대인관계 지원',
    code: 'IS',
    maxScore: 66,
    groups: [
      {
        title: '1. 파트너는 아동에게 반응적이다.',
        items: [
          { id: 'IS1.1', label: '아동의 관심 초점 따르기' },
          { id: 'IS1.2', label: '아동의 정서 및 속도에 맞추기' },
          { id: 'IS1.3', label: '의사소통 효능감을 증진시키기 위해 아동의 신호에 적절하게 반응하기' },
          { id: 'IS1.4', label: '각성 수준을 조절하기 위한 아동의 행동 전략 인식하고 지원하기' },
          { id: 'IS1.5', label: '조절장애 신호 인식하고 지원하기' },
          { id: 'IS1.6', label: '아동을 모방하기' },
          { id: 'IS1.7', label: '필요할 때 상호작용이나 활동으로부터 휴식 제공하기' },
          { id: 'IS1.8', label: '휴식에 이어 상호작용이나 활동에 다시 참여하도록 촉진하기' },
        ],
      },
      {
        title: '2. 파트너는 시작행동을 촉진한다.',
        items: [
          { id: 'IS2.1', label: '비구어 또는 구어로 선택의 기회 제공하기' },
          { id: 'IS2.2', label: '시작행동 기다리고 격려하기' },
          { id: 'IS2.3', label: '시작행동과 반응행동의 균형 유지하기' },
          { id: 'IS2.4', label: '아동이 활동을 시작하고 마치도록 해 주기' },
        ],
      },
      {
        title: '3. 파트너는 아동의 독립성을 존중한다.',
        items: [
          { id: 'IS3.1', label: '필요한 경우 활동 중간에 돌아다닐 수 있도록 휴식 허락하기' },
          { id: 'IS3.2', label: '아동이 자신의 속도로 문제를 해결하고 활동을 완수할 수 있도록 시간 허용하기' },
          { id: 'IS3.3', label: '문제행동을 의사소통 또는 조절의 기능으로 이해하기' },
          { id: 'IS3.4', label: '적절한 경우 저항, 거부, 거절 존중하기' },
        ],
      },
      {
        title: '4. 파트너는 참여를 위한 장을 마련한다.',
        items: [
          { id: 'IS4.1', label: '의사소통할 때 아동의 눈높이에 맞추기' },
          { id: 'IS4.2', label: '의사소통하기 전에 아동의 주의 확보하기' },
          { id: 'IS4.3', label: '상호작용을 촉진하기 위해 적절한 근접성과 비구어 행동 사용하기' },
          { id: 'IS4.4', label: '최적의 각성 상태와 참여를 지원하기 위해 적절한 단어와 억양 사용하기' },
        ],
      },
      {
        title: '5. 파트너는 발달을 지원한다.',
        items: [
          { id: 'IS5.1', label: '모방 격려하기' },
          { id: 'IS5.2', label: '또래와의 상호작용 격려하기' },
          { id: 'IS5.3', label: '구어 또는 비구어로 의사소통 실패를 복구하려고 시도하기' },
          { id: 'IS5.4', label: '활동 성공을 위해 필요할 때 안내 및 피드백 제공하기' },
          { id: 'IS5.5', label: '아동의 놀이와 비구어 의사소통 확장하기' },
        ],
      },
      {
        title: '6. 파트너는 언어 사용을 조절한다.',
        items: [
          { id: 'IS6.1', label: '이해를 돕기 위해 비구어 단서 사용하기' },
          { id: 'IS6.2', label: '아동의 발달 수준에 따라 언어의 복잡성 조절하기' },
          { id: 'IS6.3', label: '아동의 각성 수준에 따라 언어의 질 조절하기' },
        ],
      },
      {
        title: '7. 파트너는 적절한 행동을 시범 보인다.',
        items: [
          { id: 'IS7.1', label: '적절한 비구어 의사소통과 정서 표현 시범 보이기' },
          { id: 'IS7.2', label: '다양한 의사소통 기능 시범 보이기' },
          { id: 'IS7.3', label: '적절한 놀이 시범 보이기' },
          { id: 'IS7.4', label: '아동이 부적절한 행동을 할 때 적절한 행동 시범 보이기' },
          { id: 'IS7.5', label: '‘아동 입장’에서 언어 시범 보이기' },
        ],
      },
    ],
  },

  // 학습 지원 (LS) /50
  learningSupport: {
    label: '학습 지원',
    code: 'LS',
    maxScore: 50,
    groups: [
      {
        title: '1. 파트너는 적극적인 참여를 위해 활동을 구조화한다.',
        items: [
          { id: 'LS1.1', label: '활동의 시작과 종료를 분명하게 정하기' },
          { id: 'LS1.2', label: '차례 주고받기 기회를 만들고 아동이 참여할 수 있도록 여지 남겨 두기' },
          { id: 'LS1.3', label: '활동에 예측 가능한 순서 마련하기' },
          { id: 'LS1.4', label: '반복되는 학습 기회 제공하기' },
          { id: 'LS1.5', label: '다양한 학습 기회 제공하기' },
        ],
      },
      {
        title: '2. 파트너는 발달을 촉진하기 위해 보완의사소통 지원을 사용한다.',
        items: [
          { id: 'LS2.1', label: '의사소통과 표현언어를 강화하기 위해 보완의사소통 지원 사용하기' },
          { id: 'LS2.2', label: '언어 및 행동 이해를 강화하기 위해 보완의사소통 지원 사용하기' },
          { id: 'LS2.3', label: '정서 표현 및 이해 능력을 강화하기 위해 보완의사소통 지원 사용하기' },
          { id: 'LS2.4', label: '정서 조절을 강화하기 위해 보완의사소통 지원 사용하기' },
        ],
      },
      {
        title: '3. 파트너는 시각적 지원 및 조직화 지원을 사용한다.',
        items: [
          { id: 'LS3.1', label: '과제 수행 단계를 명확히 하기 위해 지원 사용하기' },
          { id: 'LS3.2', label: '활동 완수에 필요한 시간과 단계를 명확히 하기 위해 지원 사용하기' },
          { id: 'LS3.3', label: '활동 간 원활한 전이를 위해 시각적 지원 사용하기' },
          { id: 'LS3.4', label: '하루 전반에 걸쳐 시간 분할을 조직화하기 위해 지원 사용하기' },
          { id: 'LS3.5', label: '집단 활동에서의 주의집중을 높이기 위해 시각적 지원 사용하기' },
          { id: 'LS3.6', label: '집단 활동에서의 적극적인 참여를 촉진하기 위해 시각적 지원 사용하기' },
        ],
      },
      {
        title: '4. 파트너는 목표, 활동, 학습 환경을 수정한다.',
        items: [
          { id: 'LS4.1', label: '조직화와 상호작용을 지원하기 위해 사회적 복잡성 조절하기' },
          { id: 'LS4.2', label: '아동의 성공을 위해 과제 난이도 조절하기' },
          { id: 'LS4.3', label: '학습 환경의 감각적 속성 수정하기' },
          { id: 'LS4.4', label: '주의집중을 높일 수 있도록 학습 환경 구성하기' },
          { id: 'LS4.5', label: '시작행동을 촉진하는 학습 환경 구성하기' },
          { id: 'LS4.6', label: '활동이 발달적으로 적절하도록 고안하고 수정하기' },
          { id: 'LS4.7', label: '활동 내에 동기유발이 가능한 교재 및 주제 포함시키기' },
          { id: 'LS4.8', label: '시작행동과 확장된 상호작용을 촉진하는 활동 제공하기' },
          { id: 'LS4.9', label: '필요에 따라 동적인 활동과 정적인 활동 교대하기' },
          { id: 'LS4.10', label: '‘요구의 정도를 높이거나’ 기대감을 적절하게 높이기' },
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
    label: '공동관심',
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
          { id: 'JA2.2', label: '짚어서 가리키거나 멀리 있는 것을 가리킬 때 쳐다보기' },
          { id: 'JA2.3', label: '사회적 파트너의 관심 초점 따르기' },
          { id: 'JA2.4', label: '의도를 나타내기 전에 자신에게로 주의 끌기' },
        ],
      },
      {
        title: '3. 정서 공유하기',
        items: [
          { id: 'JA3.1', label: '부정적인 정서와 긍정적인 정서 공유하기' },
          { id: 'JA3.2', label: '다양한 정서를 표현하기 위해 상징 이해하고 사용하기' },
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
          { id: 'JA6.2', label: '행동이나 사건에 대해 언급하기' },
          { id: 'JA6.3', label: '관심 있는 것에 대해 정보 요구하기' },
        ],
      },
      {
        title: '7. 의사소통 실패를 복구하고 지속하기',
        items: [
          { id: 'JA7.1', label: '맥락에 적절한 비율로 의사소통하기' },
          { id: 'JA7.2', label: '의사소통 실패를 복구하기 위해 반복하거나 수정하기' },
          { id: 'JA7.3', label: '의사소통 실패 인식하기' },
        ],
      },
      {
        title: '8. 상호적 상호작용에서 경험 공유하기',
        items: [
          { id: 'JA8.1', label: '경험을 공유하기 위해 관심, 정서, 의도 조절하기' },
          { id: 'JA8.2', label: '경험을 공유하기 위해 청자 및 화자의 역할을 바꾸어 가며 상호작용하기' },
          { id: 'JA8.3', label: '친구와 상호작용 시작하고 경험 공유하기' },
        ],
      },
    ],
  },

  symbolUse: {
    label: '상징 사용',
    code: 'SU',
    maxScore: 50,
    groups: [
      {
        title: '1. 익숙하거나 익숙하지 않은 행동이나 단어를 관찰하고 모방하여 학습하기',
        items: [
          { id: 'SU1.1', label: '시범 후 즉시 자발적으로 익숙한 행동이나 단어 모방하기' },
          { id: 'SU1.2', label: '시범 후 즉시 자발적으로 익숙하지 않은 행동이나 단어 모방하기' },
          { id: 'SU1.3', label: '동작이나 단어를 자발적으로 모방하고 다른 행동을 더하기' },
          { id: 'SU1.4', label: '시간이 경과된 후 다른 맥락에서 다양한 행동을 자발적으로 모방하기' },
        ],
      },
      {
        title: '2. 익숙하거나 익숙하지 않은 활동에서 비구어 단서 이해하기',
        items: [
          { id: 'SU2.1', label: '익숙하거나 익숙하지 않은 활동에서 상황 및 몸짓 단서 따르기' },
          { id: 'SU2.2', label: '짚어서 가리키거나 멀리 있는 것을 가리킬 때 쳐다보기' },
          { id: 'SU2.3', label: '시각적 단서(사진이나 그림)를 동반한 지시 따르기' },
          { id: 'SU2.4', label: '얼굴 표정과 억양 단서에 반응하기' },
        ],
      },
      {
        title: '3. 놀이 중에 익숙한 사물을 관습적인 방식으로 사용하기',
        items: [
          { id: 'SU3.1', label: '구성놀이에서 다양한 사물 사용하기' },
          { id: 'SU3.2', label: '여러 가지 익숙한 사물을 관습적인 방식으로 자신에게 사용하기' },
          { id: 'SU3.3', label: '여러 가지 익숙한 사물을 관습적인 방식으로 다른 사람에게 사용하기' },
          { id: 'SU3.4', label: '놀이 중 사물을 사용하여 다양한 행동 조합하기' },
        ],
      },
      {
        title: '4. 의도 공유를 위해 몸짓이나 비구어 수단 사용하기',
        items: [
          { id: 'SU4.1', label: '다양한 관습적 또는 상징적 몸짓 사용하기' },
          { id: 'SU4.2', label: '일련의 몸짓이나 비구어 수단을 시선과 함께 사용하기' },
        ],
      },
      {
        title: '5. 의미를 표현하기 위해 단어와 단어 조합 사용하기',
        items: [
          { id: 'SU5.1', label: '소리/단어를 시선 및 몸짓과 함께 조합하여 사용하기' },
          { id: 'SU5.2', label: '상징으로 적어도 5∼10개의 단어나 반향어 구 사용하기' },
          { id: 'SU5.3', label: '초기 관계어 사용하기' },
          { id: 'SU5.4', label: '사물, 신체부위, 행위자에 대해 다양한 이름 사용하기' },
          { id: 'SU5.5', label: '상위 수준의 관계어를 다양하게 사용하기' },
          { id: 'SU5.6', label: '단어조합에 있어서 다양한 관계 의미 사용하기' },
        ],
      },
      {
        title: '6. 맥락적 단서 없이 다양한 단어와 단어 조합 이해하기',
        items: [
          { id: 'SU6.1', label: '자신의 이름에 반응하기' },
          { id: 'SU6.2', label: '여러 가지 익숙한 단어 및 구절에 반응하기' },
          { id: 'SU6.3', label: '맥락적 단서 없이 다양한 이름 이해하기' },
          { id: 'SU6.4', label: '맥락적 단서 없이 다양한 관계어 이해하기' },
          { id: 'SU6.5', label: '맥락적 단서 없이 단어 조합에서 다양한 관계 의미 이해하기' },
        ],
      },
    ],
  },

  mutualReg: {
    label: '상호조절',
    code: 'MR',
    maxScore: 46,
    groups: [
      {
        title: '1. 다양한 정서 표현하기',
        items: [
          { id: 'MR1.1', label: '부정적인 정서와 긍정적인 정서 공유하기' },
          { id: 'MR1.2', label: '다양한 정서를 표현하기 위해 상징 이해하고 사용하기' },
          { id: 'MR1.3', label: '익숙한 활동에서 파트너의 피드백에 따라 정서 표현 바꾸기' },
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
          { id: 'MR2.7', label: '익숙한 활동에서 파트너의 피드백에 따라 조절 전략 바꾸기' },
        ],
      },
      {
        title: '3. 상태를 조절하기 위해 파트너에게 도움 청하기',
        items: [
          { id: 'MR3.1', label: '위로를 구하기 위해 부정적인 정서 공유하기' },
          { id: 'MR3.2', label: '상호작용을 하기 위해 긍정적인 정서 공유하기' },
          { id: 'MR3.3', label: '좌절했을 때 도움 청하기' },
          { id: 'MR3.4', label: '괴로울 때 거부하기' },
          { id: 'MR3.5', label: '휴식을 요구하기 위해 언어 전략 사용하기' },
          { id: 'MR3.6', label: '활동이나 자극 조절을 요구하기 위해 언어 전략 사용하기' },
          { id: 'MR3.7', label: '사회적 조절 수행을 위해 언어 전략 사용하기' },
        ],
      },
      {
        title: '4. 파트너의 지원을 받아 극심한 조절장애로부터 회복하기',
        items: [
          { id: 'MR4.1', label: '활동으로부터 떨어져 있게 하는 방법으로 회복을 지원하는 파트너의 노력에 반응하기' },
          { id: 'MR4.2', label: '파트너의 행동 전략 사용에 반응하기' },
          { id: 'MR4.3', label: '파트너의 언어 전략 사용에 반응하기' },
          { id: 'MR4.4', label: '상호작용이나 활동에 다시 참여하게 하기 위한 파트너의 시도에 반응하기' },
          { id: 'MR4.5', label: '파트너의 지원을 받아 극심한 조절장애로부터 회복되는 시간 단축하기' },
          { id: 'MR4.6', label: '파트너의 지원을 받아 극심한 조절장애 상태의 강도 줄이기' },
        ],
      },
    ],
  },

  selfReg: {
    label: '자기조절',
    code: 'SR',
    maxScore: 56,
    groups: [
      {
        title: '1. 학습 또는 상호작용의 가능성 보이기',
        items: [
          { id: 'SR1.1', label: '상호작용 시도 시작하기' },
          { id: 'SR1.2', label: '간단한 상호적 상호작용에 참여하기' },
          { id: 'SR1.3', label: '확장된 상호적 상호작용에 참여하기' },
          { id: 'SR1.4', label: '차별화된 정서로 감각 및 사회적 경험에 반응하기' },
          { id: 'SR1.5', label: '행위 및 행동 억제 능력 보이기' },
          { id: 'SR1.6', label: '여러 가지 익숙한 단어 및 구절에 반응하기' },
          { id: 'SR1.7', label: '합리적인 요구를 지닌 과제 지속하기' },
          { id: 'SR1.8', label: '맥락에 적절하게 정서 표현하기' },
        ],
      },
      {
        title: '2. 익숙한 활동 중에 각성 수준을 조절하기 위해 행동 전략 사용하기',
        items: [
          { id: 'SR2.1', label: '혼자 하는 활동과 사회적 활동 중에 각성 수준을 조절하기 위해 행동 전략 사용하기' },
          { id: 'SR2.2', label: '각성 수준을 조절하기 위해 파트너가 시범 보인 행동 전략 사용하기' },
          { id: 'SR2.3', label: '장시간의 활동에 생산적으로 참여하기 위해 행동 전략 사용하기' },
        ],
      },
      {
        title: '3. 익숙한 활동 중에 각성 수준을 조절하기 위해 언어 전략 사용하기',
        items: [
          { id: 'SR3.1', label: '혼자 하는 활동 중에 각성 수준을 조절하기 위해 언어 전략 사용하기' },
          { id: 'SR3.2', label: '사회적 상호작용 중에 각성 수준을 조절하기 위해 언어 전략 사용하기' },
          { id: 'SR3.3', label: '각성 수준을 조절하기 위해 파트너가 시범 보인 언어 전략 사용하기' },
          { id: 'SR3.4', label: '장시간의 활동에 생산적으로 참여하기 위해 언어 전략 사용하기' },
          { id: 'SR3.5', label: '다양한 정서를 표현하는 상징 사용하기' },
        ],
      },
      {
        title: '4. 새롭고 변화하는 상황에서 정서 조절하기',
        items: [
          { id: 'SR4.1', label: '새롭고 변화하는 상황에 참여하기' },
          { id: 'SR4.2', label: '익숙하지 않은 활동에서 상황 및 몸짓 단서 따르기' },
          { id: 'SR4.3', label: '새롭고 변화하는 상황에서 각성 수준을 조절하기 위해 행동 전략 사용하기' },
          { id: 'SR4.4', label: '새롭고 변화하는 상황에서 각성 수준을 조절하기 위해 언어 전략 사용하기' },
          { id: 'SR4.5', label: '전이 중 각성 수준을 조절하기 위해 행동 전략 사용하기' },
          { id: 'SR4.6', label: '전이 중 각성 수준을 조절하기 위해 언어 전략 사용하기' },
        ],
      },
      {
        title: '5. 극심한 조절장애로부터 스스로 회복하기',
        items: [
          { id: 'SR5.1', label: '지나치게 자극적이거나 원하지 않는 활동으로부터 스스로 떠나기' },
          { id: 'SR5.2', label: '극심한 조절장애로부터 회복하기 위해 행동 전략 사용하기' },
          { id: 'SR5.3', label: '극심한 조절장애로부터 회복하기 위해 언어 전략 사용하기' },
          { id: 'SR5.4', label: '극심한 조절장애로부터 회복된 후 상호작용이나 활동에 다시 참여하기' },
          { id: 'SR5.5', label: '극심한 조절장애로부터 회복되는 시간 단축하기' },
          { id: 'SR5.6', label: '조절장애 상태의 강도 줄이기' },
        ],
      },
    ],
  },

  interpersonalSupport: {
    label: '대인관계 지원',
    code: 'IS',
    maxScore: 66,
    groups: [
      {
        title: '1. 파트너는 아동에게 반응적이다.',
        items: [
          { id: 'IS1.1', label: '아동의 관심 초점 따르기' },
          { id: 'IS1.2', label: '아동의 정서 및 속도에 맞추기' },
          { id: 'IS1.3', label: '의사소통 효능감을 증진시키기 위해 아동의 신호에 적절하게 반응하기' },
          { id: 'IS1.4', label: '각성 수준을 조절하기 위한 아동의 행동 및 언어 전략 인식하고 지원하기' },
          { id: 'IS1.5', label: '조절장애 신호 인식하고 지원하기' },
          { id: 'IS1.6', label: '아동을 모방하기' },
          { id: 'IS1.7', label: '필요할 때 상호작용이나 활동으로부터 휴식 제공하기' },
          { id: 'IS1.8', label: '휴식에 이어 상호작용이나 활동에 다시 참여하도록 촉진하기' },
        ],
      },
      {
        title: '2. 파트너는 시작행동을 촉진한다.',
        items: [
          { id: 'IS2.1', label: '비구어 또는 구어로 선택의 기회 제공하기' },
          { id: 'IS2.2', label: '시작행동 기다리고 격려하기' },
          { id: 'IS2.3', label: '시작행동과 반응행동의 균형 유지하기' },
          { id: 'IS2.4', label: '아동이 활동을 시작하고 마치도록 해 주기' },
        ],
      },
      {
        title: '3. 파트너는 아동의 독립성을 존중한다.',
        items: [
          { id: 'IS3.1', label: '필요한 경우 활동 중간에 돌아다닐 수 있도록 휴식 허락하기' },
          { id: 'IS3.2', label: '아동이 자신의 속도로 문제를 해결하고 활동을 완수할 수 있도록 시간 허용하기' },
          { id: 'IS3.3', label: '문제행동을 의사소통 또는 조절의 기능으로 이해하기' },
          { id: 'IS3.4', label: '적절한 경우 저항, 거부, 거절 존중하기' },
        ],
      },
      {
        title: '4. 파트너는 참여를 위한 장을 마련한다.',
        items: [
          { id: 'IS4.1', label: '의사소통할 때 아동의 눈높이에 맞추기' },
          { id: 'IS4.2', label: '의사소통하기 전에 아동의 주의 확보하기' },
          { id: 'IS4.3', label: '상호작용을 촉진하기 위해 적절한 근접성과 비구어 행동 사용하기' },
          { id: 'IS4.4', label: '최적의 각성 상태와 참여를 지원하기 위해 적절한 단어와 억양 사용하기' },
        ],
      },
      {
        title: '5. 파트너는 발달을 지원한다.',
        items: [
          { id: 'IS5.1', label: '모방 격려하기' },
          { id: 'IS5.2', label: '또래와의 상호작용 격려하기' },
          { id: 'IS5.3', label: '구어 또는 비구어로 의사소통 실패를 복구하려고 시도하기' },
          { id: 'IS5.4', label: '활동 성공을 위해 필요할 때 안내 및 피드백 제공하기' },
          { id: 'IS5.5', label: '정서를 표현하고 정서의 원인을 이해하도록 안내하기' },
        ],
      },
      {
        title: '6. 파트너는 언어 사용을 조절한다.',
        items: [
          { id: 'IS6.1', label: '이해를 돕기 위해 비구어 단서 사용하기' },
          { id: 'IS6.2', label: '아동의 발달 수준에 따라 언어의 복잡성 조절하기' },
          { id: 'IS6.3', label: '아동의 각성 수준에 따라 언어의 질 조절하기' },
        ],
      },
      {
        title: '7. 파트너는 적절한 행동을 시범 보인다.',
        items: [
          { id: 'IS7.1', label: '적절한 비구어 의사소통과 정서 표현 시범 보이기' },
          { id: 'IS7.2', label: '다양한 의사소통 기능 시범 보이기' },
          { id: 'IS7.3', label: '적절한 구성놀이 및 상징놀이 시범 보이기' },
          { id: 'IS7.4', label: '아동이 부적절한 행동을 할 때 적절한 행동 시범 보이기' },
          { id: 'IS7.5', label: '‘아동 입장’에서 언어 시범 보이기' },
        ],
      },
    ],
  },

  learningSupport: {
    label: '학습 지원',
    code: 'LS',
    maxScore: 50,
    groups: [
      {
        title: '1. 파트너는 적극적인 참여를 위해 활동을 구조화한다.',
        items: [
          { id: 'LS1.1', label: '활동의 시작과 종료를 분명하게 정하기' },
          { id: 'LS1.2', label: '차례 주고받기 기회를 만들고 아동이 참여할 수 있도록 여지 남겨 두기' },
          { id: 'LS1.3', label: '활동에 예측 가능한 순서 마련하기' },
          { id: 'LS1.4', label: '반복되는 학습 기회 제공하기' },
          { id: 'LS1.5', label: '다양한 학습 기회 제공하기' },
        ],
      },
      {
        title: '2. 파트너는 발달을 촉진하기 위해 보완의사소통 지원을 사용한다.',
        items: [
          { id: 'LS2.1', label: '의사소통과 표현언어를 강화하기 위해 보완의사소통 지원 사용하기' },
          { id: 'LS2.2', label: '언어 및 행동 이해를 강화하기 위해 보완의사소통 지원 사용하기' },
          { id: 'LS2.3', label: '정서 표현 및 이해 능력을 강화하기 위해 보완의사소통 지원 사용하기' },
          { id: 'LS2.4', label: '정서 조절을 강화하기 위해 보완의사소통 지원 사용하기' },
        ],
      },
      {
        title: '3. 파트너는 시각적 지원 및 조직화 지원을 사용한다.',
        items: [
          { id: 'LS3.1', label: '과제 수행 단계를 명확히 하기 위해 지원 사용하기' },
          { id: 'LS3.2', label: '활동 완수에 필요한 시간과 단계를 명확히 하기 위해 지원 사용하기' },
          { id: 'LS3.3', label: '활동 간 원활한 전이를 위해 시각적 지원 사용하기' },
          { id: 'LS3.4', label: '하루 전반에 걸쳐 시간 분할을 조직화하기 위해 지원 사용하기' },
          { id: 'LS3.5', label: '집단 활동에서의 주의집중을 높이기 위해 시각적 지원 사용하기' },
          { id: 'LS3.6', label: '집단 활동에서의 적극적인 참여를 촉진하기 위해 시각적 지원 사용하기' },
        ],
      },
      {
        title: '4. 파트너는 목표, 활동, 학습 환경을 수정한다.',
        items: [
          { id: 'LS4.1', label: '조직화와 상호작용을 지원하기 위해 사회적 복잡성 조절하기' },
          { id: 'LS4.2', label: '아동의 성공을 위해 과제 난이도 조절하기' },
          { id: 'LS4.3', label: '학습 환경의 감각적 속성 수정하기' },
          { id: 'LS4.4', label: '주의집중을 높일 수 있도록 학습 환경 구성하기' },
          { id: 'LS4.5', label: '시작행동을 촉진하는 학습 환경 구성하기' },
          { id: 'LS4.6', label: '활동이 발달적으로 적절하도록 고안하고 수정하기' },
          { id: 'LS4.7', label: '활동 내에 동기유발이 가능한 교재 및 주제 포함시키기' },
          { id: 'LS4.8', label: '시작행동과 확장된 상호작용을 촉진하는 활동 제공하기' },
          { id: 'LS4.9', label: '필요에 따라 동적인 활동과 정적인 활동 교대하기' },
          { id: 'LS4.10', label: '‘요구의 정도를 높이거나’ 기대감을 적절하게 높이기' },
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
    label: '공동관심',
    code: 'JA',
    maxScore: 58,
    groups: [
      {
        title: '1. 관심 공유하기',
        items: [
          { id: 'JA1.1', label: '사회적 파트너의 관심 초점 따르기' },
          { id: 'JA1.2', label: '의도를 나타내기 전에 자신에게로 주의 끌기' },
          { id: 'JA1.3', label: '관심의 초점 변화에 대한 비구어 단서 이해하기' },
          { id: 'JA1.4', label: '파트너가 보거나 들은 것을 기초로 언어 수정하기' },
          { id: 'JA1.5', label: '파트너와 내적 사고나 정신적 계획 공유하기' },
        ],
      },
      {
        title: '2. 정서 공유하기',
        items: [
          { id: 'JA2.1', label: '초기 정서 단어 이해하고 사용하기' },
          { id: 'JA2.2', label: '다른 사람의 정서 상태를 초기 정서 단어로 묘사하기' },
          { id: 'JA2.3', label: '상위 수준 정서 단어 이해하고 사용하기' },
          { id: 'JA2.4', label: '다른 사람의 정서 상태를 상위 수준 정서 단어로 묘사하기' },
          { id: 'JA2.5', label: '단계적인 정서 이해하고 사용하기' },
          { id: 'JA2.6', label: '정서를 표현하는 비구어 단서 이해하기' },
          { id: 'JA2.7', label: '자신 및 다른 사람의 정서에 대한 타당한 원인 요소 설명하기' },
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
          { id: 'JA4.1', label: '경험을 공유하기 위해 청자 및 화자의 역할을 바꾸어 가며 상호작용하기' },
          { id: 'JA4.2', label: '다양한 대화 주제 시작하기' },
          { id: 'JA4.3', label: '파트너의 관심에 맞게 대화 시작하고 유지하기' },
          { id: 'JA4.4', label: '관련된 정보를 요구하거나 제공하여 상호작용 유지하기' },
          { id: 'JA4.5', label: '대화 주제에 대해 파트너가 알고 있는 지식을 기초로 필요한 정보 제공하기' },
          { id: 'JA4.6', label: '파트너에 따라 대화 차례의 길이 및 내용 판단하기' },
          { id: 'JA4.7', label: '파트너와 함께하기를 선호하기' },
          { id: 'JA4.8', label: '관심을 공유하는 파트너와 우정 맺기' },
        ],
      },
      {
        title: '5. 의사소통 실패를 복구하고 지속하기',
        items: [
          { id: 'JA5.1', label: '맥락에 적절한 비율로 의사소통하기' },
          { id: 'JA5.2', label: '의사소통 실패를 복구하기 위해 반복하거나 수정하기' },
          { id: 'JA5.3', label: '의사소통 실패를 인식하고 명료화 요구하기' },
          { id: 'JA5.4', label: '파트너의 의견 변화에 따라 언어 및 행동 수정하기' },
          { id: 'JA5.5', label: '파트너의 정서 반응에 따라 언어 및 행동 수정하기' },
          { id: 'JA5.6', label: '상호작용 중에 성취감 및 자신감 표현하기' },
        ],
      },
    ],
  },

  symbolUse: {
    label: '상징 사용',
    code: 'SU',
    maxScore: 58,
    groups: [
      {
        title: '1. 모방, 관찰, 교수 및 협력을 통해 학습하기',
        items: [
          { id: 'SU1.1', label: '시간이 경과된 후 다른 맥락에서 다양한 행동을 자발적으로 모방하기' },
          { id: 'SU1.2', label: '사회적 행동을 안내하기 위해 파트너가 시범 보인 행동 사용하기' },
          { id: 'SU1.3', label: '행동을 안내하기 위해 성인이 시범 보인 내재화된 규칙 사용하기' },
          { id: 'SU1.4', label: '행동을 안내하기 위해 자기점검이나 혼잣말 사용하기' },
          { id: 'SU1.5', label: '문제를 해결할 때 또래와 협력하고 타협하기' },
        ],
      },
      {
        title: '2. 상호적 상호작용에서 비구어 단서와 비문자적 의미 이해하기',
        items: [
          { id: 'SU2.1', label: '차례 주고받기 및 주제 변화에 대한 비구어 단서 이해하기' },
          { id: 'SU2.2', label: '정서를 표현하는 비구어 단서 이해하기' },
          { id: 'SU2.3', label: '유머와 비유적 표현의 비구어 단서 및 비문자적 의미 이해하기' },
          { id: 'SU2.4', label: '놀림, 비꼬는 말, 속임수의 비구어 단서 및 비문자적 의미 이해하기' },
        ],
      },
      {
        title: '3. 극놀이와 여가활동에 관습적인 방식으로 참여하기',
        items: [
          { id: 'SU3.1', label: '익숙한 사건에 관한 놀이에서 행동의 논리적 순서 사용하기' },
          { id: 'SU3.2', label: '모형이나 추상적 사물을 소품으로 사용하기' },
          { id: 'SU3.3', label: '덜 익숙한 사건에 관한 놀이에서 행동의 논리적 순서 사용하기' },
          { id: 'SU3.4', label: '극놀이에서 역할을 맡아 참여하기' },
          { id: 'SU3.5', label: '다른 아동과 공동의 놀이 활동에 참여하기' },
          { id: 'SU3.6', label: '극놀이에서 역할을 맡아 또래와 협력하기' },
          { id: 'SU3.7', label: '규칙이 있는 집단 놀이 활동에 참여하기' },
        ],
      },
      {
        title: '4. 맥락에 적절한 몸짓이나 비구어 행동 사용하기',
        items: [
          { id: 'SU4.1', label: '맥락과 파트너에 맞게 적절한 얼굴 표정 사용하기' },
          { id: 'SU4.2', label: '맥락과 파트너에 맞게 적절한 몸짓 사용하기' },
          { id: 'SU4.3', label: '맥락과 파트너에 맞게 적절한 자세 및 근접성 사용하기' },
          { id: 'SU4.4', label: '맥락과 파트너에 맞게 목소리 크기와 억양 사용하기' },
        ],
      },
      {
        title: '5. 의미를 표현하기 위해 생성적 언어 이해하고 사용하기',
        items: [
          { id: 'SU5.1', label: '다양한 상위 수준 관계어 이해하고 사용하기' },
          { id: 'SU5.2', label: '어떤 것을 나타내는 지시어 이해하고 사용하기' },
          { id: 'SU5.3', label: '다양한 동사구 이해하고 사용하기' },
          { id: 'SU5.4', label: '다양한 문장 구조 이해하고 사용하기' },
          { id: 'SU5.5', label: '구어나 쓰기 담화에서 연결된 문장 이해하고 사용하기' },
        ],
      },
      {
        title: '6. 대화 규칙 따르기',
        items: [
          { id: 'SU6.1', label: '관습에 따라 대화 시작하고 차례 주고받기' },
          { id: 'SU6.2', label: '관습에 따라 대화 주제 전환하기' },
          { id: 'SU6.3', label: '관습에 따라 대화 종료하기' },
          { id: 'SU6.4', label: '예의범절에 대한 관습 따르고 표현하기' },
        ],
      },
    ],
  },

  mutualReg: {
    label: '상호조절',
    code: 'MR',
    maxScore: 56,
    groups: [
      {
        title: '1. 다양한 정서 표현하기',
        items: [
          { id: 'MR1.1', label: '초기 정서 단어 이해하고 사용하기' },
          { id: 'MR1.2', label: '상위 수준 정서 단어 이해하고 사용하기' },
          { id: 'MR1.3', label: '단계적인 정서 이해하고 사용하기' },
          { id: 'MR1.4', label: '파트너의 피드백에 따라 정서 표현 바꾸기' },
          { id: 'MR1.5', label: '정서를 표현하는 비구어 단서 사용하기' },
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
          { id: 'MR2.6', label: '파트너가 제공한 정보나 전략에 반응하기' },
        ],
      },
      {
        title: '3. 행동에 대한 피드백 및 안내에 반응하기',
        items: [
          { id: 'MR3.1', label: '정서 표현의 적절성에 대한 피드백에 반응하기' },
          { id: 'MR3.2', label: '조절 전략의 적절성에 대한 피드백에 반응하기' },
          { id: 'MR3.3', label: '사회적 행동을 안내하기 위해 파트너가 시범 보인 행동 사용하기' },
          { id: 'MR3.4', label: '문제를 해결할 때 또래와 협력하고 타협하기' },
          { id: 'MR3.5', label: '합의점에 도달하기 위해 타협하는 동안 파트너의 의견 수용하기' },
        ],
      },
      {
        title: '4. 상태를 조절하기 위해 파트너에게 도움 청하기',
        items: [
          { id: 'MR4.1', label: '위로를 구하기 위해 부정적인 정서 공유하기' },
          { id: 'MR4.2', label: '상호작용을 하기 위해 긍정적인 정서 공유하기' },
          { id: 'MR4.3', label: '다른 사람의 행동을 조절하기 위해 의도 공유하기' },
          { id: 'MR4.4', label: '사회적 상호작용을 위해 의도 공유하기' },
          { id: 'MR4.5', label: '공동관심을 위해 의도 공유하기' },
          { id: 'MR4.6', label: '갈등 및 문제 해결 상황에서 지원 요구하기' },
        ],
      },
      {
        title: '5. 파트너의 지원을 받아 극심한 조절장애로부터 회복하기',
        items: [
          { id: 'MR5.1', label: '활동으로부터 떨어져 있게 하는 방법으로 회복을 지원하는 파트너의 노력에 반응하기' },
          { id: 'MR5.2', label: '파트너의 행동 전략 사용에 반응하기' },
          { id: 'MR5.3', label: '파트너의 언어 전략 사용에 반응하기' },
          { id: 'MR5.4', label: '상호작용이나 활동에 다시 참여하게 하기 위한 파트너의 시도에 반응하기' },
          { id: 'MR5.5', label: '파트너의 지원을 받아 극심한 조절장애로부터 회복되는 시간 단축하기' },
          { id: 'MR5.6', label: '파트너의 지원을 받아 극심한 조절장애 상태의 강도 줄이기' },
        ],
      },
    ],
  },

  selfReg: {
    label: '자기조절',
    code: 'SR',
    maxScore: 64,
    groups: [
      {
        title: '1. 학습 또는 상호작용의 가능성 보이기',
        items: [
          { id: 'SR1.1', label: '차별화된 정서로 감각 및 사회적 경험에 반응하기' },
          { id: 'SR1.2', label: '사회적 파트너의 관심 초점 따르기' },
          { id: 'SR1.3', label: '경험을 공유하기 위해 청자 및 화자의 역할을 바꾸어 가며 상호작용하기' },
          { id: 'SR1.4', label: '행위 및 행동 억제 능력 보이기' },
          { id: 'SR1.5', label: '합리적인 요구를 지닌 과제 지속하기' },
          { id: 'SR1.6', label: '맥락에 적절하게 정서 표현하기' },
        ],
      },
      {
        title: '2. 익숙한 활동 중에 각성 수준을 조절하기 위해 행동 전략 사용하기',
        items: [
          { id: 'SR2.1', label: '혼자 하는 활동 및 사회적 활동 중에 각성 수준을 조절하기 위해 행동 전략 사용하기' },
          { id: 'SR2.2', label: '각성 수준을 조절하기 위해 파트너가 시범 보인 행동 전략 사용하기' },
          { id: 'SR2.3', label: '장시간의 활동에 생산적으로 참여하기 위해 행동 전략 사용하기' },
        ],
      },
      {
        title: '3. 익숙한 활동 중에 각성 수준을 조절하기 위해 언어 전략 사용하기',
        items: [
          { id: 'SR3.1', label: '초기 정서 단어 이해하고 사용하기' },
          { id: 'SR3.2', label: '상위 수준 정서 단어 이해하고 사용하기' },
          { id: 'SR3.3', label: '단계적인 정서 이해하고 사용하기' },
          { id: 'SR3.4', label: '혼자 하는 활동 및 사회적 활동 중에 각성 수준을 조절하기 위해 언어 전략 사용하기' },
          { id: 'SR3.5', label: '각성 수준을 조절하기 위해 파트너가 시범 보인 언어 전략 사용하기' },
          { id: 'SR3.6', label: '장시간의 활동에 생산적으로 참여하기 위해 언어 전략 사용하기' },
        ],
      },
      {
        title: '4. 익숙한 활동 중에 각성 수준을 조절하기 위해 초인지 전략 사용하기',
        items: [
          { id: 'SR4.1', label: '행동을 안내하기 위해 성인이 시범 보인 내재화된 규칙 사용하기' },
          { id: 'SR4.2', label: '활동 계획을 달성하기 위해 초인지 전략 사용하기' },
          { id: 'SR4.3', label: '행동을 안내하기 위해 자기점검이나 혼잣말 사용하기' },
          { id: 'SR4.4', label: '정서 조절을 돕기 위해 정서 기억 사용하기' },
          { id: 'SR4.5', label: '조절 지원 전략 파악하고 반영하기' },
        ],
      },
      {
        title: '5. 새롭고 변화하는 상황에서 정서 조절하기',
        items: [
          { id: 'SR5.1', label: '새롭고 변화하는 상황에서 각성 수준을 조절하기 위해 행동 전략 사용하기' },
          { id: 'SR5.2', label: '새롭고 변화하는 상황에서 각성 수준을 조절하기 위해 언어 전략 사용하기' },
          { id: 'SR5.3', label: '새롭고 변화하는 상황에서 각성 수준을 조절하기 위해 초인지 전략 사용하기' },
          { id: 'SR5.4', label: '전이 중 각성 수준을 조절하기 위해 행동 전략 사용하기' },
          { id: 'SR5.5', label: '전이 중 각성 수준을 조절하기 위해 언어 전략 사용하기' },
          { id: 'SR5.6', label: '전이 중 각성 수준을 조절하기 위해 초인지 전략 사용하기' },
        ],
      },
      {
        title: '6. 극심한 조절장애로부터 스스로 회복하기',
        items: [
          { id: 'SR6.1', label: '지나치게 자극적이거나 원하지 않는 활동으로부터 스스로 떠나기' },
          { id: 'SR6.2', label: '극심한 조절장애로부터 회복하기 위해 행동 전략 사용하기' },
          { id: 'SR6.3', label: '극심한 조절장애로부터 회복하기 위해 언어 전략 사용하기' },
          { id: 'SR6.4', label: '극심한 조절장애로부터 회복된 후 상호작용이나 활동에 다시 참여하기' },
          { id: 'SR6.5', label: '극심한 조절장애로부터 회복되는 시간 단축하기' },
          { id: 'SR6.6', label: '조절장애 상태의 강도 줄이기' },
        ],
      },
    ],
  },

  interpersonalSupport: {
    label: '대인관계 지원',
    code: 'IS',
    maxScore: 66,
    groups: [
      {
        title: '1. 파트너는 아동에게 반응적이다.',
        items: [
          { id: 'IS1.1', label: '아동의 관심 초점 따르기' },
          { id: 'IS1.2', label: '아동의 정서 및 속도에 맞추기' },
          { id: 'IS1.3', label: '의사소통 효능감을 증진시키기 위해 아동의 신호에 적절하게 반응하기' },
          { id: 'IS1.4', label: '각성 수준을 조절하기 위한 아동의 행동, 언어, 초인지 전략 인식하고 지원하기' },
          { id: 'IS1.5', label: '조절장애 신호 인식하고 지원하기' },
          { id: 'IS1.6', label: '상태를 조절할 수 있도록 정보와 도움 제공하기' },
          { id: 'IS1.7', label: '필요할 때 상호작용이나 활동으로부터 휴식 제공하기' },
          { id: 'IS1.8', label: '휴식에 이어 상호작용이나 활동에 다시 참여하도록 촉진하기' },
        ],
      },
      {
        title: '2. 파트너는 시작행동을 촉진한다.',
        items: [
          { id: 'IS2.1', label: '비구어 또는 구어로 선택의 기회 제공하기' },
          { id: 'IS2.2', label: '시작행동 기다리고 격려하기' },
          { id: 'IS2.3', label: '시작행동과 반응행동의 균형 유지하기' },
          { id: 'IS2.4', label: '아동이 활동을 시작하고 마치도록 해 주기' },
        ],
      },
      {
        title: '3. 파트너는 아동의 독립성을 존중한다.',
        items: [
          { id: 'IS3.1', label: '필요한 경우 활동 중간에 돌아다닐 수 있도록 휴식 허락하기' },
          { id: 'IS3.2', label: '아동이 자신의 속도로 문제를 해결하고 활동을 완수할 수 있도록 시간 허용하기' },
          { id: 'IS3.3', label: '문제행동을 의사소통 또는 조절의 기능으로 이해하기' },
          { id: 'IS3.4', label: '적절한 경우 저항, 거부, 거절 존중하기' },
        ],
      },
      {
        title: '4. 파트너는 참여를 위한 장을 마련한다.',
        items: [
          { id: 'IS4.1', label: '의사소통하기 전에 아동의 주의 확보하기' },
          { id: 'IS4.2', label: '상호작용을 촉진하기 위해 적절한 근접성과 비구어 행동 사용하기' },
          { id: 'IS4.3', label: '최적의 각성 상태와 참여를 지원하기 위해 적절한 단어와 억양 사용하기' },
          { id: 'IS4.4', label: '정서, 내적 상태, 정신적 계획 공유하기' },
        ],
      },
      {
        title: '5. 파트너는 발달을 지원한다.',
        items: [
          { id: 'IS5.1', label: '또래와의 상호작용 성공을 위해 안내 제공하기' },
          { id: 'IS5.2', label: '구어 또는 비구어로 의사소통 실패를 복구하려고 시도하기' },
          { id: 'IS5.3', label: '활동 성공을 위해 필요할 때 안내 및 피드백 제공하기' },
          { id: 'IS5.4', label: '정서를 표현하고 정서의 원인을 이해하도록 안내하기' },
          { id: 'IS5.5', label: '다른 사람의 감정과 생각을 해석할 수 있도록 안내하기' },
        ],
      },
      {
        title: '6. 파트너는 언어 사용을 조절한다.',
        items: [
          { id: 'IS6.1', label: '이해를 돕기 위해 비구어 단서 사용하기' },
          { id: 'IS6.2', label: '아동의 발달 수준에 따라 언어의 복잡성 조절하기' },
          { id: 'IS6.3', label: '아동의 각성 수준에 따라 언어의 질 조절하기' },
        ],
      },
      {
        title: '7. 파트너는 적절한 행동을 시범 보인다.',
        items: [
          { id: 'IS7.1', label: '적절한 비구어 의사소통과 정서 표현 시범 보이기' },
          { id: 'IS7.2', label: '다양한 의사소통 기능 시범 보이기' },
          { id: 'IS7.3', label: '적절한 극놀이 및 여가활동 시범 보이기' },
          { id: 'IS7.4', label: '아동이 부적절한 행동을 할 때 적절한 행동 시범 보이기' },
          { id: 'IS7.5', label: '‘아동 입장’에서 언어 및 혼잣말 사용 시범 보이기' },
        ],
      },
    ],
  },

  learningSupport: {
    label: '학습 지원',
    code: 'LS',
    maxScore: 50,
    groups: [
      {
        title: '1. 파트너는 적극적인 참여를 위해 활동을 구조화한다.',
        items: [
          { id: 'LS1.1', label: '활동의 시작과 종료를 분명하게 정하기' },
          { id: 'LS1.2', label: '차례 주고받기 기회를 만들고 아동이 참여할 수 있도록 여지 남겨 두기' },
          { id: 'LS1.3', label: '활동에 예측 가능한 순서 마련하기' },
          { id: 'LS1.4', label: '반복되는 학습 기회 제공하기' },
          { id: 'LS1.5', label: '다양한 학습 기회 제공하기' },
        ],
      },
      {
        title: '2. 파트너는 발달을 촉진하기 위해 보완의사소통 지원을 사용한다.',
        items: [
          { id: 'LS2.1', label: '의사소통과 표현언어를 강화하기 위해 보완의사소통 지원 사용하기' },
          { id: 'LS2.2', label: '언어 및 행동 이해를 강화하기 위해 보완의사소통 지원 사용하기' },
          { id: 'LS2.3', label: '정서 표현 및 이해를 강화하기 위해 보완의사소통 지원 사용하기' },
          { id: 'LS2.4', label: '정서 조절을 강화하기 위해 보완의사소통 지원 사용하기' },
        ],
      },
      {
        title: '3. 파트너는 시각적 지원 및 조직화 지원을 사용한다.',
        items: [
          { id: 'LS3.1', label: '과제 수행 단계를 명확히 하기 위해 지원 사용하기' },
          { id: 'LS3.2', label: '활동 완수에 필요한 시간과 단계를 명확히 하기 위해 지원 사용하기' },
          { id: 'LS3.3', label: '활동 간 원활한 전이를 위해 시각적 지원 사용하기' },
          { id: 'LS3.4', label: '하루 전반에 걸쳐 시간 분할을 조직화하기 위해 지원 사용하기' },
          { id: 'LS3.5', label: '집단 활동에서의 주의집중을 높이기 위해 시각적 지원 사용하기' },
          { id: 'LS3.6', label: '집단 활동에서의 적극적인 참여를 촉진하기 위해 시각적 지원 사용하기' },
        ],
      },
      {
        title: '4. 파트너는 목표, 활동, 학습 환경을 수정한다.',
        items: [
          { id: 'LS4.1', label: '조직화와 상호작용을 지원하기 위해 사회적 복잡성 조절하기' },
          { id: 'LS4.2', label: '아동의 성공을 위해 과제 난이도 조절하기' },
          { id: 'LS4.3', label: '학습 환경의 감각적 속성 수정하기' },
          { id: 'LS4.4', label: '주의집중을 높일 수 있도록 학습 환경 구성하기' },
          { id: 'LS4.5', label: '시작행동을 촉진하는 학습 환경 구성하기' },
          { id: 'LS4.6', label: '활동이 발달적으로 적절하도록 고안하고 수정하기' },
          { id: 'LS4.7', label: '활동 내에 동기유발이 가능한 교재 및 주제 포함시키기' },
          { id: 'LS4.8', label: '시작행동과 확장된 상호작용을 촉진하는 활동 제공하기' },
          { id: 'LS4.9', label: '필요에 따라 동적인 활동과 정적인 활동 교대하기' },
          { id: 'LS4.10', label: '‘요구의 정도를 높이거나’ 기대감을 적절하게 높이기' },
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
    title: '사회 의사소통',
    domains: ['joinAttention', 'symbolUse'],
  },
  {
    title: '정서 조절',
    domains: ['mutualReg', 'selfReg'],
  },
  {
    title: '교류 지원',
    domains: ['interpersonalSupport', 'learningSupport'],
  },
];

// =====================================================================
// SCERTS 지식 베이스 — 자동 가이드, 우선순위, 단계별 특징
// =====================================================================

// ── 단계별 특징 (보고서에 자동 삽입되는 단계 설명) ───────────────
// 단계 이름 (보고서 문장에 쓰는 이름 — 1권 단계 이름 그대로)
const STAGE_PROFILE = {
  social: { headline: '사회적 파트너 단계' },
  language: { headline: '언어 파트너 단계' },
  conversation: { headline: '대화 파트너 단계' },
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
  // ★ 1권 부록 언어 파트너 관찰 기록지의 '=' 표시 (양쪽 문항 모두에 표시된 9쌍)
  language: [
    ['JA1.1', 'SR1.1'],
    ['JA1.2', 'SR1.2'],
    ['JA1.3', 'SR1.3'],
    ['JA2.2', 'SU2.2'],
    ['JA3.1', 'MR1.1'],
    ['JA3.3', 'MR2.5'],
    ['MR1.2', 'SR3.5'],
    ['SR1.6', 'SU6.2'],
    ['SR4.2', 'SU2.1'],
  ],
  // ★ 1권 부록 대화 파트너 관찰 기록지의 '=' 표시 (19쌍. JA2.1=MR1.1=SR3.1처럼 셋이 같은 것도 있음)
  conversation: [
    ['JA1.1', 'SR1.2'],
    ['JA2.1', 'MR1.1'],
    ['JA2.1', 'SR3.1'],
    ['JA2.3', 'MR1.2'],
    ['JA2.3', 'SR3.2'],
    ['JA2.5', 'MR1.3'],
    ['JA2.5', 'SR3.3'],
    ['JA2.6', 'SU2.2'],
    ['JA3.1', 'MR4.3'],
    ['JA3.2', 'MR4.4'],
    ['JA3.3', 'MR4.5'],
    ['JA4.1', 'SR1.3'],
    ['MR1.1', 'SR3.1'],
    ['MR1.2', 'SR3.2'],
    ['MR1.3', 'SR3.3'],
    ['MR3.3', 'SU1.2'],
    ['MR3.4', 'SU1.5'],
    ['SR4.1', 'SU1.3'],
    ['SR4.3', 'SU1.4'],
  ],
};

// ★ 1권 부록 관찰 기록지에 문항 옆에 적힌 관계 표시(=, ≈, ↔)와 문항 아래 체크칸(□) — 책 글자 그대로
const BOOK_ITEM_MARKS = {
 "social": {
  "JA1.1": {
   "rel": "(=MR2.3)"
  },
  "JA1.2": {
   "rel": "(=SR1.4)"
  },
  "JA1.3": {
   "rel": "(=SR1.5)"
  },
  "JA1.4": {
   "rel": "(=SR1.6)"
  },
  "JA2.3": {
   "rel": "(=SU2.4)"
  },
  "JA2.4": {
   "rel": "(=SU2.5)"
  },
  "JA3.1": {
   "rel": "(≈MR3.1)"
  },
  "JA3.2": {
   "rel": "(≈MR3.2)"
  },
  "JA3.3": {
   "rel": "(=MR2.4, SU2.7)"
  },
  "JA3.4": {
   "rel": "(=MR2.5)"
  },
  "JA4.1": {
   "rel": "(≈MR2.6)"
  },
  "JA4.2": {
   "rel": "(≈MR3.4)"
  },
  "JA4.3": {
   "rel": "(≈MR3.3)"
  },
  "JA4.4": {
   "rel": "(≈MR3.4)"
  },
  "JA5.1": {
   "rel": "(≈MR3.1)"
  },
  "JA7.2": {
   "rel": "(↔JA4-JA6)"
  },
  "JA7.3": {
   "rel": "(↔JA4-JA6)"
  },
  "SU2.1": {
   "rel": "(=SR3.1)"
  },
  "SU2.4": {
   "rel": "(=JA2.3)"
  },
  "SU2.5": {
   "rel": "(=JA2.4)"
  },
  "SU2.7": {
   "rel": "(≈JA3.3)"
  },
  "SU3.1": {
   "rel": "(↔SR2.1)"
  },
  "SU4.4": {
   "subs": [
    "주기",
    "밀어내기",
    "보여 주기",
    "손 뻗기/만지기",
    "가리키기/만지기"
   ]
  },
  "SU4.5": {
   "subs": [
    "손 흔들기",
    "멀리 손 뻗기",
    "멀리 있는 것 가리키기",
    "손뼉 치기",
    "고개 젓기",
    "고개 끄덕이기"
   ]
  },
  "SU5.1": {
   "rel": "(↔MR1)"
  },
  "MR2.3": {
   "rel": "(=JA1.1)"
  },
  "MR2.4": {
   "rel": "(=JA3.3)"
  },
  "MR2.5": {
   "rel": "(=JA3.4)"
  },
  "MR2.6": {
   "rel": "(≈JA4.1)"
  },
  "MR3.1": {
   "rel": "(≈JA3.1; ↔ JA5.1)"
  },
  "MR3.2": {
   "rel": "(≈JA3.2)"
  },
  "MR3.3": {
   "rel": "(≈JA4.3; ↔ SU4-SU5)"
  },
  "MR3.4": {
   "rel": "(≈JA4.2, JA4.4; ↔ SU4-SU5)"
  },
  "SR1.4": {
   "rel": "(=JA1.2)"
  },
  "SR1.5": {
   "rel": "(=JA1.3)"
  },
  "SR1.6": {
   "rel": "(=JA1.4)"
  },
  "SR2.1": {
   "rel": "(↔SU3.1)"
  },
  "SR3.1": {
   "rel": "(=SU2.1)"
  },
  "IS7.2": {
   "subs": [
    "a. 행동 조절",
    "b. 사회적 상호작용",
    "c. 공동관심"
   ]
  }
 },
 "language": {
  "JA1.1": {
   "rel": "(=SR1.1)"
  },
  "JA1.2": {
   "rel": "(=SR1.2)"
  },
  "JA1.3": {
   "rel": "(=SR1.3)"
  },
  "JA2.2": {
   "rel": "(=SU2.2)"
  },
  "JA2.4": {
   "rel": "(≈JA5.5)"
  },
  "JA3.1": {
   "rel": "(=MR1.1;≈MR3.1, MR3.2)"
  },
  "JA3.2": {
   "rel": "(≈MR1.2, SR3.5)"
  },
  "JA3.3": {
   "rel": "(≈SU2.4; =MR2.5)"
  },
  "JA3.4": {
   "rel": "(↔SU5.6)"
  },
  "JA4.1": {
   "rel": "(≈MR2.6)"
  },
  "JA4.2": {
   "rel": "(≈MR3.4)"
  },
  "JA4.3": {
   "rel": "(≈MR3.3)"
  },
  "JA4.4": {
   "rel": "(≈MR3.4)"
  },
  "JA5.1": {
   "rel": "(≈MR3.1)"
  },
  "JA5.5": {
   "rel": "(≈JA2.4)"
  },
  "JA7.2": {
   "rel": "(↔JA4-JA6)"
  },
  "JA8.2": {
   "rel": "(↔ JA4-JA6)"
  },
  "SU2.1": {
   "rel": "(=SR4.2)"
  },
  "SU2.2": {
   "rel": "(=JA2.2)"
  },
  "SU2.4": {
   "rel": "(≈JA3.3)"
  },
  "SU4.1": {
   "subs": [
    "a. 보여 주기",
    "b. 손 흔들기",
    "c. 멀리 손 뻗기/가리키기",
    "d. 손뼉 치기",
    "e. 고개 젓기",
    "f. 고개 끄덕이기",
    "g. 기타"
   ]
  },
  "SU5.3": {
   "subs": [
    "a. 존재",
    "b. 부재/사라짐",
    "c. 재출현",
    "d. 거부"
   ]
  },
  "SU5.5": {
   "subs": [
    "a. 개인적-사회적",
    "b. 행위",
    "c. 수식어",
    "d. 의문사"
   ]
  },
  "SU5.6": {
   "rel": "(↔JA3.4)",
   "subs": [
    "a. 수식어+대상",
    "b. 부정어+대상",
    "c. 행위자+행위+대상"
   ]
  },
  "SU6.2": {
   "rel": "(=SR1.6)"
  },
  "SU6.4": {
   "subs": [
    "a. 행위",
    "b. 수식어",
    "c. 의문사"
   ]
  },
  "SU6.5": {
   "subs": [
    "a. 수식어+대상",
    "b. 부정어+대상",
    "c. 행위자+행위+대상"
   ]
  },
  "MR1.1": {
   "rel": "(=JA3.1)"
  },
  "MR1.2": {
   "rel": "(≈JA3.2; =SR3.5)"
  },
  "MR2.5": {
   "rel": "(=JA3.3)"
  },
  "MR2.6": {
   "rel": "(≈JA4.1)"
  },
  "MR3.1": {
   "rel": "(≈JA3.1; ↔JA5.1)"
  },
  "MR3.2": {
   "rel": "(≈JA3.1)"
  },
  "MR3.3": {
   "rel": "(≈JA4.3; ↔SU4-SU5)"
  },
  "MR3.4": {
   "rel": "(≈JA4.2, JA4.4; ↔SU4-SU5)"
  },
  "MR3.7": {
   "rel": "(↔JA4)"
  },
  "SR1.1": {
   "rel": "(=JA1.1)"
  },
  "SR1.2": {
   "rel": "(=JA1.2)"
  },
  "SR1.3": {
   "rel": "(=JA1.3)"
  },
  "SR1.6": {
   "rel": "(=SU6.2)"
  },
  "SR3.5": {
   "rel": "(≈JA3.2;=MR1.2)"
  },
  "SR4.2": {
   "rel": "(=SU2.1)"
  },
  "IS7.2": {
   "subs": [
    "a. 행동 조절",
    "b. 사회적 상호작용",
    "c. 공동관심"
   ]
  }
 },
 "conversation": {
  "JA1.1": {
   "rel": "(=SR1.2)"
  },
  "JA2.1": {
   "rel": "(=MR1.1, SR3.1)"
  },
  "JA2.3": {
   "rel": "(=MR1.2, SR3.2)"
  },
  "JA2.5": {
   "rel": "(=MR1.3, SR3.3)"
  },
  "JA2.6": {
   "rel": "(=SU2.2)"
  },
  "JA3.1": {
   "rel": "(=MR4.3)",
   "subs": [
    "a. 원하는 사물이나 활동 요구하기",
    "b. 도움 청하기",
    "c. 휴식 요구하기",
    "d. 원하지 않는 사물이나 활동 거절/거부하기"
   ]
  },
  "JA3.2": {
   "rel": "(=MR4.4)",
   "subs": [
    "a. 인사하기",
    "b. 부르기",
    "c. 위로 구하기",
    "d. 차례 조절하기",
    "e. 허락 구하기",
    "f. 파트너 칭찬하기",
    "g. 공감 표현하기",
    "h. 비밀 공유하기"
   ]
  },
  "JA3.3": {
   "rel": "(=MR4.5)",
   "subs": [
    "a. 현재, 과거, 상상의 사건 언급하기",
    "b. 현재 또는 과거 사건에 대해 요구된 정보 제공하기",
    "c. 현재, 과거, 미래 사건에 대한 정보 요구하기",
    "d. 기분이나 의견 표현하기",
    "e. 결과 예상하고 계획하기"
   ]
  },
  "JA4.1": {
   "rel": "(=SR1.3)"
  },
  "JA5.2": {
   "rel": "(↔JA3)"
  },
  "SU1.2": {
   "rel": "(=MR3.3)"
  },
  "SU1.3": {
   "rel": "(=SR4.1)"
  },
  "SU1.4": {
   "rel": "(=SR4.3)"
  },
  "SU1.5": {
   "rel": "(=MR3.4)"
  },
  "SU2.2": {
   "rel": "(=JA2.6)"
  },
  "SU5.1": {
   "subs": [
    "a. 의문사",
    "b. 시간 관계",
    "c. 물리적 관계",
    "d. 수 관계",
    "e. 장소 어휘",
    "f. 친족 어휘",
    "g. 원인 어휘"
   ]
  },
  "SU5.2": {
   "subs": [
    "a. 주격 대명사",
    "b. 기타 대명사",
    "c. 관사",
    "d. 복수"
   ]
  },
  "SU5.3": {
   "subs": [
    "a. 본동사",
    "b. 시제",
    "c. 조동사",
    "d. 법조동사",
    "e. 부정어"
   ]
  },
  "SU5.4": {
   "subs": [
    "a. 능동형 평서문",
    "b. 명령문",
    "c. 부정문",
    "d. 의문문",
    "e. 삽입문",
    "f. 복합문"
   ]
  },
  "MR1.1": {
   "rel": "(=JA2.1, SR3.1)"
  },
  "MR1.2": {
   "rel": "(=JA2.3, SR3.2)"
  },
  "MR1.3": {
   "rel": "(=JA2.5, SR3.3)"
  },
  "MR3.3": {
   "rel": "(=SU1.2)"
  },
  "MR3.4": {
   "rel": "(=SU1.5)"
  },
  "MR4.3": {
   "rel": "(=JA3.1)",
   "subs": [
    "a. 원하는 사물이나 활동 요구하기",
    "b. 도움 청하기",
    "c. 휴식 요구하기",
    "d. 원하지 않는 사물이나 활동을 거절/거부하기"
   ]
  },
  "MR4.4": {
   "rel": "(=JA3.2)",
   "subs": [
    "a. 인사하기",
    "b. 부르기",
    "c. 위로 구하기",
    "d. 차례 조절하기",
    "e. 허락 구하기",
    "f. 파트너 칭찬하기",
    "g. 공감 표현하기",
    "h. 비밀 공유하기"
   ]
  },
  "MR4.5": {
   "rel": "(=JA3.3)",
   "subs": [
    "a. 현재, 과거, 상상의 사건 언급하기",
    "b. 현재 또는 과거 사건에 대해 요구된 정보 제공하기",
    "c. 현재, 과거, 미래 사건에 대한 정보 요구하기",
    "d. 기분이나 의견 표현하기",
    "e. 결과 예상하고 계획하기"
   ]
  },
  "SR1.2": {
   "rel": "(=JA1.1)"
  },
  "SR1.3": {
   "rel": "(=JA4.1)"
  },
  "SR3.1": {
   "rel": "(=JA2.1, MR1.1)"
  },
  "SR3.2": {
   "rel": "(=JA2.3, MR1.2)"
  },
  "SR3.3": {
   "rel": "(=JA2.5, MR1.3)"
  },
  "SR4.1": {
   "rel": "(=SU1.3)"
  },
  "SR4.3": {
   "rel": "(=SU1.4)"
  },
  "IS7.2": {
   "subs": [
    "a. 행동 조절",
    "b. 사회적 상호작용",
    "c. 공동관심"
   ]
  }
 }
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

// ── IEP 우선순위 추천 (IEP 화면과 자동 채움·보고서가 같은 목록을 쓴다) ─────
//   책의 세 기준(기능성·가족 우선순위·발달적 적합성, 2권 33~35쪽)을 돕는 보조 점수.
//   ★ '=' 같은 문항(1권 부록)은 한 번만 추천하고, 짝 문항 번호를 sameAs에 붙인다
function computeRecommendedGoals(stageKey, scores, familyPriorities) {
  const stageData = STAGE_DATA[stageKey];
  if (!stageData) return [];
  const sc = scores || {};
  const weights = IEP_PRIORITY_WEIGHTS;
  const foundations = FOUNDATION_ITEMS[stageKey] || new Set();
  const tree = JA_DEVELOPMENT_TREE[stageKey] || {};
  const familyFocus = new Set(familyPriorities?.focusGoalIds || []);
  const list = [];
  Object.entries(stageData).forEach(([dkey, domain]) => {
    domain.groups.forEach((g) =>
      g.items.forEach((it) => {
        const v = sc[it.id];
        if (v !== 0 && v !== 1) return;
        // ★ 책 기준(2권 32~35쪽): 가족의 우선순위 → 발달적 적합성
        //   (연습 중인 1점 → 배우는 중인 0점, 앞 장기목표·앞 교수목표 먼저). 아동 목표를 교류 지원보다 먼저.
        //   책에 없는 영역별 가중치는 쓰지 않는다.
        const isFamilyChoice = familyFocus.has(it.id);
        const isTsItem = dkey === 'interpersonalSupport' || dkey === 'learningSupport';
        const [gNo, iNo] = it.id.slice(2).split('.').map(Number);
        const priority = (isTsItem ? 0 : 1000000) + (isFamilyChoice ? 100000 : 0) + (v === 1 ? 10000 : 0) - gNo * 100 - iNo;
        const prereqsMet = true;
        list.push({
          id: it.id, label: it.label, domain: domain.label, domainKey: dkey,
          groupTitle: (g.title || '').replace(/^\d+\.\s*/, '').replace(/[.。]\s*$/, ''),
          score: v, priority, isFoundation: foundations.has(it.id), isFamilyChoice, prereqsMet,
        });
      }),
    );
  });
  list.sort((a, b) => b.priority - a.priority);
  // '=' 짝 문항은 우선순위가 높은 쪽 하나만 남긴다
  const seen = new Set();
  const out = [];
  list.forEach((g) => {
    if (seen.has(g.id)) return;
    const eq = getEquivalentItems(stageKey, g.id);
    eq.forEach((e) => seen.add(e));
    seen.add(g.id);
    out.push(eq.length ? { ...g, sameAs: eq } : g);
  });
  return out;
}

// ── IEP·보고서 문장용 목표 묶음 ───────────────────────────────────
//   아동 목표는 선생님이 고른 주간 우선순위 문항을 먼저, 없으면 추천 상위 문항을 쓴다
//   교류 지원은 파트너 문항(IS/LS) 중 점수가 낮은 것
const SC_KEYS = ['joinAttention', 'symbolUse'];
const ER_KEYS = ['mutualReg', 'selfReg'];
const TS_KEYS_ALL = ['interpersonalSupport', 'learningSupport'];
// 교류 지원 문항을 영역에 나눠 연결 (책 2권 4장: 교류 지원은 사회 의사소통·정서 조절 목표를 돕는 수단)
//   사회 의사소통 ← IS2 시작행동 촉진, IS5 발달 지원, IS6 언어 조절, IS7 시범, LS2.1·LS2.2 보완의사소통
//   정서 조절 ← IS1 반응성, IS3 독립성 존중, LS2.3·LS2.4 정서 지원, LS3 시각/조직화, LS4 수정
const TS_FOR_SC = /^(IS2|IS5|IS6|IS7)\.|^LS2\.[12]$|^LS1\.2$/;
const TS_FOR_ER = /^(IS1|IS3)\.|^LS2\.[34]$|^LS3\.|^LS4\./;
function itemLookup(stageKey) {
  const m = {};
  Object.entries(STAGE_DATA[stageKey] || {}).forEach(([dkey, domain]) => domain.groups.forEach((g) => g.items.forEach((it) => {
    m[it.id] = { id: it.id, label: it.label, domainKey: dkey, groupTitle: (g.title || '').replace(/^\d+\.\s*/, '').replace(/[.。]\s*$/, '') };
  })));
  return m;
}
// ★ 책 2권 4장 「목표 간 연계」(162~287쪽)의 연결표: 아동 장기목표 → 관련된 파트너 교류 지원 교수목표
//   (책이 표로 제시한 장기목표만 있음. 없는 장기목표는 영역별 묶음으로 고른다)
const TS_LINKS = {
  social: {
    JA1: ['IS1.1', 'IS1.6', 'IS2.1', 'IS2.2', 'LS1.2', 'LS1.3', 'LS4.5'],
    JA3: ['IS1.2', 'IS2.2', 'IS6.1', 'IS7.1', 'LS2.3', 'LS4.6'],
    JA4: ['IS1.3', 'IS2.1', 'IS3.4', 'IS7.2', 'LS2.1', 'LS4.5'],
    JA5: ['IS1.6', 'IS2.3', 'IS7.2', 'LS1.2', 'LS2.1', 'LS4.5'],
    JA6: ['IS1.6', 'IS2.2', 'IS4.3', 'IS7.2', 'LS1.5', 'LS4.5', 'LS4.7'],
    SU3: ['IS5.1', 'IS5.5', 'IS7.3', 'LS1.3', 'LS1.4', 'LS4.6'],
    SU4: ['IS5.5', 'IS7.1', 'IS7.4', 'LS2.1', 'LS4.5', 'LS4.10'],
    SU5: ['IS1.3', 'IS1.6', 'IS5.1', 'LS1.2', 'LS1.4'],
    SU6: ['IS4.2', 'IS6.1', 'IS6.2', 'LS2.2', 'LS3.6'],
    MR1: ['IS4.3', 'IS5.5', 'IS7.1', 'LS1.5', 'LS2.3', 'LS4.4'],
    MR3: ['IS1.3', 'IS2.2', 'IS5.5', 'IS7.1', 'LS1.4', 'LS2.1', 'LS2.3', 'LS4.10'],
    MR4: ['IS1.5', 'IS3.4', 'IS7.1', 'LS2.3', 'LS3.6', 'LS4.3'],
    SR1: ['IS1.3', 'IS1.5', 'IS4.2', 'LS1.1', 'LS1.4', 'LS3.3'],
    SR3: ['IS1.7', 'IS2.4', 'IS4.4', 'LS1.5', 'LS2.4', 'LS3.4'],
    SR4: ['IS1.4', 'IS3.4', 'IS7.1', 'LS2.3', 'LS3.6', 'LS4.3'],
  },
  language: {
    JA1: ['IS1.3', 'IS2.2', 'IS2.3', 'LS1.2', 'LS4.5', 'LS4.8'],
    JA3: ['IS1.2', 'IS2.2', 'IS6.1', 'IS7.1', 'LS2.3', 'LS4.1'],
    JA4: ['IS1.3', 'IS2.1', 'IS2.4', 'IS3.4', 'IS7.2', 'LS2.1', 'LS4.5'],
    JA5: ['IS1.3', 'IS2.3', 'IS7.2', 'LS1.2', 'LS3.6', 'LS4.5'],
    JA6: ['IS1.1', 'IS2.2', 'IS4.3', 'IS7.2', 'LS1.5', 'LS2.1', 'LS4.7'],
    JA8: ['IS1.3', 'IS2.2', 'IS2.3', 'LS1.2', 'LS2.1', 'LS3.6', 'LS4.8'],
    SU1: ['IS1.6', 'IS2.3', 'IS4.3', 'IS5.1', 'LS1.4', 'LS3.1', 'LS4.6'],
    SU3: ['IS5.1', 'IS7.3', 'LS1.3', 'LS2.2', 'LS4.6'],
    SU5: ['IS1.3', 'IS6.2', 'IS7.5', 'LS2.1', 'LS4.5', 'LS4.10'],
    SU6: ['IS4.2', 'IS6.1', 'IS6.2', 'LS1.4', 'LS2.2', 'LS4.6'],
    MR1: ['IS1.2', 'IS2.2', 'IS5.5', 'IS7.1', 'LS1.5', 'LS2.3', 'LS4.4'],
    MR3: ['IS2.2', 'IS4.3', 'IS7.1', 'IS7.5', 'LS1.4', 'LS2.3', 'LS2.4', 'LS4.5'],
    MR4: ['IS1.5', 'IS3.4', 'IS6.3', 'IS7.1', 'LS2.2', 'LS2.3', 'LS4.3'],
    SR1: ['IS1.2', 'IS4.4', 'IS5.5', 'LS1.3', 'LS1.4', 'LS2.2', 'LS4.6'],
    SR3: ['IS3.3', 'IS6.3', 'IS7.1', 'LS1.4', 'LS2.3', 'LS4.1'],
    SR4: ['IS4.3', 'IS5.4', 'IS7.5', 'LS3.3', 'LS4.4', 'LS4.9'],
    SR5: ['IS1.5', 'IS1.7', 'IS3.1', 'IS7.5', 'LS2.4', 'LS3.6', 'LS4.3'],
  },
  conversation: {
    JA1: ['IS4.2', 'IS4.4', 'LS2.2', 'LS4.4'],
    JA3: ['IS1.3', 'IS2.3', 'IS7.2', 'LS2.1', 'LS4.8'],
    JA4: ['IS1.3', 'IS2.3', 'IS5.1', 'IS7.2', 'LS1.2', 'LS2.1', 'LS3.6', 'LS4.1'],
    JA5: ['IS4.4', 'IS5.2', 'IS5.5', 'LS3.6', 'LS4.1'],
    SU1: ['IS5.3', 'IS7.4', 'IS7.5', 'LS1.3', 'LS2.2', 'LS3.6', 'LS4.1'],
    SU2: ['IS4.3', 'IS4.4', 'IS7.1', 'LS1.5', 'LS2.2', 'LS4.6'],
    SU5: ['IS6.2', 'IS7.5', 'LS2.1', 'LS4.2'],
    SU6: ['IS5.3', 'IS7.2', 'IS7.4', 'LS2.1', 'LS3.6', 'LS4.8'],
    MR1: ['IS4.4', 'IS5.2', 'IS7.1', 'LS1.5', 'LS2.3', 'LS2.4'],
    MR3: ['IS1.6', 'IS5.1', 'IS5.4', 'IS5.5', 'LS2.2', 'LS4.4', 'LS4.10'],
    MR4: ['IS2.2', 'IS3.3', 'IS7.2', 'LS2.1', 'LS2.3', 'LS4.5'],
    MR5: ['IS1.5', 'IS3.4', 'IS6.3', 'IS7.1', 'LS2.2', 'LS2.3', 'LS4.3'],
    SR1: ['IS4.2', 'IS5.1', 'IS7.1', 'LS1.5', 'LS3.2', 'LS4.6'],
    SR3: ['IS1.3', 'IS5.3', 'IS7.5', 'LS1.3', 'LS2.3', 'LS4.10'],
    SR4: ['IS1.6', 'IS4.4', 'IS5.4', 'IS7.5', 'LS1.1', 'LS2.4', 'LS3.2'],
    SR6: ['IS1.2', 'IS1.4', 'IS3.4', 'IS7.5', 'LS2.4', 'LS3.6', 'LS4.3'],
  },
};
function buildGoalPlan(stageKey, scores, familyPriorities, iep) {
  const rec = computeRecommendedGoals(stageKey, scores, familyPriorities);
  const lookup = itemLookup(stageKey);
  const sc = scores || {};
  const pick = (keys, n) => {
    const chosen = (iep?.selectedGoals || [])
      .map((g) => lookup[g.id] ? { ...lookup[g.id], label: (g.customGoal || '').trim() || lookup[g.id].label, score: sc[g.id], custom: g.customGoal } : null)
      .filter((g) => g && keys.includes(g.domainKey));
    if (chosen.length > 0) return chosen.slice(0, 8);   // ★ 선생님이 고른 목표는 모두 (책: 사회 의사소통+정서 조절 4~8개, 1권 266쪽)
    return rec.filter((g) => keys.includes(g.domainKey)).slice(0, n);
  };
  // 파트너 목표: 선생님이 고른 파트너 목표 → 없으면 점수 낮은 IS/LS
  // ★ 파트너 목표는 칩(번호 있음), "[IS1.2] 글자", 직접 쓴 글자 세 가지가 섞여 있다 → 모두 목표로 쓴다
  const partnerChosen = (iep?.partnerGoals || []).map((p) => {
    if (p && typeof p === 'object' && p.id) return lookup[p.id] ? { ...lookup[p.id], score: sc[p.id] } : { id: p.id, label: (p.customGoal || p.label || '').trim(), groupTitle: '' };
    const t = typeof p === 'string' ? p.trim() : '';
    if (!t) return null;
    const m = t.match(/^\[([A-Z]{2}\d+\.\d+)\]\s*(.*)$/);
    if (m && lookup[m[1]]) return { ...lookup[m[1]], score: sc[m[1]] };
    return { id: m ? m[1] : '', label: m ? m[2] : t, groupTitle: '' };
  }).filter((g) => g && (g.id || g.label));
  const tsLow = rec.filter((g) => TS_KEYS_ALL.includes(g.domainKey));
  const scGoals = pick(SC_KEYS, 2);
  const erGoals = pick(ER_KEYS, 2);
  // 아동 목표의 장기목표(JA5.1 → JA5)에 책 연결표가 있으면 그 교류 지원을, 없으면 영역 묶음에서 점수 낮은 것을
  //   아직 일관되지 않은(0·1점 또는 미채점) 지원을 앞에 둔다
  const supportsFor = (goals, re) => {
    const links = TS_LINKS[stageKey] || {};
    const ids = [];
    goals.forEach((g) => (links[g.id.replace(/\.\d+$/, '')] || []).forEach((id) => { if (lookup[id] && !ids.includes(id)) ids.push(id); }));
    if (ids.length === 0) return tsLow.filter((g) => re.test(g.id)).slice(0, 3);
    const rank = (id) => (sc[id] === 0 ? 0 : sc[id] === 1 ? 1 : typeof sc[id] !== 'number' ? 2 : 3);
    return ids.map((id) => ({ ...lookup[id], score: sc[id] })).sort((a, b) => rank(a.id) - rank(b.id)).slice(0, 3);
  };
  const scSupports = supportsFor(scGoals, TS_FOR_SC);
  const erSupports = supportsFor(erGoals, TS_FOR_ER);
  // 파트너 단기목표: 선생님이 고른 것 → 없으면 연결된 지원 중 0·1점인 것 → 없으면 점수 낮은 교류 지원
  // ★ 책 1권 266쪽: 교류 지원 주간 목표 4~8개, 아동 목표마다 그 행동을 돕는 교류 지원이 최소 1개
  //   ① 아동 목표마다 연결표에서 아직 일관되지 않은(0·1점) 지원 1개 → ② 연결된 다른 0·1점 지원 → ③ 점수 낮은 교류 지원으로 4개까지
  const isLow = (id) => sc[id] === 0 || sc[id] === 1;
  const lowRank = (id) => (sc[id] === 0 ? 0 : 1);
  const linksOf = (g) => ((TS_LINKS[stageKey] || {})[g.id.replace(/\.\d+$/, '')] || []).filter((id) => lookup[id] && isLow(id)).sort((a, b) => lowRank(a) - lowRank(b));
  const tsIds = [];
  const add = (id) => { if (id && !tsIds.includes(id) && tsIds.length < 8) tsIds.push(id); };
  [...scGoals, ...erGoals].forEach((g) => { const l = linksOf(g); if (!l.some((id) => tsIds.includes(id))) add(l[0]); });
  [...scGoals, ...erGoals].forEach((g) => linksOf(g).forEach((id) => { if (tsIds.length < 4) add(id); }));
  [...scSupports, ...erSupports].forEach((g) => { if (tsIds.length < 4 && isLow(g.id)) add(g.id); });
  tsLow.forEach((g) => { if (tsIds.length < 4) add(g.id); });
  const ts = partnerChosen.length ? partnerChosen.slice(0, 8) : tsIds.map((id) => ({ ...lookup[id], score: sc[id] }));
  // 이미 잘 되는 교류 지원(2점) — 종결 권고에서 '다음 파트너에게 전할 지원'
  const tsStrong = Object.entries(sc).filter(([id, v]) => v === 2 && lookup[id] && TS_KEYS_ALL.includes(lookup[id].domainKey))
    .map(([id]) => lookup[id]).slice(0, 3);
  return { sc: scGoals, er: erGoals, ts, scSupports, erSupports, tsStrong, lookup };
}
// "SU5.1 「소리/단어를 …」" 형태
const goalRef = (g) => (g.id ? `${g.id} 「${g.label}」` : `「${g.label}」`);
const uniqTitles = (arr) => [...new Set(arr.map((g) => g.groupTitle).filter(Boolean))];


// ── (예전) IEP 목표 우선순위 가중치 — 지금 추천 순서는 computeRecommendedGoals의 책 기준(가족 우선 → 1점 → 0점 → 앞 장기목표)을 쓰고,
//    아래 가중치는 쓰지 않는다. 다른 화면 호환을 위해 남겨 둠 ────────────────────────────
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
  // ★ 책 기준(1권 265쪽): 5개 미만의 칸 = 상대적 요구, 5개 이상의 칸 = 상대적 강점
  ranges: [
    { min: 0, max: 4, label: '상대적 요구', color: '#b54a3a',
      meaning: '10칸 중 5칸 미만으로, 상대적 요구에 해당합니다.' },
    { min: 5, max: 10, label: '상대적 강점', color: '#2d4a3e',
      meaning: '10칸 중 5칸 이상으로, 상대적 강점에 해당합니다.' },
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
        { id: 'lp_sc_1', type: 'text', q: '다른 사람과 어떻게 상호작용하는지 기술하시오. 예를 들어, 다른 사람의 상호작용 시도에 반응하는가? 상호작용을 시작하는가? 두세 번 정도 차례를 주고받는가? 파트너와 관심을 공유하면서 여러 번 차례를 주고받는가?' },
        { id: 'lp_sc_2', type: 'text', q: '상호작용을 하는 동안 시선을 어떻게 사용하는지 기술하시오. 예를 들어, 사람을 전혀 또는 거의 쳐다보지 않는가, 아니면 자주 쳐다보는가? 놀잇감을 가지고 놀 때 당신이 지켜보는지를 살피기 위해 고개를 들어 쳐다본 다음 다시 물건을 향해 시선을 옮기는가?' },
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
            '행위 단어(예: "먹는다" "달린다" "간다")',
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
        { id: 'lp_sc_8', type: 'text', q: '아동이 가장 좋아하는 놀잇감은 무엇인가? 그것을 가지고 어떻게 놀이하는가?' },
        { id: 'lp_sc_9', type: 'text', q: '친숙한 성인이 놀이에 끼어들면 아동은 어떻게 반응하는가? 친숙한 또래나 형제가 끼어들면 어떻게 반응하는가?' },
        {
          id: 'lp_sc_imit', type: 'frequency',
          q: '다른 사람이 시범을 보인 행동이나 소리에 대해 어떻게 반응하는가?',
          partners: ['익숙한 행동이나 소리를 모방하는가?', '새로운 행동이나 소리를 모방하는가?', '새로운 상황에서 행동을 모방하는가?'],
        },
        {
          id: 'lp_sc_10', type: 'checklist',
          q: '다음의 교수나 단서 중 아동이 이해하는 것에 모두 표시하시오.',
          options: [
            '가리키기 외의 몸짓', '가리키기', '사진이나 그림', '글자',
            '얼굴 표정', '억양', '아동의 이름',
          ],
          withText: [
            { id: 'familiar', label: '익숙한 상황에서의 단어 또는 구(예를 적으시오)' },
            { id: 'noun', label: '상황 단서가 없을 때 사람이나 물건의 이름(예를 적으시오)' },
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
        { id: 'lp_er_1', type: 'text', q: '아동은 자신의 환경 내에 있는 사람과 사물에 대해 어떻게 반응하는가? 예를 들어, 다양한 상황에 흥미를 보이는지, 몇 가지에 대해서만 강한 흥미를 보이는지, 다양한 감정을 나타내는지, 혼자 지내는지, 상호작용을 위한 시도에 반응하거나 상호작용을 하기 위해 노력하는지 등을 기술하시오.' },
        { id: 'lp_er_2', type: 'text', q: '가장 재미있어 하거나 흥미를 보이는 활동 또는 상황은 무엇인가?' },
        { id: 'lp_er_3', type: 'text', q: '가장 힘들어하거나 지루해하는 활동 또는 상황은 무엇인가?' },
        { id: 'lp_er_4', type: 'text', q: '친숙한 활동을 하는 동안 집중과 흥미를 유지하기 위해서 또는 진정하거나 활동에 참여하기 위해서 전략을 사용하는가(예: 양손을 꽉 쥐기, 담요 문지르기, 몸 흔들기, "끝나면 밖에 나가요?"라고 말하기)? 만일 그렇다면, 그 전략을 구체적으로 기술하시오.' },
        { id: 'lp_er_5', type: 'text', q: '새롭고 변화된 상황이나 그 밖의 도전적인 상황에서 집중과 흥미를 유지하기 위해서 또는 진정하거나 활동에 참여하기 위해서 전략을 사용하는가(예: 활동이 바뀔 때 친숙한 노래 부르기, 두려움을 느낄 때 "걱정하지 마"라고 말하기)? 만일 그렇다면, 그 전략을 구체적으로 기술하시오.' },
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
        { id: 'lp_er_11', type: 'text', q: '아동이 지루해하거나 흥미가 없다는 것을 어떻게 알 수 있는가? 아동은 어떤 신호를 보이는가?' },
        {
          id: 'lp_er_12', type: 'recoveryPair',
          q: '아동은 매우 심하게 화가 나거나 괴로울 때',
          self: '어떻게 스스로 회복하는가? 보통 회복되기까지 얼마나 오래 걸리는가?',
          partner: '파트너가 어떻게 도와줄 때 회복되는가? 보통 회복되기까지 얼마나 오래 걸리는가?',
        },
      ],
    },
    {
      key: 'ts',
      title: '교류 지원',
      questions: [
        { id: 'lp_ts_1', type: 'text', q: '아동이 정기적으로(매일 또는 매주) 상호작용을 하거나 일상적으로 만나는 사람은 누구인가?' },
        { id: 'lp_ts_2', type: 'text', q: '아동이 정기적으로(매일 또는 매주) 가는 장소는 어디인가?' },
        {
          id: 'lp_ts_3', type: 'scale02List',
          q: '다음 중 쉽게 파악하거나 따르거나 반응할 수 있는 것은 모두 다음의 숫자로 표시하시오: 거의 또는 전혀 파악할 수 없거나 반응할 수 없다면 0, 가끔씩 파악하거나 반응할 수 있다면 1, 대부분의 경우 파악하거나 반응할 수 있다면 2.',
          items: [
            '아동이 관심을 갖는 대상', '아동이 의사소통하려고 하는 것',
            '아동의 감정 상태', '아동이 선호하는 속도(빠름 또는 느림)',
            '아동에게 휴식이 필요할 때', '아동이 흥미를 보이는지 여부',
            '아동이 좌절했는지 여부', '아동이 흥분했는지 여부',
          ],
        },
        { id: 'lp_ts_4', type: 'text', q: '아동이 의사소통을 시작하도록 격려하는 데에 가장 도움이 되는 전략은 무엇인가(예: 선택할 기회 제공하기, 아동을 기다리며 쳐다보기, 내 차례가 지난 후 기다리기)?' },
        { id: 'lp_ts_5', type: 'text', q: '아동이 때리거나 소리를 지르거나 깨무는 등 문제행동을 보일 때 당신은 보통 어떻게 반응하는가? 그러한 반응이 효과적인가?' },
        { id: 'lp_ts_6', type: 'text', q: '아동의 주의를 끄는 데에 가장 도움이 되는 전략은 무엇인가(예: 아동의 수준에 맞추기, 아동에게 가까이 다가가거나 멀리 떨어지기, 아동의 감정에 맞추기, 아동을 기다리고 따르기)?' },
        { id: 'lp_ts_7', type: 'text', q: '아동과의 상호작용을 유지하는 데에 가장 도움이 되는 전략은 무엇인가(예: 아동이 상호작용을 시작하게 하기, 아동이 휴식을 취한 후 계속하게 하기, 아동의 흥미를 따르기)?' },
        { id: 'lp_ts_8', type: 'text', q: '아동에게 전달한 메시지를 이해했는지 확인하기 위해서 아동에게 주로 어떻게 의사소통을 하는가?' },
        { id: 'lp_ts_9', type: 'text', q: '아동이 의사소통을 하고, 언어를 이해하고, 감정을 표현하고, 순조로운 일과를 진행하도록 도와주기 위해서 시각적 지원을 사용하는가? 만일 그렇다면, 어떤 지원을 사용하는가(예: 그림으로 과제의 단계 보여 주기, 전이용 사물, 선택용 그림, 수어)?' },
        { id: 'lp_ts_10', type: 'text', q: '아동이 참여를 유지하는 데 도움이 되는 물리적 또는 사회적 환경 특성은 무엇인가(예: 아동이 상호작용하는 사람의 수 제한하기, 배경 소음 또는 시각적인 혼잡함 줄이기, 움직임이나 리듬을 위한 기회 더 많이 주기, 특정 활동을 위해 특정 장소를 일관성 있게 사용하기)?' },
        { id: 'lp_ts_11', type: 'text', q: '아동이 의사소통을 더 잘 하도록 돕는 물리적 또는 사회적 환경 특성은 무엇인가(예: 아동이 좋아해서 동기를 유발할 수 있는 놀잇감이나 활동 이용하기, 좋아할 만한 또는 좋아하는 물건을 조금 멀리 두기)?' },
      ],
    },
    // ★ 추가 의견 — 언어 파트너 질문지(1권 438쪽)는 4번이 '아동에 대해 알아야 할…'('우리가' 없음)
    { ...SP_INTERVIEW.sections[3], questions: SP_INTERVIEW.sections[3].questions.map((q) => ({ ...q, id: q.id.replace('sp_', 'lp_'), q: q.q.replace('아동에 대해 우리가 알아야 할', '아동에 대해 알아야 할') })) },
  ],
};

// =====================================================================
// 대화 파트너 단계 질문지
// =====================================================================
const CP_INTERVIEW = {
  stage: 'conversation',
  intro: SP_INTERVIEW.intro,
  meta: SP_INTERVIEW.meta,
  // ★ 1권 부록 대화 파트너 SCERTS 진단-질문지(456~462쪽) 그대로.
  //   예전 질문지와 뜻이 달라진 질문은 새 번호(cpb_)를 쓰고, 예전 답은 RETIRED_INTERVIEW_QUESTIONS로 계속 보여 준다
  sections: [
    {
      key: 'social',
      title: '사회 의사소통',
      questions: [
        { id: 'cp_sc_1', type: 'text', q: '다른 사람과 어떻게 상호작용하는지 기술하시오. 예를 들어, 파트너가 하고 있는 일을 주시하는가? 말하기 전에 상대방의 주의를 끌기 위한 행동을 하는가? 파트너와 관심을 공유하면서 여러 번 차례를 주고받는가?' },
        {
          id: 'cpb_sc_2', type: 'checklist',
          q: '아동이 대화 중 의사소통을 하는 이유는 무엇인가? 다음 중 해당되는 것에 표시하고 예를 적으시오.',
          options: [
            '원하는 물건을 요구하거나 도움 청하기', '휴식 요구하기', '원하지 않는 활동을 거절/거부하기',
            '인사하기', '허락 구하기', '공감 표현하기',
            '현재와 과거의 사건에 대해 이야기하기', '현재와 과거의 사건에 대해 정보 요구하기',
            '감정과 의견 표현하기', '앞으로의 계획을 세우고 일어날 일에 대해 의논하기',
          ],
        },
        { id: 'cpb_sc_3', type: 'text', q: '아동의 요구를 알아채지 못할 때 어떤 일이 발생하는가? 아동은 어떻게 행동하는가?' },
        {
          id: 'cpb_sc_4', type: 'checklist',
          q: '다음 중 아동이 문장에서 일상적으로 사용하는 단어 형태에 해당하는 것을 모두 표시하고 구체적인 예를 적으시오.',
          options: [
            '의문사(예: 무엇, 어디, 누구)',
            '시간을 나타내는 단어(예: 전에, 지금, 나중에, 언제)',
            '크기나 수를 나타내는 단어(예: 작은, 많이)',
            '장소를 나타내는 단어(예: 옆에, 사이에, 아래에)',
            '대명사(예: 나/너, 그/그녀, 우리/그들)',
            '동사(예: 과거형, 현재형, 미래형 시제[먹었다, 달렸다, 갈 거야])',
            '등위접속사(예: 그리고, 또는)',
            '종속접속사(예: 그러나, 그래서, 왜냐하면, 만일)',
          ],
        },
        {
          id: 'cpb_sc_5', type: 'checklist',
          q: '다음 중 아동이 일상적으로 따르는 대화의 \'규칙\'에 해당하는 것을 모두 표시하고 예를 적으시오.',
          options: [
            '다양한 주제로 대화를 시작한다', '자주 주제를 시작한다',
            '다른 사람에게 관심 있는 것에 대해 이야기한다',
            '청자와 화자로서 적절히 차례를 지키며 대화한다',
            '다른 사람이 알고 있는 것에 따라 필요한 정보를 제공한다',
            '관련된 정보를 요구한다',
            '상대방의 행동에 따라 자기 차례의 길이를 조절한다',
            '자연스럽게 주제를 바꾼다', '정중하게 대화를 끝낸다',
          ],
        },
        {
          id: 'cpb_sc_6', type: 'checklist',
          q: '다음 중 아동이 대화를 하는 동안 적절하게 사용하는 비구어 행동에 해당하는 것을 모두 표시하시오.',
          options: [
            '얼굴 표정', '몸짓', '자세',
            '상대방과의 근접성이나 물리적 거리', '목소리의 성량 또는 세기', '억양 또는 운율',
          ],
        },
        { id: 'cpb_sc_7', type: 'text', q: '가장 좋아하는 놀잇감, 게임, 놀이 활동은 무엇인가? 어떻게 놀이를 하고 즐기는가?' },
        { id: 'cpb_sc_8', type: 'text', q: '가장 좋아하는 친구는 누구인가? 그 친구와 함께 하기를 원하거나 이야기하고 싶어 하는 것은 무엇인가?' },
        {
          id: 'cpb_sc_9', type: 'frequency',
          q: '집단 상황에서 어떻게 학습하는가?',
          partners: ['새로운 상황에서 행동을 모방하는가?', '성인이 시범을 보이면 규칙을 학습하는가?', '또래와 협력하거나 협상하는가?'],
        },
        {
          id: 'cpb_sc_10', type: 'checklist',
          q: '다음 중 일관성 있게 이해하는 의미나 비구어 단서에 모두 표시하시오.',
          options: [
            '차례를 바꾸기 위한 비구어 단서', '감정에 대한 비구어 단서', '유머',
            '비유적인 표현', '놀리기', '비꼬는 말', '속이는 말',
          ],
        },
      ],
    },
    {
      key: 'emo',
      title: '정서 조절',
      questions: [
        { id: 'cp_er_1', type: 'text', q: '아동은 자신의 환경 내에 있는 사람과 사물에 대해 어떻게 반응하는가? 예를 들어, 다양한 상황에 흥미를 보이는지, 몇 가지에 대해서만 강한 흥미를 보이는지, 다양한 감정을 나타내는지, 혼자 지내는지, 상호작용을 위한 시도에 반응하거나 상호작용을 하기 위해 노력하는지, 활동이나 행동을 억제하는지, 자신의 능력에 맞는 과제를 지속해서 수행하는지 등을 기술하시오.' },
        { id: 'cp_er_2', type: 'text', q: '가장 재미있어 하거나 흥미를 보이는 활동 또는 상황은 무엇인가?' },
        { id: 'cp_er_3', type: 'text', q: '가장 힘들어하거나 지루해하는 활동 또는 상황은 무엇인가?' },
        { id: 'cp_er_4', type: 'text', q: '친숙한 활동을 하는 동안 집중과 흥미를 유지하기 위해서 또는 진정하거나 활동에 참여하기 위해서 전략을 사용하는가(예: 천이나 다른 물건을 입에 넣거나 깨물기, 만지작거리기, 몸 흔들기, 일과 순서를 반복적으로 말하기, 과제 진행을 점검하기 위해 체크리스트 활용하기)? 만일 그렇다면, 그 전략을 구체적으로 기술하시오.' },
        { id: 'cp_er_5', type: 'text', q: '새롭고 변화된 상황이나 그 밖의 도전적인 상황에서 집중과 흥미를 유지하기 위해서 또는 진정하거나 활동에 참여하기 위해서 전략을 사용하는가(예: "다 썼어"라고 말한 후 다음에 무엇을 해야 하는지 보기 위해 시간표 확인하기, 기다려야 하는 상황에서 스트레스를 낮추기 위해 감정을 표현하거나 정보를 요구하기)? 만일 그렇다면, 그 전략을 구체적으로 기술하시오.' },
        {
          id: 'cpb_er_6',
          type: 'emotionPairs',
          q: '구어 또는 비구어 수단으로 긍정적인 감정과 부정적인 감정을 표현하는가? 만일 그렇다면, 어떻게 표현하는가?',
          pairs: [
            ['기쁨', '슬픔'],
            ['만족감', '분노 또는 좌절'],
            ['익살스러움', '두려움'],
            ['흥분', '질병 또는 피로'],
            ['흥미', '불안, 스트레스 또는 걱정'],
            ['자랑스러움', '지루함'],
            ['희망', '난처함'],
          ],
        },
        { id: 'cpb_er_7', type: 'text', q: '다른 사람이 정서 조절과 관련해서 제공하는 피드백과 안내에 반응하는가? 만일 그렇다면, 어떻게 반응하는가?' },
        { id: 'cp_er_9', type: 'text', q: '아동이 집중하고, 흥미를 갖고, 진정하고, 참여를 유지하도록 돕기 위해 어떤 전략을 사용하는가?' },
        { id: 'cp_er_10', type: 'text', q: '아동이 흥분하거나 화가 났다는 것을 어떻게 알 수 있는가? 아동은 어떤 신호를 보이는가?' },
        { id: 'cpb_er_10', type: 'text', q: '아동이 지루해하거나 흥미가 없다는 것을 어떻게 알 수 있는가? 아동은 어떤 신호를 보이는가?' },
        {
          id: 'cp_er_12', type: 'recoveryPair',
          q: '아동은 매우 심하게 화가 나거나 괴로울 때',
          self: '어떻게 스스로 회복하는가? 보통 회복되기까지 얼마나 오래 걸리는가?',
          partner: '파트너가 어떻게 도와 줄 때 회복되는가? 보통 회복되기까지 얼마나 오래 걸리는가?',
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
          id: 'cpb_ts_3', type: 'scale02List',
          q: '다음 중 쉽게 파악하거나 따르거나 반응할 수 있는 것은 모두 다음의 숫자로 표시하시오: 거의 또는 전혀 파악할 수 없거나 반응할 수 없다면 0, 가끔씩 파악하거나 반응할 수 있다면 1, 대부분의 경우 파악하거나 반응할 수 있다면 2.',
          items: [
            '아동이 관심을 갖는 대상', '아동이 의사소통하려고 하는 것',
            '아동의 감정 상태', '아동이 선호하는 속도(빠름 또는 느림)',
            '아동에게 휴식이 필요할 때', '아동이 흥미를 보이는지 여부',
            '아동이 좌절했는지 여부', '아동이 흥분했는지 여부',
          ],
        },
        { id: 'cp_ts_4', type: 'text', q: '아동이 대화를 시작하고 대화 중에 주제를 유지할 수 있도록 격려하는 데에 가장 도움이 되는 전략은 무엇인가(예: 선택할 기회 제공하기, 대화를 시작하도록 기다리고 격려하기, 아동의 주제 따르기, 정보 요구하기)?' },
        { id: 'cp_ts_5', type: 'text', q: '아동이 스트레스가 매우 높은 상황에서 소리를 지르거나 달아나거나 쉴 새 없이 어떤 구절을 암송하는 등 문제행동을 보일 때 당신은 보통 어떻게 반응하는가? 그러한 반응이 효과적인가?' },
        { id: 'cp_ts_6', type: 'text', q: '아동의 주의를 끄는 데에 가장 도움이 되는 전략은 무엇인가(예: 아동에게 가까이 다가가거나 멀리 떨어지기, 아동의 이름 부르기, 대화 중에 아동에게 동기 부여가 될 만한 주제 삽입하기)?' },
        { id: 'cp_ts_7', type: 'text', q: '아동과의 상호작용을 유지하는 데에 가장 도움이 되는 전략은 무엇인가(예: 아동이 상호작용을 시작하게 하기, 아동이 휴식을 취한 후 계속하게 하기, 아동의 흥미를 따르기)?' },
        { id: 'cp_ts_8', type: 'text', q: '아동에게 전달한 메시지를 이해했는지 확인하기 위해서 아동에게 주로 어떻게 의사소통을 하는가?' },
        { id: 'cp_ts_9', type: 'text', q: '아동이 의사소통을 하고, 언어를 이해하고, 감정을 표현하고, 순조로운 일과를 진행하도록 도와주기 위해서 시각적 지원을 사용하는가? 만일 그렇다면, 어떤 지원을 사용하는가(예: 언어와 문자 단서를 함께 사용하기, 그림, 문자, 시간표, 달력 등을 이용하여 과제의 단계 보여 주기, 비디오 모델링 사용하기, 감정 일기 활용하기)?' },
        { id: 'cp_ts_10', type: 'text', q: '아동이 참여를 유지하는 데 도움이 되는 물리적 또는 사회적 환경 특성은 무엇인가(예: 아동이 상호작용하는 사람의 수 제한하기, 배경 소음 또는 시각적인 혼잡함 줄이기, 움직임이나 리듬을 위한 기회 더 많이 주기, 특정 활동을 위해 특정 장소를 일관성 있게 사용하기)?' },
        { id: 'cp_ts_11', type: 'text', q: '아동이 의사소통을 더 잘 하도록 돕는 물리적 또는 사회적 환경의 특성은 무엇인가(예: 집단 크기 줄이기, 아동이 좋아하는 주제나 활동으로 동기 부여하기, 사전에 사회적 활동 연습하기)?' },
      ],
    },
    // ★ 추가 의견 — 대화 파트너 질문지(1권 462쪽)는 4번이 '아동에 대해 알아야 할…'('우리가' 없음)
    { ...SP_INTERVIEW.sections[3], questions: SP_INTERVIEW.sections[3].questions.map((q) => ({ ...q, id: q.id.replace('sp_', 'cp_'), q: q.q.replace('아동에 대해 우리가 알아야 할', '아동에 대해 알아야 할') })) },
  ],
};

// ★ 질문지를 책대로 바꾸면서 없어진 예전 질문 (이미 받은 답을 지우지 않고 '예전 질문지에 받은 답'으로 보여 주기 위해 남겨 둠)
const RETIRED_INTERVIEW_QUESTIONS = {
  conversation: [
    { id: 'cp_sc_2', type: 'text', q: '상호작용 중 시선/얼굴표정/몸짓을 어떻게 사용하는지 기술하시오.', section: '사회 의사소통' },
    {
      id: 'cp_sc_3', type: 'checklist',
      q: '다음 중 아동이 일관성 있게 사용하는 의사소통 기능을 모두 표시하시오.',
      options: [
        '원하는 것 요구하기', '도움 청하기', '거절/거부하기',
        '인사하기', '허락 구하기', '경험 공유하기',
        '관심 끌기', '정보 요구하기', '정보 제공하기',
        '감정 표현하기', '의견 또는 생각 공유하기', '농담/유머 사용하기',
      ],
      section: '사회 의사소통',
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
      section: '사회 의사소통',
    },
    {
      id: 'cp_sc_5', type: 'frequency',
      q: '상호작용할 때 얼마나 자주 의사소통/대화를 시작하는가?',
      partners: ['친숙한 성인과 함께', '친숙한 또래와 함께', '친숙하지 않은 사람과 함께', '소집단 내에서', '대집단 내에서'],
      section: '사회 의사소통',
    },
    { id: 'cp_sc_6', type: 'text', q: '대화가 잘못되거나 의사소통이 실패할 때 아동은 어떻게 행동하는가? 명료화를 요구하는가?', section: '사회 의사소통' },
    { id: 'cp_sc_7', type: 'text', q: '관심 있는 주제나 대화 시 주제를 어떻게 유지하는가? 한 주제에 머무는 시간은 얼마나 되는가?', section: '사회 의사소통' },
    { id: 'cp_sc_8', type: 'text', q: '또래와의 우정 관계를 어떻게 맺고 유지하는가?', section: '사회 의사소통' },
    { id: 'cp_sc_9', type: 'text', q: '유머, 농담, 비유 표현, 놀림 등을 이해하고 사용하는가?', section: '사회 의사소통' },
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
      section: '사회 의사소통',
    },
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
      section: '정서 조절',
    },
    { id: 'cp_er_7', type: 'text', q: '단계적인 정서(예: 짜증→화남→격분)를 이해하거나 사용하는가?', section: '정서 조절' },
    { id: 'cp_er_8', type: 'text', q: '자신/타인의 정서에 대한 원인을 설명하거나 이해하는가?', section: '정서 조절' },
    { id: 'cp_er_11', type: 'text', q: '갈등이나 문제 해결 상황에서 어떻게 반응하는가? 타협하거나 협력할 수 있는가?', section: '정서 조절' },
    {
      id: 'cp_ts_3', type: 'scale02List',
      q: '다음 중 쉽게 파악하거나 따르거나 반응할 수 있는 것 (0/1/2)',
      items: [
        '아동이 관심을 갖는 대상', '아동이 의사소통하려고 하는 것',
        '아동의 감정 상태', '아동이 선호하는 속도',
        '아동에게 휴식이 필요할 때', '아동이 흥미를 보이는지 여부',
        '아동이 좌절/흥분했는지 여부', '아동의 내적 사고/정신적 계획',
      ],
      section: '교류 지원',
    },
    { id: 'cp_ts_12', type: 'text', q: '또래와의 상호작용/우정 관계를 지원하기 위해 사용하는 전략은?', section: '교류 지원' },
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
        // ★ 칸이 여러 개인 문항(감정별·회복·0/1/2)도 선생님 화면과 같은 모양으로 받기 위한 정보
        emotions: q.emotions || null,
        pairs: q.pairs || null,
        self: q.self || null,
        partner: q.partner || null,
        items: q.items || null,
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
      } else if (q.type === 'emotionsRows' || q.type === 'emotionPairs' || q.type === 'recoveryPair') {
        // 칸 여러 개 (감정별 / 스스로·파트너)
        var fields = [];
        if (q.type === 'emotionsRows') (q.emotions||[]).forEach(function(e){ fields.push([e, e]); });
        else if (q.type === 'emotionPairs') (q.pairs||[]).forEach(function(pr){ pr.forEach(function(e){ fields.push([e, e]); }); });
        else { fields.push(['self', '• ' + (q.self||'')]); fields.push(['partner', '• ' + (q.partner||'')]); }
        var prevObj = (ans[q.id] && typeof ans[q.id]==='object') ? ans[q.id] : {};
        var oldTxt = (typeof ans[q.id]==='string') ? ans[q.id] : (prevObj.__old || '');
        if (oldTxt && String(oldTxt).trim()) {
          var on=document.createElement('div'); on.style.cssText='font-size:12.5px;color:#6b5320;background:#fef7e6;border:1px dashed #c19a3a;border-radius:6px;padding:7px 10px;margin-bottom:8px;white-space:pre-wrap;';
          on.textContent='이전에 적어 주신 답: ' + oldTxt; box.appendChild(on);
        }
        fields.forEach(function(f){
          var lb=document.createElement('div'); lb.style.cssText='font-size:13.5px;font-weight:600;margin:6px 0 4px;'; lb.textContent=f[1]; box.appendChild(lb);
          var t=document.createElement('textarea'); t.dataset.qid=q.id; t.dataset.key=f[0]; t.placeholder='여기에 답변을 입력하세요';
          if (prevObj[f[0]]) t.value=prevObj[f[0]];
          box.appendChild(t);
        });
      } else if (q.type === 'scale02List') {
        // 항목별 0/1/2
        var prevS = (ans[q.id] && typeof ans[q.id]==='object') ? ans[q.id] : {};
        var oldS = (typeof ans[q.id]==='string') ? ans[q.id] : (prevS.__old || '');
        if (oldS && String(oldS).trim()) {
          var on2=document.createElement('div'); on2.style.cssText='font-size:12.5px;color:#6b5320;background:#fef7e6;border:1px dashed #c19a3a;border-radius:6px;padding:7px 10px;margin-bottom:8px;white-space:pre-wrap;';
          on2.textContent='이전에 적어 주신 답: ' + oldS; box.appendChild(on2);
        }
        var st=document.createElement('table'); st.className='freq';
        var sh='<tr><th></th><th>거의/전혀 (0)</th><th>가끔 (1)</th><th>대부분 (2)</th></tr>';
        var sb='';
        (q.items||[]).forEach(function(it, ri){
          sb+='<tr><td>'+escapeHtml(it)+'</td>';
          [0,1,2].forEach(function(n){
            var ck=(prevS[it]===n)?'checked':'';
            sb+='<td><input type="radio" name="'+q.id+'_s'+ri+'" data-qid="'+q.id+'" data-key="'+escapeHtml(it).replace(/"/g,'&quot;')+'" data-val="'+n+'" '+ck+'></td>';
          });
          sb+='</tr>';
        });
        st.innerHTML='<thead>'+sh+'</thead><tbody>'+sb+'</tbody>';
        box.appendChild(st);
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
    form.querySelectorAll('textarea[data-qid]:not([data-key])').forEach(function(ta){
      if (ta.value.trim()) out[ta.dataset.qid]=ta.value;
    });
    // 칸 여러 개 문항 → {칸이름: 답}
    form.querySelectorAll('textarea[data-key]').forEach(function(ta){
      if (ta.value.trim()){ var id=ta.dataset.qid; out[id]=out[id]||{}; out[id][ta.dataset.key]=ta.value; }
    });
    form.querySelectorAll('input[type=radio][data-key]:checked').forEach(function(r){
      var id=r.dataset.qid; out[id]=out[id]||{}; out[id][r.dataset.key]=parseInt(r.dataset.val,10);
    });
    // checklist
    form.querySelectorAll('input[type=checkbox][data-qid]').forEach(function(cb){
      if (cb.checked){ var id=cb.dataset.qid; out[id]=out[id]||{checked:{},texts:{}}; out[id].checked[cb.dataset.opt]=true; }
    });
    form.querySelectorAll('input.extra[data-qid]').forEach(function(ex){
      if (ex.value.trim()){ var id=ex.dataset.qid; out[id]=out[id]||{checked:{},texts:{}}; out[id].texts[ex.dataset.txt]=ex.value; }
    });
    // frequency
    form.querySelectorAll('input[type=radio][data-row]:checked').forEach(function(r){
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

// shared_store 읽기/쓰기
//   2026-11 보안: 보기 · 지우기는 로그인한 원장·선생님만 (로그인 열쇠로 접근)
//   부모님은 '보내기'만 — submit_external 전용 통로
const scertsShared = {
  async set(key, value) {
    try {
      const payload = typeof value === 'string' ? value : JSON.stringify(value);
      const r = await fetch(`${SUPABASE_URL}/rest/v1/rpc/submit_external`, {
        method: 'POST',
        headers: await authHeaders(),
        body: JSON.stringify({ p_key: SHARED_SKEY(key), p_value: payload }),
      });
      if (!r.ok) return null;
      return { value };
    } catch (e) { return null; }
  },
  async listByPrefix(prefix) {
    try {
      const like = encodeURIComponent(SHARED_SKEY(prefix) + '%');
      const url = `${SUPABASE_URL}/rest/v1/shared_store?key=like.${like}&select=key,value`;
      const r = await fetch(url, { headers: await authHeaders() });
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
      await fetch(url, { method: 'DELETE', headers: await authHeaders() });
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
  intro: '',
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
      note: '※ 총 관찰 시간: ••사회적 파트너-최소 2시간 ••언어 파트너-최소 2시간 ••대화 파트너-3∼4시간',
      type: 'datetime',
      fields: ['날짜/시간', '관찰 소요 시간'],
    },
    {
      id: 'team',
      label: '팀/파트너',
      note: '※ 최소 2개 이상의 집단 크기(일대일, 소집단, 대집단) ※ 언어 파트너 및 대화 파트너의 경우 친숙한 파트너와 친숙하지 않은 파트너 포함',
      type: 'text',
      fields: ['팀 구성원', '파트너 및 집단 크기'],
    },
    {
      id: 'activity',
      label: '활동/변인',
      note: '※ 최소 4개 변인에 따른 4개 활동 ※ 활동 변인의 주요 요소:',
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
      cols: ['목표', '유의점: 활동 중 보인 최상의 행동', '+ 표시 (시작·올바른 반응마다)'],
    },
    {
      title: '아동의 정서 조절 목표',
      type: 'goals',
      rows: 4,
      cols: ['목표', '유의점: 활동 중 보인 최상의 행동', '+ 표시 (시작·올바른 반응마다)'],
    },
    {
      title: '파트너의 교류 지원 목표',
      type: 'goals',
      rows: 6,
      cols: ['목표', '유의점: 파트너가 제공한 지원', '+ 표시 (제공할 때마다)'],
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

// ★ 이 기기 저장칸을 계정별로 나눔 — 한 컴퓨터를 여러 선생님이 써도 앞사람 자료가 섞이지 않게
let _lsUser = '';
const lsKey = (base) => (_lsUser ? `${base}::${_lsUser}` : base);
// 예전 공용 칸 → 지금 계정 칸으로 복사 (계정 칸이 비어 있을 때 한 번만)
function migrateSharedLocal() {
  try {
    // 계정마다 한 번만 (매번 하면 지운 템플릿이 되살아남)
    const doneKey = lsKey('scerts_shared_migrated');
    if (localStorage.getItem(doneKey)) return;
    [LS_STATE, LS_ARCHIVE, LS_BACKUPS].forEach((base) => {
      if (localStorage.getItem(lsKey(base)) == null) {
        const old = localStorage.getItem(base);
        if (old != null) localStorage.setItem(lsKey(base), old);
      }
    });
    // 템플릿은 계정 칸에 이미 뭔가 있어도(먼저 서버와 맞춘 경우) 예전 것을 합쳐 넣는다
    const oldT = JSON.parse(localStorage.getItem(LS_TEMPLATES) || '[]');
    if (Array.isArray(oldT) && oldT.length > 0) {
      const curT = JSON.parse(localStorage.getItem(lsKey(LS_TEMPLATES)) || '[]');
      const byId = new Map();
      [...(Array.isArray(curT) ? curT : []), ...oldT].forEach((t) => { if (t && t.id && !byId.has(t.id)) byId.set(t.id, t); });
      localStorage.setItem(lsKey(LS_TEMPLATES), JSON.stringify([...byId.values()]));
    }
    localStorage.setItem(doneKey, '1');
  } catch (e) {}
}

// 회기 템플릿 로드/저장
function loadTemplates() {
  try {
    const raw = localStorage.getItem(lsKey(LS_TEMPLATES));
    return raw ? JSON.parse(raw) : [];
  } catch (e) { return []; }
}
function saveTemplates(list) {
  try {
    localStorage.setItem(lsKey(LS_TEMPLATES), JSON.stringify(list));
  } catch (e) {}
  // ★ 서버에도 저장 → 다른 기기(아이폰·컴퓨터)에서도 같은 템플릿이 보이게
  try { if (window.storage) window.storage.set('gd-aba-templates', JSON.stringify(list)).catch(() => {}); } catch (e) {}
}
// 지운 템플릿 기록 (기기 사이에 합칠 때 되살아나지 않게)
function loadDeletedTemplateIds() {
  try { const v = JSON.parse(localStorage.getItem(lsKey(LS_TEMPLATES + '_deleted')) || '[]'); return Array.isArray(v) ? v : []; } catch (e) { return []; }
}
function saveDeletedTemplateIds(ids) {
  try { localStorage.setItem(lsKey(LS_TEMPLATES + '_deleted'), JSON.stringify(ids)); } catch (e) {}
  try { if (window.storage) window.storage.set('gd-aba-templates-deleted', JSON.stringify(ids)).catch(() => {}); } catch (e) {}
}
async function markTemplateDeleted(id) {
  // 서버에 있는 '지운 목록'과 합친 뒤 저장 (다른 기기에서 지운 기록을 덮어쓰지 않게). 최근 500개까지만 보관
  let server = [];
  try {
    if (window.storage) {
      const r = await window.storage.get('gd-aba-templates-deleted', true);
      if (r && !r.error && r.value) { const v = JSON.parse(r.value); if (Array.isArray(v)) server = v; }
    }
  } catch (e) {}
  const all = [...new Set([...server, ...loadDeletedTemplateIds(), id])];
  saveDeletedTemplateIds(all.slice(-500));
}
const BACKUP_INTERVAL_MS = 5 * 60 * 1000;  // 5분 이상 간격으로만 백업

// 회전 백업 저장 (마지막 백업 후 5분 지난 경우만)
function saveBackup(state) {
  try {
    const raw = localStorage.getItem(lsKey(LS_BACKUPS));
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
    localStorage.setItem(lsKey(LS_BACKUPS), JSON.stringify(list));
  } catch (e) {}
}

function loadBackups() {
  try {
    const raw = localStorage.getItem(lsKey(LS_BACKUPS));
    return raw ? JSON.parse(raw) : [];
  } catch (e) {
    return [];
  }
}

function removeBackup(id) {
  try {
    const raw = localStorage.getItem(lsKey(LS_BACKUPS));
    if (!raw) return;
    const list = JSON.parse(raw).filter((b) => b.id !== id);
    localStorage.setItem(lsKey(LS_BACKUPS), JSON.stringify(list));
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
      therapist: '',  // ★ 새로 추가할 때 로그인한 선생님 이름으로 채움 (addChild 참고)
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
      // ★ 아이마다 선생님이 직접 쓰도록 빈칸 3줄 (모든 아이에게 같은 문장이 들어가지 않게)
      familySuggestions: ['', '', ''],
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
// ★ 종결보고서 목표 달성도 = 책의 0·1·2점 채점 기준 말 그대로(1권 8장 채점 기준)
const ACHIEVE_LABEL = { 2: '준거에 일관성 있게 도달(2)', 1: '준거에 일관성 없이 도달하거나 보조를 받아서 수행함(1)', 0: '준거에 도달하지 못함(0)' };
// 예전 이름(오늘 앞서 쓴 이름)도 같은 값으로 본다
const ACHIEVE_OLD = { '일관성 있게 도달(2)': 2, '일관성 없이 도달(1)': 1, '도달하지 못함(0)': 0 };

// ★ 샘플 아동에 책 양식(파트너 목표·주간 기록지·활동 계획서) 예시를 채운다
function addSampleBookForms(c, partnerIds, startDate, team, activities) {
  const lookup = itemLookup(c.meta?.stage);
  c.iep.partnerGoals = partnerIds.filter((id) => lookup[id]).map((id) => ({ id, label: lookup[id].label }));
  const keys = [...(c.iep.selectedGoals || []).map((g) => g.id), ...c.iep.partnerGoals.map((g) => g.id)];
  const nWeeks = 6;
  const d0 = new Date(startDate + 'T00:00:00');
  const startDates = Array.from({ length: 12 }, (_, i) => {
    if (i >= nWeeks) return '';
    const d = new Date(d0.getTime() + i * 7 * 86400000);
    return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`;
  });
  // 주간 점수는 사전 진단 점수에서 시작해 사후 진단 점수로 끝나게 한다(보고서와 서로 맞도록)
  const pre = (c.sessions || []).find((x) => x.designation === 'pre')?.scores || {};
  const post = (c.sessions || []).find((x) => x.designation === 'post')?.scores || {};
  // 샘플에서 고른 목표는 사전에 아직 일관되지 않았던(0·1점) 목표로 맞추고, 대부분 사후에 1점씩 오르게 한다
  keys.forEach((k, i) => {
    if (typeof pre[k] !== 'number' || pre[k] === 2) pre[k] = 1;
    if (typeof post[k] !== 'number' || post[k] < pre[k]) post[k] = pre[k];
    if (i % 4 !== 3 && post[k] === pre[k]) post[k] = Math.min(2, pre[k] + 1);
  });
  const scores = {};
  keys.forEach((k, i) => {
    const a0 = typeof pre[k] === 'number' ? pre[k] : 0;
    const b0 = typeof post[k] === 'number' ? post[k] : a0;
    const turn = 2 + (i % 3);   // 바뀌는 주를 목표마다 조금씩 다르게
    scores[k] = [...Array.from({ length: nWeeks }, (_, w) => (w < turn ? a0 : b0)), ...Array(12 - nWeeks).fill(null)];
  });
  c.activities.weeklyScores = { startDates, scores };
  const checks = {};
  keys.forEach((k, i) => { checks[k] = Array.from({ length: 6 }, (_, j) => j < activities.length && (j === i % activities.length || j === (i + 1) % activities.length)); });
  c.activities.plan = { ...(c.activities.plan || {}), book: { team, cols: activities.map((a) => ({ ...a })), checks } };
  // ★ 미리 적어 둔 옛날 형식 문장(백분율·패턴 이름·도달 등급)은 비워 두고, '자동 채움'으로 책 방식 문장이 채워지게 한다
  const blank3 = { sc: '', er: '', ts: '' };
  c.iep = { ...c.iep, currentLevel: { ...blank3 }, annualGoals: { ...blank3 }, shortGoals: { ...blank3 }, strategies: { ...blank3 }, measures: { ...blank3 } };
  c.interim = { ...c.interim, summary: '', domainSummary: {}, observations: '', direction: '', recommendation: '', goalAchievement: [], familySuggestions: ['', '', ''] };
  // ★ 샘플 회기 기록도 책 활동 일지 I 양식(목표 줄마다 활동·유의점)으로 바꿔 둔다
  c.activities.logI = (c.activities.logI || []).map((l) => {
    const act = l.fields?.activity || '';
    const conv = (g) => ({ goal: String(g.goal || '').replace(/^\[([A-Z]{2}\d+\.\d+)\]\s*/, '$1 '), act: [act, ''], note: [`${g.observed || ''}${(g.rating || '').trim() ? ` (${g.rating.trim()})` : ''}`, ''] });
    const child = [...(l.goalsSocial || []), ...(l.goalsEmo || [])].filter((g) => g && g.goal).map(conv);
    const partner = (l.partnerGoals || []).filter((g) => g && g.goal).map(conv);
    return { id: l.id, date: l.date, kind: 'I', bookChild: padBookRows(child), bookPartner: padBookRows(partner) };
  });
  // ★ 가족·전문가 지원 계획은 책 양식(1권 부록 진단 요약지 5쪽: 교육 지원·정서 지원 — 활동, 얼마나 자주)으로 넣는다
  c.familySupport = { bookPlan: {
    edu: [{ act: '가정 일과 안에서 의사소통 기회 만들기 안내', freq: '월 1회' }, { act: '시각 일정표 가정 사용법 시범', freq: '월 1회' }],
    emo: [{ act: '부모 면담(어려운 점 듣기)', freq: '월 1회' }],
  } };
  c.profSupport = { bookPlan: {
    edu: [{ act: '어린이집 교사와 공동 목표·전략 공유', freq: '월 1회' }],
    emo: [{ act: '팀 회의에서 교사 어려움 나누기', freq: '월 1회' }],
  } };
}

// ★ 샘플 아동은 책처럼 모든 문항을 채점한 상태로 만든다(진단 요약지는 전 문항 채점이 전제, 1권 265쪽)
//   미리 적어 둔 점수는 그대로 두고, 빈 문항은 같은 장기목표에서 가장 낮은 점수보다 1점 낮게(최소 0점) 채운다
//   (장기목표 안 문항을 하나도 적지 않았으면 아동 목표는 0점, 교류 지원은 1점). 사후 점수는 사전보다 낮지 않게.
function completeSampleScores(c) {
  const data = STAGE_DATA[c.meta?.stage];
  if (!data || !Array.isArray(c.sessions)) return;
  const fill = (scores, floor) => {
    const out = { ...scores };
    Object.entries(data).forEach(([key, d]) => {
      const isTs = key === 'interpersonalSupport' || key === 'learningSupport';
      d.groups.forEach((g) => {
        const given = g.items.map((it) => scores[it.id]).filter((v) => typeof v === 'number');
        const base = given.length ? Math.max(0, Math.min(...given) - 1) : (isTs ? 1 : 0);
        g.items.forEach((it) => {
          if (typeof out[it.id] !== 'number') out[it.id] = Math.max(base, floor?.[it.id] ?? 0);
        });
      });
    });
    return out;
  };
  const pre = c.sessions.find((x) => x.designation === 'pre');
  const post = c.sessions.find((x) => x.designation === 'post');
  if (pre) pre.scores = fill(pre.scores || {}, null);
  if (post) post.scores = fill(post.scores || {}, pre?.scores);
}

function makeSampleChild() {
  const c = blankChild('민준호');
  c.meta.birthDate = '2022-04-15';
  c.meta.startDate = '2026-01-10';
  c.meta.stage = 'language';
  c.meta.className = 'SCERTS 프로그램 햇살반';
  c.meta.therapist = '민 다 혜';

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
    lp_sc_imit: { 0: 2, 1: 1, 2: 1 },
    lp_sc_10: { checked: { '가리키기': true, '얼굴 표정': true, '아동의 이름': true, familiar: true, verb: true }, texts: { familiar: '"신발 신고 나가자" 같은 익숙한 구는 이해함', verb: '"빨리", "크게" 등 익숙한 수식어는 이해함' } },
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
      goalsSocial: [{ goal: '[JA5.3] 차례 주고받기', observed: '블록을 가리키며 "더 줘"라고 요청하고 교사와 번갈아 쌓음', rating: '+ + +' }],
      goalsEmo: [], notes: '활동 시작 시 집중도가 높았고 차례 주고받기 3회 성공' },
    { id: 'log2', date: '2026-03-19', fields: { activity: '그림책 함께 보기' },
      goalsSocial: [{ goal: '[SU5.3] 초기 관계어 사용하기', observed: '그림을 보고 "강아지 없어", "공 또"라고 말함', rating: '+ +' }],
      goalsEmo: [{ goal: '[SR3.1] 혼자 하는 활동 중 언어 전략 사용하기', observed: '책장을 넘기고 싶을 때 "기다려"라고 혼잣말하며 기다림', rating: '+' }],
      notes: '' },
    { id: 'log3', date: '2026-03-26', fields: { activity: '자동차 역할놀이' },
      goalsSocial: [],
      goalsEmo: [{ goal: '[SR3.1] 혼자 하는 활동 중 언어 전략 사용하기', observed: '자동차를 뺏기자 화났지만 "내 차"라고 말한 뒤 교사가 감정을 짚어 주자 진정', rating: '+' }],
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
    sc: '준호는 언어 파트너 단계 수준에서 공동관심 55%, 상징 사용 50%로 나타났다. 보호자 보고에 따르면 눈맞춤은 잘하고 원하는 것을 단어로 표현하지만, 먼저 대화를 시작하는 일은 드뭅니다. 점수가 낮은 항목을 IEP 목표로 선정하였다.',
    er: '준호는 정서 조절 영역에서 상호조절 44%, 자기조절 32%로, "조절 토대 형성 필요" 패턴에 해당한다. 상호조절과 자기조절 모두 절반 미만으로 상대적 요구에 해당한다. 두 능력은 발달 내내 서로 의존하므로 함께 지원한다. 흥미를 보이는 활동은 블록 쌓기, 자동차 놀이, 그림책 보기이며, 어려움을 보이는 상황은 놀이를 끝내고 다른 활동으로 바꿀 때, 시끄럽고 사람이 많은 환경이다.',
    ts: '파트너의 교류 지원은 양호한 수준이다. 파트너의 반응성과 시각 지원 사용에서 강점이 있으며, 시작행동 촉진과 또래 상호작용 지원이 교실과 가정 간 일관성 확보의 우선 과제이다.',
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
    { id: 'SU5.3', label: '초기 관계어 사용하기', domain: 'symbolUse', customGoal: '' },
    { id: 'SR3.1', label: '혼자 하는 활동 중 언어 전략 사용하기', domain: 'selfReg', customGoal: '' },
  ];

  // 7) 중간보고서 — 미리 채움 (STEP5는 사전/사후로 이미 완료, 내용도 채워둠)
  c.interim.reportType = 'interim';
  c.interim.reportDate = '2026-05-20';  // 중간보고서 작성일 (IEP·홈과 다르게)
  c.interim.period = '2026년 1월 ~ 5월 (1차 중재 기간)';
  c.interim.summary = '준호는 언어 파트너 단계(상징적 의사소통의 확장) 수준에 해당한다. 이번 평가 기간 동안 SCERTS 세 영역(사회 의사소통, 정서 조절, 교류 지원)을 중심으로 중재를 진행하였다. 사전·사후 진단 점수 변화는 구성 요소별로 SAP 요약지에 정리하였다. 이 단계의 핵심 발달 과제는 단일 단어에서 2~3어 조합으로 확장, 다양한 의사소통 기능 출현이며, 해당 과제를 중심으로 지원하였다.';
  c.interim.observations = '회기별 활동 일지 3건 중 주요 관찰 사례는 다음과 같다.\n\n▸ 2026-03-12 - 블록 쌓기 놀이\n  · 블록을 가리키며 "더 줘"라고 요청 (독립 수행)\n  메모: 활동 시작 시 집중도가 높았고 차례 주고받기 3회 성공\n\n▸ 2026-03-19 - 그림책 함께 보기\n  · 그림을 보고 "강아지", "공"이라고 명명 (부분 보조)\n\n▸ 2026-03-26 - 자동차 역할놀이\n  · 자동차를 뺏기자 화났지만 교사가 감정을 말로 짚어주자 진정 (파트너 도움)';
  c.interim.direction = '정서 조절 영역의 현재 프로파일은 상호조절 44%, 자기조절 32%로 "조절 토대 형성 필요" 패턴에 해당한다.\n\n상호조절과 자기조절 모두 절반 미만으로 상대적 요구에 해당한다. 두 능력은 발달 내내 서로 의존하므로 함께 지원한다.\n\n다음 기간에는 다음 전략을 중점적으로 적용한다.\n1. 파트너의 반응성·예측가능성 확보 (IS1 영역 강조)\n2. 준호가 좋아하는 감각 자극이나 활동으로 진정·각성 조절 시범\n3. 간단한 신호(예: 그림 카드)로 도움 요청을 가르치기\n4. 파트너 지원과 함께 준호가 혼자서 할 수 있는 자기조절 행동 전략도 연습';

  completeSampleScores(c);
  addSampleBookForms(c, ['IS2.3', 'LS1.2', 'IS6.2', 'LS2.3'], '2026-03-09', '교사(T), 엄마(M), 어린이집 교사(D)', [
    { name: '등원 인사', time: '9:30', complexity: '1:1', group: '2명', partners: 'T', ts: '인사 그림 카드' },
    { name: '블록 놀이', time: '10:00', complexity: '1:1', group: '2명', partners: 'T', ts: '차례 카드' },
    { name: '그림책 보기', time: '10:30', complexity: '1:2', group: '3명', partners: 'T', ts: '단어 조합 시범' },
    { name: '간식', time: '11:00', complexity: '1:3', group: '4명', partners: 'D', ts: '그림 선택판' },
  ]);
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
  c.meta.therapist = '민 다 혜';

  c.decision = { q1: { a1: false, a2: false }, q2: { b1: true, b2: false } };

  c.interview.meta = { name: '김서아', age: '만 2세 8개월', date: '2026-02-03', reporter: '박미영', relation: '어머니' };
  c.interview.answers = {
    sp_sc_1: '아직 단어는 거의 사용하지 않으며, 원하는 것이 있을 때 손을 끌어서 보여줍니다. 눈맞춤은 짧게 가능합니다.',
    sp_sc_2: '주로 사람을 도구처럼 사용하여 원하는 것을 얻으려 합니다. 가리키기는 아직 일관되지 않습니다.',
    // ★ 책(1권 부록) 사회적 파트너 질문지 문항·보기에 맞춘 견본 답
    sp_sc_3: { checked: { '다른 사람의 손을 당겨 물건 위에 놓기': true, '손 뻗기/만지기': true, vocal: true, word: true }, texts: { vocal: '"음", "어어" 같은 발성, 울음', word: '"엄마", "맘마" 시도' } },
    sp_sc_4: { checked: { '원하는 물건 요구하기': true, '원하지 않는 것 거절하기': true }, texts: {} },
    sp_sc_5: { 0: 1, 1: 0, 2: 0 },
    sp_sc_6: '못 알아채면 더 크게 울거나 손을 잡아 끌고 갑니다.',
    sp_sc_7: '비눗방울, 흔들리는 인형, 까꿍 놀이를 가장 좋아합니다.',
    sp_sc_8: '친숙한 어른이 다가오면 미소 짓고 짧게 눈맞춤하나, 또래에는 거의 반응 없음.',
    sp_sc_9: { 0: 1, 1: 1, 2: 0 },
    sp_sc_10: { checked: { '얼굴 표정': true, '아동의 이름': true, name_word: true, phrase: true }, texts: { name_word: '"엄마"', phrase: '"안 돼", "이리 와"' } },
    sp_er_1: '낯선 자극에 위축되며 엄마를 찾습니다. 친숙한 자극에는 미소나 발성을 보입니다.',
    sp_er_2: '비눗방울, 음악, 까꿍 놀이',
    sp_er_3: '낯선 사람, 큰 소음, 옷 갈아입기',
    sp_er_4: '엄마가 안아주거나 좋아하는 인형을 쥐어주면 진정됩니다.',
    sp_er_5: '새로운 상황에서는 엄마 다리에 매달려 진정하려 합니다.',
    sp_er_6: { '기쁨': '소리내며 웃고 손뼉을 침', '슬픔': '울음', '분노': '큰 울음과 발버둥', '두려움': '엄마에게 매달림' },
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
    sp_ts_3: { '아동이 관심을 갖는 대상': 2, '아동이 의사소통하려고 하는 것': 1, '아동의 감정 상태': 2, '아동이 선호하는 속도(빠름 또는 느림)': 1, '아동에게 휴식이 필요할 때': 1, '아동이 흥미를 보이는지 여부': 2, '아동이 좌절했는지 여부': 2, '아동이 흥분했는지 여부': 1 },
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
      goalsSocial: [{ goal: '[JA2.2] 사람과 사물 간에 시선 옮기기', observed: '비눗방울을 더 원할 때 비눗방울과 엄마를 번갈아 봄', rating: '+ + +' }],
      goalsEmo: [], notes: '5초간 시선 유지 가능' },
    { id: 'log2', date: '2026-03-12', fields: { activity: '까꿍 놀이' },
      goalsSocial: [{ goal: '[SU5.1] 차별화된 발성 사용하기', observed: '엄마가 잠시 멈추자 "아-" 발성으로 다시 하자고 요청', rating: '+ +' }],
      goalsEmo: [{ goal: '[MR2.1] 파트너의 위로에 진정하기', observed: '까꿍 소리에 놀라 울었으나 엄마가 안아 주자 1분 안에 진정', rating: '+' }],
      notes: '' },
  ];

  c._isSample = true;
  c.iep.reportDate = '2026-02-25';
  c.iep.currentLevel = {
    sc: '서아는 사회 의사소통 영역에서 사회적 파트너 단계 초기 수준이다. 보호자 보고에 따르면 아직 단어는 거의 사용하지 않으며 손 끌기와 발성으로 의사를 보인다. 공동관심은 발달 중이며, 가리키기와 시선 맞추기가 일관되지 않다.',
    er: '서아는 정서 조절 영역에서 파트너 의존이 높은 양상이다. 낯선 자극에 위축되며 엄마의 도움으로 진정한다. 흥미를 보이는 활동은 비눗방울·음악·까꿍 놀이이며, 어려움을 보이는 상황은 낯선 사람·큰 소음·옷 갈아입기이다.',
    ts: '친숙한 파트너가 서아의 신호에 잘 반응하는 것이 교류 지원의 강점이다. 파트너의 반응성·기다림·시각 지원 사용에서 일관성을 높이는 것이 우선 과제이다.',
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
    { id: 'JA2.2', label: '사람과 사물 간에 시선 옮기기', domain: 'joinAttention', customGoal: '' },
    { id: 'JA2.3', label: '짚어서 가리키는 것을 쳐다보기', domain: 'joinAttention', customGoal: '' },
    { id: 'SU5.1', label: '차별화된 발성 사용하기', domain: 'symbolUse', customGoal: '' },
    { id: 'MR2.1', label: '파트너의 위로에 진정하기', domain: 'mutualReg', customGoal: '' },
  ];

  c.interim.reportType = 'interim';
  c.interim.reportDate = '2026-06-10';
  c.interim.period = '2026년 2월 ~ 6월 (1차 중재 기간)';
  c.interim.summary = '서아는 사회적 파트너 단계(전 상징적 의사소통)에 해당한다. 이번 평가 기간 동안 의도적 의사소통 시도가 늘었으며, 발성과 가리키기 사용 빈도가 증가하였다. 사전·사후 진단 점수 변화는 구성 요소별로 SAP 요약지에 정리하였다.';
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

  completeSampleScores(c);
  addSampleBookForms(c, ['IS1.3', 'IS1.6', 'IS5.1', 'LS1.4'], '2026-03-02', '엄마(M), 치료사(T)', [
    { name: '비눗방울 놀이', time: '10:00', complexity: '1:1', group: '2명', partners: 'M', ts: '빈 통 건네기 기다리기' },
    { name: '까꿍 놀이', time: '10:20', complexity: '1:1', group: '2명', partners: 'M', ts: '멈추고 기다리기' },
    { name: '노래 율동', time: '10:40', complexity: '1:1', group: '2명', partners: 'T', ts: '동작 모방' },
    { name: '옷 입기', time: '11:00', complexity: '1:1', group: '2명', partners: 'M', ts: '사물 일정표' },
  ]);
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
  c.meta.therapist = '민 다 혜';

  c.decision = { q1: { a1: true, a2: true, a3: true }, q2: { b1: true, b2: true, b3: true } };

  c.interview.meta = { name: '이지훈', age: '만 6세 3개월', date: '2026-01-17', reporter: '최수정', relation: '어머니' };
  c.interview.answers = {
    cp_sc_1: '문장으로 자기 생각을 표현할 수 있으나, 대화 주제를 유지하거나 상대 의도를 파악하는 데 어려움이 있습니다.',
    // ★ 책(1권 부록) 대화 파트너 질문지 문항에 맞춘 견본 답
    cpb_sc_2: { checked: { '원하는 물건을 요구하거나 도움 청하기': true, '현재와 과거의 사건에 대해 이야기하기': true, '현재와 과거의 사건에 대해 정보 요구하기': true, '감정과 의견 표현하기': true }, texts: {} },
    cpb_sc_3: '관심 있는 주제로 돌아가거나, 말이 통하지 않으면 짜증을 냅니다.',
    cpb_sc_4: { checked: { '의문사(예: 무엇, 어디, 누구)': true, '시간을 나타내는 단어(예: 전에, 지금, 나중에, 언제)': true, '동사(예: 과거형, 현재형, 미래형 시제[먹었다, 달렸다, 갈 거야])': true, '등위접속사(예: 그리고, 또는)': true }, texts: {} },
    cpb_sc_5: { checked: { '자주 주제를 시작한다': true, '관련된 정보를 요구한다': true }, texts: {} },
    cpb_sc_6: { checked: { '얼굴 표정': true, '몸짓': true }, texts: {} },
    cpb_sc_7: '공룡 책 읽기, 지하철 노선도 보기, 블록으로 건물 만들기.',
    cpb_sc_8: '같은 반 친구 2명. 공룡 이야기를 하거나 블록 놀이를 함께 하고 싶어 합니다.',
    cpb_sc_9: { 0: 2, 1: 2, 2: 1 },
    cpb_sc_10: { checked: { '감정에 대한 비구어 단서': true }, texts: {} },
    cp_er_1: '관심사에는 적극적이나, 예상과 다른 상황에서 강한 정서 변화를 보입니다.',
    cp_er_2: '공룡 박물관 가기, 지하철 타기, 블록 건축',
    cp_er_3: '계획 변경, 친구와의 의견 충돌, 시끄러운 환경',
    cp_er_4: '"5분 더 하고 끝내자"고 미리 약속하면 협상이 가능합니다.',
    cp_er_5: '심호흡을 시범 보이면 따라 합니다. 자기 자리로 가서 책을 보며 진정합니다.',
    cpb_er_6: { '기쁨': '뛰며 큰 소리로 좋아한다고 말함', '슬픔': '"속상해"라고 말하며 풀이 죽음', '만족감': '"좋아"라고 말하며 미소', '분노 또는 좌절': '"싫어!"라고 외치고 발을 구름', '익살스러움': '농담을 시도하지만 또래가 이해 못해 좌절', '두려움': '"안 할래"라고 말하며 회피' },
    cpb_er_7: '안내해 주면 받아들이지만, 감정이 진정되기까지 시간이 좀 걸립니다.',
    cp_er_9: '심호흡, 좋아하는 책 보기, 혼잣말로 상황 정리하기.',
    cp_er_10: '얼굴이 빨개지고 목소리가 커지며 같은 말을 반복합니다.',
    cpb_er_10: '대답이 짧아지고 주제를 바꾸거나 자리를 뜨려 합니다.',
    cp_er_12: { self: '자기 자리로 가서 책을 보거나 혼잣말로 상황을 정리함', partner: '감정을 짚어주고 대안을 함께 찾으면 회복됨' },
    cp_ts_1: '엄마, 아빠, 누나, 담임 선생님, 친구 2명',
    cp_ts_2: '집, 학교, 공룡 박물관, 지하철역',
    cpb_ts_3: { '아동이 관심을 갖는 대상': 2, '아동이 의사소통하려고 하는 것': 2, '아동의 감정 상태': 1, '아동이 선호하는 속도(빠름 또는 느림)': 2, '아동에게 휴식이 필요할 때': 1, '아동이 흥미를 보이는지 여부': 2, '아동이 좌절했는지 여부': 1, '아동이 흥분했는지 여부': 1 },
    cp_ts_4: '관심 주제로 대화를 시작해 점차 새 주제로 확장합니다.',
    cp_ts_5: '감정을 언어로 짚어주고 대안을 함께 찾습니다.',
    cp_ts_6: '눈높이에서 이름을 부르고 짧고 명확하게 요점을 전달합니다.',
    cp_ts_7: '관심 주제를 활용해 대화를 길게 이어갑니다.',
    cp_ts_8: '구체적 언어와 시각 자료(그림, 도식)를 함께 사용합니다.',
    cp_ts_9: '주간 일정표와 활동 순서표를 사용합니다.',
    cp_ts_10: '구조화된 환경, 예측 가능한 일정, 익숙한 또래가 있을 때 잘 참여합니다.',
    cp_ts_11: '시각 자료가 함께 제시되고 한 번에 한 가지 활동이 주어질 때 효과적입니다.',
  };

  // CP 단계 진단 점수 (전반적으로 높음 — 대화 가능 단계)
  const preScores = {
    'JA1.1':2,'JA2.1':2,'JA3.1':1,'JA4.1':2,'JA5.1':2,'JA4.2':1,'JA5.2':1,'JA4.8':1,
    'SU1.1':2,'SU2.1':2,'SU3.1':2,'SU4.1':1,'SU5.1':2,'SU5.2':1,'SU6.1':1,
    'MR1.1':2,'MR2.1':1,'MR2.3':2,'MR3.1':1,
    'SR1.1':2,'SR2.1':1,'SR3.1':1,'SR4.1':1,
    'IS1.1':2,'IS2.1':2,'IS6.1':1,'LS1.1':2,'LS2.1':1,'LS3.1':1,
  };
  const postScores = {
    'JA1.1':2,'JA2.1':2,'JA3.1':2,'JA4.1':2,'JA5.1':2,'JA4.2':2,'JA5.2':2,'JA4.8':2,
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
      goalsSocial: [{ goal: '[JA4.1] 청자/화자 역할 바꾸며 상호작용하기', observed: '"내 차례야"라고 말하고 친구 차례를 기다림', rating: '+ + + +' }],
      goalsEmo: [{ goal: '[SR5.2] 새/변화 상황에서 언어 전략 사용하기', observed: '처음 해 보는 게임에서 졌을 때 "괜찮아, 다시 하자"고 말함', rating: '+' }],
      notes: '' },
    { id: 'log2', date: '2026-03-17', fields: { activity: '주제 대화 (좋아하는 영화)' },
      goalsSocial: [{ goal: '[JA4.3] 파트너 관심에 맞게 대화 시작/유지하기', observed: '친구가 좋아하는 영화로 주제를 바꿔 5번 주고받음', rating: '+ + + + +' }],
      goalsEmo: [], notes: '관심 외 주제로도 1분간 대화 가능' },
  ];

  c._isSample = true;
  c.iep.reportDate = '2026-02-05';
  c.iep.currentLevel = {
    sc: '지훈이는 사회 의사소통 영역에서 대화 파트너 단계 중간 수준이다. 문장으로 자기 생각을 표현할 수 있으나, 보호자 보고에 따르면 대화 주제를 유지하거나 상대 의도를 파악하는 데 어려움이 있다.',
    er: '지훈이는 정서 조절 영역에서 자기조절 전략(심호흡, 혼잣말, 책 보기)을 사용할 수 있으나, 예상과 다른 상황(계획 변경, 의견 충돌)에서 강한 정서 변화를 보인다.',
    ts: '구조화된 환경과 예측 가능한 일정 제공이 교류 지원의 강점이다. 또래 매개 전략과 갈등 중재 지원이 우선 과제이다.',
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
    { id: 'JA4.1', label: '청자/화자 역할 바꾸며 상호작용하기', domain: 'joinAttention', customGoal: '' },
    { id: 'JA4.3', label: '파트너 관심에 맞게 대화 시작/유지하기', domain: 'joinAttention', customGoal: '' },
    { id: 'SR5.1', label: '새/변화 상황에서 행동 전략 사용하기', domain: 'selfReg', customGoal: '' },
    { id: 'SR5.2', label: '새/변화 상황에서 언어 전략 사용하기', domain: 'selfReg', customGoal: '' },
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

  completeSampleScores(c);
  addSampleBookForms(c, ['IS2.3', 'IS5.1', 'LS3.6', 'IS3.4'], '2026-03-09', '담임(T), 특수교사(S), 엄마(M), 누나(N)', [
    { name: '아침 모임', time: '9:00', complexity: '1:20', group: '21명', partners: 'T', ts: '모임 순서표' },
    { name: '보드게임', time: '10:40', complexity: '1:3', group: '4명', partners: 'S', ts: '갈등 해결 단계 카드' },
    { name: '점심시간', time: '12:00', complexity: '1:20', group: '21명', partners: 'T', ts: '대화 주제 카드' },
    { name: '집 놀이', time: '17:00', complexity: '1:2', group: '3명', partners: 'M, N', ts: '자기조절 카드' },
  ]);
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
    const raw = localStorage.getItem(lsKey(LS_STATE));
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
    // legacy 마이그레이션 (계정이 정해진 뒤에는 쓰지 않음 — 이 기기의 공용 칸에는 다른 계정 자료가 있을 수 있음)
    const legacy = _lsUser ? null : localStorage.getItem(LS_KEY);
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
      assessment: { quarter: '', scores: {}, ses: {}, notes: '', subChecks: {} },
      pre: null, post: null,
      iep: dummy.iep, interim: dummy.interim, activities: dummy.activities,
      familySupport: dummy.familySupport, profSupport: dummy.profSupport,
      communicationSchedule: dummy.communicationSchedule, fba: dummy.fba,
      _childId: null, _sessionId: null, _allSessions: [], _preSession: null, _postSession: null,
      _empty: true,
    };
  }
  // ★ 세션마다 그 세션을 채점한 단계(stage)가 적혀 있으면, 지금 단계의 세션만 보이고 비교한다
  //   (단계를 바꾼 뒤 이전 단계 점수가 새 단계 문항과 섞이지 않게. 단계가 안 적힌 예전 세션은 늘 보임)
  const allSessions = child.sessions || [];
  //   이 단계 세션이 하나도 없으면 다른 단계 세션을 보여 주지 않는다(빈 화면 → 처음 채점할 때 새 세션이 생김)
  const stageSessions = allSessions.filter((s) => !s.stage || s.stage === child.meta?.stage);
  const session = stageSessions.find((s) => s.id === child.activeSessionId)
                  || stageSessions[0]
                  || blankSession();
  const preSession = stageSessions.find((s) => s.designation === 'pre');
  const postSession = stageSessions.find((s) => s.designation === 'post');
  return {
    meta: child.meta,
    decision: child.decision,
    interview: child.interview,
    observation: child.observation,
    familyPriorities: child.familyPriorities,
    assessment: {
      quarter: session.quarter,
      scores: session.scores,
      ses: sesOf(session, child.meta?.stage),   // ★ 문항 점수로 계산 (표 7-5)
      notes: session.notes,
      subChecks: session.subChecks || {},       // ★ 문항 아래 체크칸(□, 1권 부록)
    },
    pre: preSession ? { scores: preSession.scores, ses: sesOf(preSession, child.meta?.stage) } : null,
    post: postSession ? { scores: postSession.scores, ses: sesOf(postSession, child.meta?.stage) } : null,
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
    _allSessions: stageSessions,
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
  // ★ 화면에 보이던 세션(oldWs._sessionId)에 저장 — 가려진 다른 단계 세션에 잘못 저장되지 않게
  let sessionIdx = (child.sessions || []).findIndex((s) => s.id === oldWs._sessionId);
  // 이 단계 세션이 없어서 임시 세션을 보고 있었던 경우: 그 내용을 이 단계 세션으로 새로 만들어 저장
  let childSessions = child.sessions || [];
  let activeSessionId = child.activeSessionId;
  if (sessionIdx < 0 && newWs.assessment) {
    const a = newWs.assessment;
    const changed = Object.keys(a.scores || {}).length > 0 || Object.keys(a.ses || {}).length > 0 || Object.keys(a.subChecks || {}).length > 0 || (a.notes || '').trim();
    if (changed) {
      const ns = { ...blankSession(`${STAGE_LABELS[newWs.meta?.stage] || ''} 진단`.trim(), a.quarter || 1), stage: newWs.meta?.stage || child.meta?.stage || null };
      childSessions = [...childSessions, ns];
      activeSessionId = ns.id;
      sessionIdx = childSessions.length - 1;
    }
  }
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
    activeSessionId,
    sessions: sessionIdx >= 0
      ? childSessions.map((s, i) => i === sessionIdx ? {
          ...s,
          quarter: newWs.assessment.quarter,
          scores: newWs.assessment.scores,
          // ★ 성장 지표는 화면에서 문항 점수로 계산하므로 저장된 값(예전에 손으로 정한 값)은 그대로 둔다
          ses: s.ses || {},
          notes: newWs.assessment.notes,
          subChecks: newWs.assessment.subChecks || s.subChecks || {},
        } : s)
      : childSessions,
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
    // ★ 아이마다 선생님이 직접 쓰도록 빈칸 3줄 (모든 아이에게 같은 문장이 들어가지 않게)
    familySuggestions: ['', '', ''],
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
    const raw = localStorage.getItem(lsKey(LS_ARCHIVE));
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
// ★ [통합본 연결] 통합본(원장님 화면)에서 아이를 골라 이 앱을 열었을 때 넘겨받은 이름·생년월일
//   - 주소에는 아이 번호만(?aba_child=...), 이름·생년월일은 같은 사이트 저장칸(aba-child-handoff)에 잠깐 맡겨 둔 것을 한 번 읽고 지운다.
//   - 이 앱(APPKEY) 것이고 30분 안의 것만 쓴다.
//   - 로그인 확인 뒤 화면이 처음부터 다시 그려져도 잃지 않게, 처리가 끝날 때까지 이 창 안 저장칸에 맡겨 둔다.
const ABA_CHILD_HANDOFF_KEY = 'aba-child-handoff';
const ABA_CHILD_LINK_KEY = 'aba-child-link-scerts';
function clearAbaChildLink() {
  try { sessionStorage.removeItem(ABA_CHILD_LINK_KEY); } catch (e) {}
}
function readAbaChildLink(appKey) {
  try {
    const params = new URLSearchParams(window.location.search || '');
    const cid = params.get('aba_child');
    if (!cid) {
      try {
        const saved = JSON.parse(sessionStorage.getItem(ABA_CHILD_LINK_KEY) || 'null');
        if (saved && saved.cid && saved.name && Date.now() - (Number(saved.ts) || 0) < 30 * 60 * 1000) return { cid: saved.cid, name: saved.name, birth: saved.birth || '' };
      } catch (e) {}
      clearAbaChildLink();
      return null;
    }
    let link = null;
    try {
      const h = JSON.parse(localStorage.getItem(ABA_CHILD_HANDOFF_KEY) || 'null');
      if (h && h.app === appKey && String(h.cid) === String(cid) && Date.now() - (Number(h.ts) || 0) < 30 * 60 * 1000) {
        const b = String(h.birth || '');
        link = { cid: String(cid), name: String(h.name || '').trim(), birth: /^\d{4}-\d{2}-\d{2}$/.test(b) ? b : '' };
      }
    } catch (e) {}
    try { localStorage.removeItem(ABA_CHILD_HANDOFF_KEY); } catch (e) {}
    if (link && link.name) { try { sessionStorage.setItem(ABA_CHILD_LINK_KEY, JSON.stringify({ ...link, ts: Date.now() })); } catch (e) {} }
    else clearAbaChildLink();
    try { params.delete('aba_child'); const q = params.toString(); window.history.replaceState(null, '', window.location.pathname + (q ? '?' + q : '') + window.location.hash); } catch (e) {}
    return link && link.name ? link : null;
  } catch (e) { return null; }
}

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
  // ★ 이 기기 저장칸을 로그인한 계정 것으로 맞춘 뒤에 불러온다 (계정이 바뀌면 이 화면이 새로 그려짐)
  _lsUser = authUser?.id || '';
  // 예전(계정 구분 전) 이 기기 공용 칸의 자동 백업·템플릿 등은 원장님 계정으로만 옮겨 온다 (선생님 계정으로는 옮기지 않음)
  if (_lsUser && authUser?.role === 'admin') migrateSharedLocal();
  const [state, setStateRaw] = useState(loadState);
  const [loadFailed, setLoadFailed] = useState(false); // 서버에서 내 자료를 못 불러왔는지
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
      // ★ 화면을 안 보고 있을 땐 확인하지 않음 (아이폰 데이터·배터리 절약)
      if (typeof document !== 'undefined' && document.hidden) { timer = setTimeout(check, 30000); return; }
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
      timer = setTimeout(check, 30000); // 30초마다 (전에는 5초마다 전체 자료를 받아 데이터를 많이 씀)
    };
    timer = setTimeout(check, 30000);
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
  const loadDoneRef = useRef(false); // '내 데이터로 돌아가기'로 이미 내 자료를 받아 왔는지 (처음 불러오기 결과가 늦게 와서 덮어쓰지 않게)
  const [sharedReady, setSharedReady] = useState(false); // ★ [통합본 연결] 내 데이터를 다 불러왔는지
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
    setSharedReady(false);
    (async () => {
      if (!authUser?.name) return;
      if (!window.storage) {
        // 게시 안 된 환경: 공유 저장소 없음 → localStorage 그대로 사용
        sharedLoadedRef.current = true;
        setSharedReady(true);
        return;
      }
      // ★ 서버에서 못 불러오면(인터넷 끊김 등) 이 기기의 옛 자료로 서버를 덮어쓰지 않도록 저장을 막고 알린다.
      //   잠깐 끊긴 경우를 위해 1.5초 간격으로 3번까지 다시 시도한다.
      let ok = false;
      let loadedState = null;
      for (let attempt = 0; attempt < 3 && !cancelled; attempt++) {
        try {
          const r = await window.storage.get('gd-aba-state', true);
          if (r && r.error) throw new Error('state');
          const ar = await window.storage.get('gd-aba-archive', true);
          if (ar && ar.error) throw new Error('archive');
          if (cancelled || loadDoneRef.current) return;
          // 서버 글이 깨져 읽을 수 없는 경우는 (예전처럼) '자료 없음'으로 보고 넘어간다 — 계속 저장이 막히지 않게
          if (r?.value) {
            try {
              const loaded = JSON.parse(r.value);
              if (loaded && Array.isArray(loaded.children)) { loadedState = loaded; setStateRaw(loaded); }
            } catch (e) {}
          }
          if (ar?.value) {
            try {
              const loadedArchive = JSON.parse(ar.value);
              if (Array.isArray(loadedArchive)) setArchive(loadedArchive);
            } catch (e) {}
          }
          ok = true;
          break;
        } catch (e) {
          if (attempt < 2) await new Promise((res) => setTimeout(res, 1500));
        }
      }
      if (cancelled || loadDoneRef.current) return;
      if (ok) {
        // ★ 선생님 계정: 이 기기 예전 공용 칸의 아이들이 모두 이 선생님 서버 자료에 있는 아이일 때만
        //   (= 그 공용 칸이 이 선생님 것일 때만) 예전 자동 백업·템플릿을 옮겨 온다
        if (authUser?.role !== 'admin' && _lsUser) {
          try {
            const old = JSON.parse(localStorage.getItem(LS_STATE) || 'null');
            const oldIds = (old?.children || []).map((c) => c.id);
            const mine = new Set((loadedState?.children || []).map((c) => c.id));
            if (oldIds.length > 0 && oldIds.every((id) => mine.has(id))) migrateSharedLocal();
          } catch (e) {}
        }
        setLoadFailed(false); sharedLoadedRef.current = true; setSharedReady(true);
      }
      else setLoadFailed(true);
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
        localStorage.setItem(lsKey(LS_STATE), JSON.stringify(stamped));
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
      localStorage.setItem(lsKey(LS_ARCHIVE), JSON.stringify(archive));
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

  // 새 아동의 치료사 기본값: 원장님은 기존처럼 '민 다 혜', 선생님은 본인 이름
  const myTherapistName = authUser?.role === 'admin' ? '민 다 혜' : (authUser?.name || '');

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
      child.meta.therapist = myTherapistName;
      return { ...s, children: [...s.children, child], activeChildId: child.id };
    });
    if (blocked) { showToast('조회 모드에서는 추가할 수 없습니다. 먼저 "내 데이터로 돌아가기"를 누르세요'); return; }
    setTab('home');
    showToast(`${name || '새 아동'}이(가) 추가되었습니다`);
  }, [showToast, myTherapistName]);

  // ★ [통합본 연결] 원장님 계정일 때만: 같은 아이가 있으면 그 아이를 열고, 없으면 물어본 뒤 이름·생년월일을 넣어 새로 추가
  const [abaLink, setAbaLink] = useState(() => readAbaChildLink('scerts'));
  const abaLinkBusyRef = useRef(false);
  useEffect(() => {
    if (!abaLink || abaLinkBusyRef.current) return;
    if (!authUser) return;
    if (authUser.role !== 'admin') { clearAbaChildLink(); setAbaLink(null); return; }
    if (!sharedReady) return;
    abaLinkBusyRef.current = true;
    clearAbaChildLink(); // 이제 처리하므로 맡겨 둔 것은 지움
    const link = abaLink;
    (async () => {
      try {
        if (state._viewingTeacher) { showToast('다른 선생님 자료를 보는 중이라 통합본 아이를 열지 않았습니다'); return; }
        const list = Array.isArray(state.children) ? state.children : [];
        const found = list.find((c) => c.meta && String(c.meta.abaChildId || '') === link.cid)
          || list.find((c) => c.meta && String(c.meta.childName || '').trim() === link.name);
        if (found) { switchChild(found.id); return; }
        const ok = await appConfirm(`통합본의 "${link.name}" 아동을 SCERTS에 새로 추가할까요?\n\n이름${link.birth ? '·생년월일(' + link.birth + ')' : ''}이 들어갑니다.`);
        if (!ok) return;
        setState((s) => {
          if (s._viewingTeacher) return s;
          const child = blankChild(link.name);
          child.meta = { ...child.meta, birthDate: link.birth || '', abaChildId: link.cid, therapist: myTherapistName };
          return { ...s, children: [...s.children, child], activeChildId: child.id };
        });
        setTab('home');
        showToast(`${link.name}이(가) 추가되었습니다`);
      } finally {
        setAbaLink(null);
      }
    })();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [abaLink, authUser, sharedReady, myTherapistName]);

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
        // ★ 새 세션에 지금 단계를 적어 둔다 (단계를 바꾸면 그 단계 세션끼리만 보이고 비교되게)
        ? { ...c, sessions: [...(c.sessions || []), { ...newSes, stage: c.meta?.stage || null }], activeSessionId: newSes.id }
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
        // 지운 세션이 열려 있었으면 같은 단계의 다른 세션을 연다
        const sameStage = filtered.find((x) => !x.stage || x.stage === c.meta?.stage);
        const newActive = c.activeSessionId === sessionId ? (sameStage || filtered[0]).id : c.activeSessionId;
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
        // 같은 designation 다른 세션은 해제 (같은 단계 세션만 — 다른 단계의 사전/사후 지정은 그대로 둠)
        const sameStage = (x) => !x.stage || x.stage === c.meta?.stage;
        return {
          ...c,
          sessions: c.sessions.map((x) => {
            if (x.id === sessionId) return { ...x, designation };
            if (designation && x.designation === designation && sameStage(x)) return { ...x, designation: null };
            return x;
          }),
        };
      }),
    }));
  }, []);

  // ★ 단계 바꾸기를 한 번에 처리 (되돌리기 ↶ 한 번에 원래대로 돌아가게)
  //   - 단계가 안 적힌 지금 세션들에 이전 단계를 적어 둠 (열린 세션이 비어 있으면 새 단계용으로 씀)
  //   - 새 단계 세션이 있으면 그것을 열고, 없으면 빈 세션을 하나 만듦
  const switchStage = useCallback((newStage) => {
    setState((st) => {
      if (st._viewingTeacher) return st;
      return {
        ...st,
        children: st.children.map((c) => {
          if (c.id !== st.activeChildId) return c;
          const prev = c.meta?.stage || null;
          let sessions = c.sessions || [];
          if (prev && prev !== newStage) {
            sessions = sessions.map((x) => {
              if (x.stage) return x;
              const empty = Object.keys(x.scores || {}).length === 0 && Object.keys(x.ses || {}).length === 0 && !(x.notes || '').trim() && !x.designation;
              if (x.id === c.activeSessionId && empty) return { ...x, stage: newStage };
              return { ...x, stage: prev };
            });
          }
          const visible = sessions.filter((x) => !x.stage || x.stage === newStage);
          let activeId = c.activeSessionId;
          if (visible.length === 0) {
            const ns = { ...blankSession(`${STAGE_LABELS[newStage]} 진단`, 1), stage: newStage };
            sessions = [...sessions, ns];
            activeId = ns.id;
          } else if (!visible.some((x) => x.id === activeId)) {
            activeId = visible[visible.length - 1].id;
          }
          return { ...c, meta: { ...c.meta, stage: newStage }, sessions, activeSessionId: activeId };
        }),
      };
    });
  }, [setState]);

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

  // 사전/사후 저장: 현재 활성 세션을 사전/사후로 지정
  const savePre = () => {
    if (!ws._sessionId) return;
    // 이 단계 세션이 아직 없으면(빈 임시 화면) 지정할 세션이 없음 → 안내
    if (!(ws._allSessions || []).some((x) => x.id === ws._sessionId)) { showToast('먼저 점수를 하나 이상 입력해 세션을 만든 뒤 지정해 주세요'); return; }
    setSessionDesignation(ws._sessionId, 'pre');
    showToast('현재 세션이 "사전 진단"으로 지정되었습니다');
  };
  const savePost = () => {
    if (!ws._sessionId) return;
    // 이 단계 세션이 아직 없으면(빈 임시 화면) 지정할 세션이 없음 → 안내
    if (!(ws._allSessions || []).some((x) => x.id === ws._sessionId)) { showToast('먼저 점수를 하나 이상 입력해 세션을 만든 뒤 지정해 주세요'); return; }
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

  // ★ 보관함 불러오기: 그 보고서의 '주인 아이'에게만 되돌려 넣는다 (지금 열린 다른 아이를 덮어쓰지 않게) + 먼저 확인
  const loadArchiveItem = async (snap, item) => {
    if (!snap) return;
    if (state._viewingTeacher) { showToast('조회 모드에서는 불러올 수 없습니다. 먼저 "내 데이터로 돌아가기"를 누르세요'); return; }
    const name = (item && item.childName) || snap.meta?.childName || '이름 없음';
    const when = item && item.savedAt ? new Date(item.savedAt).toLocaleString('ko-KR') : '';
    const ok = await appConfirm(
      `"${name}"의 자료를 이 보고서를 저장했던 때(${when}) 내용으로 되돌립니다.\n\n` +
      `그 뒤에 쓴 질문지·진단 점수·활동 기록 등은 이 보고서 시점으로 바뀝니다.\n` +
      `(다른 아이 자료는 바뀌지 않으며, 잘못 눌렀으면 위쪽 ↶ 버튼으로 되돌릴 수 있습니다)\n\n계속할까요?`);
    if (!ok) return;
    setState((s) => {
      if (s._viewingTeacher) return s;
      // 주인 아이 찾기: 보관 당시 아이 번호. 번호가 없는 아주 예전 보관 자료만 이름으로 찾는다
      //   (번호가 있는데 그 아이가 지워졌으면, 같은 이름의 다른 아이를 덮어쓰지 않도록 새 아이로 만든다)
      const cid = (item && item.childId) || snap._childId || null;
      let target = cid ? s.children.find((c) => c.id === cid) : null;
      if (!target && !cid) target = s.children.find((c) => (c.meta?.childName || '') === name) || null;
      let children = s.children;
      let targetId;
      if (target) {
        targetId = target.id;
      } else {
        const c = blankChild(snap.meta?.childName || '');
        children = [...children, c];
        targetId = c.id;
      }
      // ★ 점수는 보관 당시 열려 있던 '그 진단 세션'에 되돌린다 (지금 열린 다른 세션을 덮어쓰지 않게).
      //   그 세션이 지워졌으면 새 세션을 만들어 거기에 넣는다.
      const snapStage = snap.meta?.stage || null;
      children = children.map((c) => {
        if (c.id !== targetId) return c;
        // 지금 단계와 다른 단계로 되돌리면, 단계가 안 적힌 지금 세션들에 지금 단계를 먼저 적어 둔다 (섞여 보이지 않게)
        const curStage = c.meta?.stage || null;
        const sessions = (curStage && curStage !== snapStage)
          ? (c.sessions || []).map((x) => (x.stage || x.id === snap._sessionId) ? x : { ...x, stage: curStage })
          : (c.sessions || []);
        const found = snap._sessionId && sessions.find((x) => x.id === snap._sessionId);
        if (found) {
          return { ...c, sessions, meta: { ...c.meta, stage: snapStage }, activeSessionId: found.id };
        }
        const ns = { ...blankSession('보관함에서 복원', snap.assessment?.quarter || 1), stage: snapStage };
        // 새로 만든 아이의 빈 첫 세션은 쓰지 않고 복원 세션만 남긴다
        const keep = target ? sessions : [];
        return { ...c, meta: { ...c.meta, stage: snapStage }, sessions: [...keep, ns], activeSessionId: ns.id };
      });
      return applyWsUpdate({ ...s, children, activeChildId: targetId }, snap);
    });
    setTab('home');
    showToast(`${name}의 보관 자료를 불러왔습니다`);
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
            if (state.children.length > 1 || state.children[0]?.meta?.childName) {  // ★ 아동 0명이어도 멈추지 않게
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
              const isEmptyFirst = !!first && !first.meta?.childName && !first.meta?.stage;
              if (!first) return { ...s, children: [child], activeChildId: child.id };
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
      fresh.meta.therapist = myTherapistName;
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
            const prevLoaded = sharedLoadedRef.current;
            sharedLoadedRef.current = false;
            if (window.storage && authUser?.name) {
              // ★ 내 자료를 못 불러오면 조회 모드를 그대로 둔다 (보던 선생님 자료가 내 계정에 저장되지 않게)
              //   저장 가능 여부도 원래대로 둔다 (처음 불러오기가 실패했던 경우 계속 저장 막음)
              const failBack = () => {
                sharedLoadedRef.current = prevLoaded;
                showToast('내 자료를 불러오지 못했습니다. 인터넷 연결을 확인하고 다시 눌러 주세요');
              };
              try {
                const r = await window.storage.get('gd-aba-state', true);
                if (r && r.error) { failBack(); return; }
                // 보관함도 서버 것으로 다시 받아 둔다 (이 기기의 옛 보관함으로 서버를 덮어쓰지 않게)
                const ar = await window.storage.get('gd-aba-archive', true);
                if (ar && ar.error) { failBack(); return; }
                if (ar?.value) {
                  try { const la = JSON.parse(ar.value); if (Array.isArray(la)) setArchive(la); } catch (e) {}
                }
                let mine = null;
                if (r?.value) { try { mine = JSON.parse(r.value); } catch (e) { mine = null; } }  // 깨진 글은 '자료 없음'으로 (처음 불러오기와 같게)
                loadDoneRef.current = true;  // 처음 불러오기가 아직 다시 시도 중이어도 이 결과가 우선
                if (mine && Array.isArray(mine.children)) {
                  delete mine._viewingTeacher;
                  setState(mine);
                } else if (r?.value) {
                  // 서버 글이 깨진 경우 → 처음 불러올 때와 같게 이 기기에 있던 내 자료로 (조회 중 자료는 이 칸에 저장되지 않음)
                  const local = loadState();
                  delete local._viewingTeacher;
                  setState(local);
                } else {
                  // 내 자료가 아직 하나도 없는 경우 → 빈 상태로 (보던 자료를 가져오지 않음)
                  setState({ children: [], activeChildId: null });
                }
                // 내 자료를 제대로 받아 왔으니 '못 불러옴' 안내를 내리고 저장을 다시 켠다
                setLoadFailed(false);
                setSharedReady(true);
              } catch (e) { failBack(); return; }
            } else {
              setState((s) => { const c = { ...s }; delete c._viewingTeacher; return c; });
            }
            setTimeout(() => { sharedLoadedRef.current = true; }, 100);
            showToast('내 데이터로 돌아왔습니다');
          }}>내 데이터로 돌아가기</button>
        </div>
      )}

      {loadFailed && (
        <div className="viewing-banner no-print">
          <span className="viewing-banner-text">
            ⚠️ 서버에서 내 자료를 불러오지 못했습니다. 지금 화면에서 고친 내용은 저장되지 않습니다. 인터넷 연결을 확인한 뒤 새로고침해 주세요.
          </span>
          <button className="viewing-banner-btn" onClick={() => window.location.reload()}>새로고침</button>
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
            onChosen={async (s) => {
              // ★ 이미 점수가 있는데 단계를 바꾸면: 단계마다 같은 번호라도 문항 내용이 달라 점수가 엉뚱한 문항에 붙음 → 확인
              const prev = ws.meta.stage;
              if (ws._viewingTeacher) { updateMeta({ stage: s }); return; }  // 조회 모드: 읽기 전용 안내만
              const hasScores = (ws._allSessions || []).some((x) => Object.keys(x.scores || {}).length > 0);
              if (prev && prev !== s && hasScores) {
                const ok = await appConfirm(
                  `단계를 ${STAGE_LABELS[prev]}에서 ${STAGE_LABELS[s]}(으)로 바꿉니다.\n\n` +
                  `단계마다 같은 번호라도 문항 내용이 달라서, 지금까지 매긴 점수를 그대로 두면 다른 문항의 점수로 잘못 들어갑니다.\n\n` +
                  `확인을 누르면 지금까지의 진단 세션은 '${STAGE_LABELS[prev]}' 세션으로 따로 보관되고(지워지지 않음), ` +
                  `'${STAGE_LABELS[s]}' 세션만 보입니다. 그 단계 세션이 전에 있었으면 다시 보이고, 없으면 빈 세션을 새로 만듭니다. ` +
                  `사전/사후 비교와 진전 그래프도 같은 단계 세션끼리만 계산됩니다.`);
                if (!ok) return;
              }
              if (prev !== s) switchStage(s);
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
              <SapSummary ws={ws} setWs={setWs} />
            </div>
          </div>
        )}
        {tab === 'family' && (
          <div className="tab-content">
            <div className="card">
              <h2 className="section-title">가족 지원 계획</h2>
              <FamilySupportForm ws={ws} setWs={setWs} />
            </div>
          </div>
        )}
        {tab === 'prof' && (
          <div className="tab-content">
            <div className="card">
              <h2 className="section-title">전문가와 서비스 제공자를 위한 지원 계획</h2>
              <ProfSupportForm ws={ws} setWs={setWs} />
            </div>
          </div>
        )}
        {tab === 'commSchedule' && (
          <div className="tab-content">
            <div className="card">
              <h2 className="section-title">의사소통 일과 분석 <span className="section-optional-tag">센터 양식</span></h2>
              <p className="hint">하루 일과 중 자연스럽게 발생하는 의사소통 기회를 시간대별로 분석합니다.</p>
              <CommunicationScheduleForm ws={ws} setWs={setWs} showToast={showToast} />
            </div>
          </div>
        )}
        {tab === 'fba' && (
          <div className="tab-content">
            <div className="card">
              <h2 className="section-title">도전 행동 기능적 분석 <span className="section-optional-tag">센터 양식</span></h2>
              <p className="hint">행동의 기능과 정서 조절 맥락을 통합 분석하여 대체 행동 중재 계획을 수립합니다.</p>
              <FbaForm ws={ws} setWs={setWs} showToast={showToast} />
            </div>
          </div>
        )}
        {tab === 'archive' && (
          <ArchiveTab
            archive={archive}
            onLoad={loadArchiveItem}
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
            <li><b>사회 의사소통</b> — 공동관심, 상징 사용</li>
            <li><b>정서 조절</b> — 상호조절, 자기조절</li>
            <li><b>교류 지원</b> — 대인관계 지원, 학습 지원</li>
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
          <p>선생님이 활동 일지에 목표별 유의점(시작행동·올바른 반응마다 + 표시, 또는 가장 잘한 행동)을 기록하고, 그 기록으로 주간 기록지에 목표별 0·1·2점을 매깁니다. 활동 계획서에는 하루 활동마다 다룰 목표를 표시합니다(책 1권 267~268쪽). 이 기록은 중간·종결보고서에 인용됩니다.</p>
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
              // ★ 지금 단계의 세션만 센다 (다른 단계로 보관된 세션은 빼고)
              const cs = (c.sessions || []).filter((s) => !s.stage || s.stage === c.meta?.stage);
              const sessionCount = cs.length;
              const preDone = cs.some((s) => s.designation === 'pre');
              const postDone = cs.some((s) => s.designation === 'post');
              const scoredCount = cs.reduce((a, s) => a + Object.keys(s.scores || {}).length, 0);
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
            <button className="btn-primary btn-small" onClick={() => setTab('sap')}>📄 진단 요약지 보기</button>
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
            <h2 className="section-title">진단 요약지</h2>
            <button className="btn-primary btn-small" onClick={() => setTab('sap')}>📄 요약지 보기</button>
          </div>
          <p className="hint">책 진단 요약지(1~5쪽)를 보고 인쇄할 수 있습니다. 진전 추적 차트는 2개 이상의 세션이 필요합니다.</p>
        </section>
      )}

      {/* 협력 계획서 (가족 / 전문가 / 의사소통 일과 / 행동 분석) */}
      {ws.meta.stage && (
        <section className="card">
          <h2 className="section-title">추가 양식 <span className="section-optional-tag">선택</span></h2>
          <p className="hint">필요한 경우에만 작성하세요. 가족·전문가 지원 계획은 책(1권 부록 진단 요약지 5쪽) 양식이고, 의사소통 일과 분석과 도전 행동 분석은 센터 양식(책 양식 아님)입니다.</p>
          <div className="collab-card-grid">
            <button className="collab-card collab-card-recommended" onClick={() => setTab('family')}>
              <div className="collab-card-badge">SCERTS 권장</div>
              <div className="collab-card-icon">👨‍👩‍👧</div>
              <div className="collab-card-title">가족 지원 계획</div>
              <div className="collab-card-desc">교육 지원·정서 지원 — 활동과 얼마나 자주(제공 빈도)</div>
            </button>
            <button className="collab-card" onClick={() => setTab('prof')}>
              <div className="collab-card-icon">🤝</div>
              <div className="collab-card-title">전문가와 서비스 제공자를 위한 지원 계획</div>
              <div className="collab-card-desc">교육 지원·정서 지원 — 활동과 얼마나 자주(제공 빈도)</div>
            </button>
            <button className="collab-card" onClick={() => setTab('commSchedule')}>
              <div className="collab-card-icon">📅</div>
              <div className="collab-card-title">의사소통 일과 분석</div>
              <div className="collab-card-desc">하루 일과별 의사소통 기회·현재 양상·필요 지원 (센터 양식)</div>
            </button>
            <button className="collab-card" onClick={() => setTab('fba')}>
              <div className="collab-card-icon">🔍</div>
              <div className="collab-card-title">도전 행동 분석 (FBA)</div>
              <div className="collab-card-desc">ABC 분석, 기능 가설, 대체 행동 중재 계획 (센터 양식)</div>
            </button>
          </div>
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
function AssessmentTab({ ws, updateScore, setWs, onSavePre, onSavePost,
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
            { id: 'background', label: '📄 기록지 1쪽', desc: '배경 정보·관찰일·프로파일 요약' },
            { id: 'extra', label: '📑 추가 기록지', desc: '책 뒤쪽 기록지 (인쇄용 빈 양식)' },
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
            showToast={showToast}
          />
        )}

        {mode === 'observation' && (
          <AssessObservationView ws={ws} setWs={setWs} />
        )}

        {mode === 'extra' && <AssessExtraSheetsView ws={ws} />}

        {mode === 'background' && (
          <AssessBackgroundView ws={ws} setWs={setWs} stageData={stageData} />
        )}
      </div>
    </div>
  );
}

// ── 채점 뷰 ──────────────────────────────────────────────────────
function AssessScoreView({
  ws, setWs, stageData, domain, domainTotals, activeDomain, setActiveDomain,
  updateScore, showToast,
}) {
  // ★ 문항 아래 체크칸(□) — 책의 '=' 같은 문항에 같은 체크칸이 있으면 함께 체크
  const toggleSub = (itemId, sub, on) => setWs((s) => {
    const all = { ...(s.assessment.subChecks || {}) };
    const ids = [itemId, ...getEquivalentItems(s.meta.stage, itemId)];
    ids.forEach((id) => {
      const subs = BOOK_ITEM_MARKS[s.meta.stage]?.[id]?.subs || [];
      const same = subs.find((x) => x === sub) || subs.find((x) => x.replace(/을 /g, ' ') === sub.replace(/을 /g, ' '));
      if (!same) return;
      const cur = { ...(all[id] || {}) };
      if (on) cur[same] = true; else delete cur[same];
      if (Object.keys(cur).length) all[id] = cur; else delete all[id];
    });
    return { ...s, assessment: { ...s.assessment, subChecks: all } };
  });
  const setSubOther = (itemId, text) => setWs((s) => {
    const all = { ...(s.assessment.subChecks || {}) };
    const cur = { ...(all[itemId] || {}) };
    if (text) cur['기타_내용'] = text; else delete cur['기타_내용'];
    if (Object.keys(cur).length) all[itemId] = cur; else delete all[itemId];
    return { ...s, assessment: { ...s.assessment, subChecks: all } };
  });
  // ★ 주간 기록지 기반 진단 점수 제안 — 책: 분기별 재진단은 주간 기록지·새 관찰·행동 표집 정보로 갱신(1권 269쪽)
  //   진단 날짜 이전에 기록한 주만 보고, 2주 이상 기록된 목표에 '가장 최근 주 점수'를 제안한다(적용은 선생님이)
  const suggestions = useMemo(() => {
    const sessionDate = (ws._allSessions || []).find((s) => s.id === ws._sessionId)?.date;
    const result = {};
    weeklyGoalRows(ws).forEach((r) => {
      if (!r.id || r.group !== 'child') return;
      const hist = weeklyHistory(ws, r.key).filter((h) => !sessionDate || !h.date || h.date <= sessionDate);
      if (hist.length < 2) return;
      const recent = hist.slice(-3);
      const suggested = recent[recent.length - 1].score;
      result[r.id] = { suggested, reason: `주간 기록지 최근 ${recent.length}주: ${recent.map((h) => h.score).join('·')} → 최근 주 ${suggested}점`, count: hist.length };
    });
    return result;
  }, [ws.activities, ws.iep, ws._sessionId, ws._allSessions]);

  // 적용 가능한 (현재 점수와 다른) 제안만 카운트
  const applicableSuggestions = useMemo(() => {
    return Object.entries(suggestions).filter(([id, sug]) => {
      const cur = ws.assessment.scores[id];
      return cur !== sug.suggested;
    });
  }, [suggestions, ws.assessment.scores]);

  const applyAllSuggestions = async () => {
    if (applicableSuggestions.length === 0) return;
    const msg = `주간 기록지에서 ${applicableSuggestions.length}개 항목의 점수가 제안되었습니다.\n\n예시:\n` +
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
      {/* 주간 기록지 기반 제안 (있을 때만) */}
      {applicableSuggestions.length > 0 && (
        <div className="session-suggestion-bar">
          <div className="ss-info">
            <span className="ss-icon">💡</span>
            <div>
              <strong>{applicableSuggestions.length}개 항목 점수 제안 가능</strong>
              <div className="ss-hint">주간 기록지의 최근 주 점수를 보여 주는 제안입니다. 현재 점수와 다른 항목만 표시되며, 미채점 항목에만 자동 적용됩니다.</div>
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
        {scoringLegendFor(ws.meta.stage).map((l) => (
          <div key={l.score} className="legend-item">
            <span className={`legend-score score-${l.score}`}>{l.score}</span>
            <span className="legend-label">{l.desc}</span>
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
          <div className="domain-detail-score">점수 {domainTotals[activeDomain]} / {domain.maxScore}</div>
        </div>
        {domain.groups.map((group) => (
          <div key={group.title} className="score-group">
            <h4 className="score-group-title">{group.title}</h4>
            {group.items.map((item) => {
              const v = ws.assessment.scores[item.id];
              const hasWarning = false;  // ★ 선행 문항 경고는 책에 없어 표시하지 않음
              const mark = BOOK_ITEM_MARKS[ws.meta.stage]?.[item.id];
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
                    {mark?.rel && (
                      <span className="equivalent-badge" title={equivalents.length > 0 ? `책의 같은 문항(=): ${equivalents.join(', ')} — 한쪽을 채점하면 같은 점수로 함께 바뀝니다` : '책에 적힌 관계 표시: = 같은 문항, ≈ 비슷한 문항, ↔ 관련 문항'}>
                        {mark.rel}
                      </span>
                    )}
                    {!mark?.rel && equivalents.length > 0 && (
                      <span className="equivalent-badge" title={`책의 같은 문항(=): ${equivalents.join(', ')}`}>
                        (= {equivalents.join(', ')})
                      </span>
                    )}
                    {mark?.subs && (
                      <span className="score-subs">
                        {mark.subs.map((sub) => {
                          const cur = ws.assessment.subChecks?.[item.id] || {};
                          const isOther = /기타$/.test(sub);
                          return (
                            <label key={sub} className="score-sub">
                              <input type="checkbox" checked={!!cur[sub]} onChange={(e) => toggleSub(item.id, sub, e.target.checked)} />
                              {sub}
                              {isOther && (
                                <input type="text" className="score-sub-other" value={cur['기타_내용'] || ''}
                                  onChange={(e) => setSubOther(item.id, e.target.value)} aria-label={`${item.id} 기타 내용`} />
                              )}
                            </label>
                          );
                        })}
                      </span>
                    )}
                    {hasSuggestion && (
                      <button
                        className="session-suggestion-chip"
                        onClick={() => updateScore(item.id, sug.suggested)}
                        title={sug.reason}
                      >
                        💡 주간 기록지 {sug.suggested}점 제안
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

      {/* 사회-정서 성장 지표 — ★ 문항 점수로 자동 계산 (1권 표 7-5, 265쪽) */}
      <div className="ses-section">
        <h3>사회-정서 성장 지표 (0~10)</h3>
        <p className="hint" style={{ marginBottom: 14 }}>
          지표마다 정해진 교수목표 5개의 점수를 더한 값입니다(1권 표 7-5). 문항 점수를 넣으면 자동으로 바뀝니다.
          5점 이상은 상대적 강점, 5점 미만은 상대적 요구입니다.
        </p>
        {(() => {
          const calc = computeSes(ws.meta.stage, ws.assessment.scores);
          return SES_INDICATORS.map((ind) => {
            const v = calc ? calc.values[ind.id] : (ws.assessment.ses[ind.id] ?? 0);
            const det = calc ? calc.detail[ind.id] : null;
            const range = SES_INTERPRETATION.ranges.find((r) => v >= r.min && v <= r.max);
            const parts = det ? det.parts : (SES_ITEMS[ws.meta.stage]?.[ind.id] || []).map((id) => ({ id, score: null }));
            return (
              <div key={ind.id} className="ses-row ses-row-calc">
                <span className="ses-label">{ind.label}</span>
                <span className="ses-formula">
                  {parts.map((p, i) => (
                    <span key={p.id}>{i > 0 ? ' + ' : ''}{p.id}({p.score === null ? '–' : p.score})</span>
                  ))}
                  {det && det.unscored > 0 && <span className="ses-unscored"> · {det.unscored}문항 미채점</span>}
                  {!calc && Object.keys(ws.assessment.ses || {}).length > 0 && <span className="ses-unscored"> · 문항 점수가 없어 예전에 정해 둔 값</span>}
                </span>
                <span className="ses-value" style={{ color: range?.color }}>
                  {v}/10 · {range?.label}
                </span>
              </div>
            );
          });
        })()}
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
        SCERTS는 <em>"준거에 일관성 있게 도달(두 가지 상황에서 {partnerCountWord(ws.meta.stage)} 명의 파트너에 걸쳐 나타남)"</em>해야 2점을 줍니다(1권 484쪽 점수 산출 기준).
        그래서 진단 전에 관찰 환경을 다양하게 계획해야 정확한 채점이 가능합니다.
        최소 2개 자연스러운 상황(예: 가정 + 어린이집)에서, 친숙/비친숙 파트너를 포함해 관찰하세요.
      </div>

      <div className="no-print" style={{ textAlign: 'right', marginBottom: 12 }}>
        <button className="btn-primary" onClick={printReport}>📄 관찰 계획서 인쇄</button>
      </div>

      <div id="printable-report" className="printable">
        <ReportHeader title="SCERTS 관찰 계획서" ws={ws} />

        <section className="report-section">
          {OBSERVATION_MAP.intro && <p className="hint">{OBSERVATION_MAP.intro}</p>}
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
// ★ 1권 부록 진단-관찰 기록지 뒤쪽의 추가 기록지 (책 글자 그대로, 인쇄해서 손으로 기록하는 빈 양식)
//   사회적 파트너 (8)쪽 429 / 언어 파트너 (8)~(11)쪽 448~451 / 대화 파트너 (8)~(13)쪽 471~476
const INTENT_MEANS = {
  pre: ['근접성', '응시(시선 옮기기)', '얼굴 표정', '간단한 동작', '울기/징징거리기', '탠트럼', '공격 행동', '자해 행동', '물건 건네주기', '손 뻗기', '밀어내기', '가리키기', '보여 주기', '손 흔들기', '고개 젓기', '고개 끄덕이기', '재연', '차별화된 발성', '다양한 자음과 모음 사용', '기타'],
  sym: ['즉각 반향어', '지연 반향어', '한 단어(구어)', '창의적인 단어 조합', '수어', '그림 체계', '기타'],
};
const INTENT_ROWS = (mr) => [
  { head: '의사소통 의도', center: true },
  { head: '행동조절' },
  { label: 'JA4.1 원하는 음식이나 물건 요구하기' },
  { label: 'JA4.2 원하지 않는 음식이나 물건 거부/거절하기' },
  { label: 'JA4.3 도움 또는 기타 행동 요구하기' },
  { label: 'JA4.4 원하지 않는 행동이나 활동 거부하기' },
  { head: '사회적 상호작용' },
  { label: 'JA5.1 위로 구하기' },
  { label: 'JA5.2 사회적 게임 요구하기' },
  { label: 'JA5.3 차례 주고받기' },
  { label: 'JA5.4 인사하기' },
  { label: 'JA5.5 부르기' },
  { label: 'JA5.6 자랑하기' },
  { head: '공동관심' },
  { label: 'JA6.1 사물에 대해 언급하기' },
  { label: 'JA6.2 행동이나 사건에 대해 언급하기' },
  { head: '정서 표현', center: true },
  { label: `${mr ? 'MR1.1 ' : ''}기쁨 표현하기` },
  { label: `${mr ? 'MR1.2 ' : ''}슬픔 표현하기` },
  { label: `${mr ? 'MR1.3 ' : ''}분노 표현하기` },
  { label: `${mr ? 'MR1.4 ' : ''}두려움 표현하기` },
];
const BOX = (n) => '□'.repeat(n);
const WORD_MEANING_ROWS = [
  { head: '초기 관계어' },
  { use: 1, form: '존재', def: ['어떤 것의 존재를 인식하거나 그것으로 주의를 돌리게 함(예: 이거, 저거, 여기, 그거 뭐야?)'] },
  { use: 1, form: '부재/사라짐', def: ['기대하는 무엇인가가 거기에 없거나 거기에 있었던 무엇인가가 사라진 것을 인식함(예: 없다, 사라졌다, 하나도 없다, 바이바이)'] },
  { use: 1, form: '재출현', def: ['사라진 대상 또는 대체할 대상을 요구하거나 대상이 사라진 후에 다시 나타났다는 것을 인식함(예: 더, 다시, 또)'] },
  { use: 1, form: '거부', def: ['제공된 무엇인가를 거절함(예: 아니, 바이바이, 그만)'] },
  { head: '사물이나 사람에 대한 이름' },
  { use: 10, form: '사물', def: ['행위의 대상이 되는 개체 또는 물건(예: 우유, 주스, 물, 과자, 컵, 병, 공, 차, 모자, 신발)'] },
  { use: 3, form: '신체부위', def: ['신체부위(예: 눈, 코, 손, 배)'] },
  { use: 3, form: '행위자', def: ['행위의 주체인 사람이나 동물(예: 엄마, 아빠, 아기, 멍멍이, 야옹이)'] },
  { head: '상위 수준 관계어' },
  { use: 2, form: '개인적-사회적', def: ['누군가를 인지하는 단어(예: 안녕, 바이바이, 제발, 고마워)'] },
  { use: 5, form: '행위', def: ['대상을 포함하거나 포함하지 않은 일반적인 또는 특정 행위를 설명하는 단어',
    '••특정 행위를 의미하는 것이 아닌 일반적인 목적의 행위 단어(예: 하다, 두다, 만들다, 얻다, 원하다, 주다, 가버리다)',
    '••청자의 주의를 끌기 위해 지시하는 행위 단어(예: 이거 봐, 보다)',
    '••특정 행위를 언급하는 대상 관련 행위 단어(예: 밀다, 열다, 먹다, 마시다, 던지다, 뽀뽀하다, 점프하다)',
    '••대상을 포함하지 않은 자동사적인 행위 단어(예: 걷다, 뛰다, 자다, 웃다)'] },
  { page: 10 },
  { use: 5, form: '수식어', def: ['어떤 것의 상태, 특성, 관계를 기술하는 단어',
    '••속성: 어떤 것의 특성이나 둘 간의 차이를 설명함(예: 뜨거운, 큰, 냄새나는, 더러운)',
    '••소유: 행위자가 무엇인가를 가지고 있다는 것을 인식함(예: 내 거, 엄마 거)',
    '••장소: 방향을 나타내거나 둘 간의 공간 관계를 나타냄(초기 장소 단어는 위로, 밖에, 밖으로 등과 같이 행위 단어로 기능하며 장소를 나타내는 처소격으로 사용됨)(예: 위로, 위에, 밖으로, 안에, 밖에, 밑에)',
    '••부인: 어떤 것의 존재를 부인함(예: 아니, 안)'] },
  { use: 2, form: '의문사', def: ['어떤 것의 이름이나 장소에 대한 질문을 나타내는 단어(초기 질문은 상승 억양을 함께 사용하기도 함)(예: 무엇, 어디)'] },
];
const RELATION_ROWS = [
  { head: '초기 관계어' },
  { use: 5, form: '수식어+대상' },
  { sub: '재출현+대상', ex: '과자 더, 또 뛰어' },
  { sub: '속성+대상', ex: '큰 신발, 더러운 기저귀, 한 아기, 귀여운 고양이' },
  { sub: '소유자+소유물', ex: '엄마 신발, 아빠 머리, 내 컵' },
  { sub: '지시+대상', ex: '이 컵, 이 공' },
  { sub: '장소+대상', ex: '책상 위에, 상자 안에' },
  { use: 5, form: '부정어+대상' },
  { sub: '부재', ex: '주스 없어, 물 없어' },
  { sub: '사라짐', ex: '비눗방울 안녕, 우유 다 먹었어' },
  { sub: '거부', ex: '안 잘래' },
  { sub: '부인', ex: '아기 아니야, 신발 아니야' },
  { use: 5, form: '행위자+행위+대상' },
  { sub: '행위 + 대상', ex: '과자 먹어, 공 던져, 주스 마셔, 저거 봐, 나 안아줘, 탁자에 놔, 옷 벗어' },
  { sub: '행위자 + 행위', ex: '엄마 바이바이 가, 아기 자, 아빠 던져, 강아지 앉아' },
  { sub: '행위자 + 대상', ex: '아빠 과자, 엄마 병, 강아지 공, 인형 의자' },
  { sub: '행위자+행위+대상', ex: '아빠 공 던져, 아빠 차 밀어, 엄마 아기 뽀뽀, 엄마 병 들어' },
];
const CONV_RULE_ROWS = [
  { head: '대화 의도: 생각을 표현하는 방법 알기', center: true },
  { head: '다른 사람의 행동을 조절하기 위해 의도 공유하기' },
  { label: 'JA3.1a 원하는 사물이나 활동 요구하기' },
  { label: 'JA3.1b 도움 청하기' },
  { label: 'JA3.1c 휴식 요구하기' },
  { label: 'JA3.1d 원하지 않는 사물이나 활동 거절/거부하기' },
  { head: '사회적 상호작용을 위해 의도 공유하기' },
  { label: 'JA3.2a 인사하기' },
  { label: 'JA3.2b 부르기' },
  { label: 'JA3.2c 위로 구하기' },
  { label: 'JA3.2d 차례 조절하기' },
  { label: 'JA3.2e 허락 구하기' },
  { label: 'JA3.2f 파트너 칭찬하기' },
  { label: 'JA3.2g 공감 표현하기' },
  { label: 'JA3.2h 비밀 공유하기' },
  { head: '공동관심을 위해 의도 공유하기' },
  { label: 'JA3.3a 현재, 과거, 상상의 사건에 대해 언급하기' },
  { label: 'JA3.3b 현재 또는 과거 사건에 대해 요구된 정보 제공하기' },
  { label: 'JA3.3c 현재, 과거, 미래 사건에 대한 정보 요구하기' },
  { label: 'JA3.3d 기분이나 의견 표현하기' },
  { label: 'JA3.3e 결과 예상하고 계획하기' },
  { head: '가정: 어떤 지식이 공유되는지 알기', center: true },
  { label: 'JA1.4 파트너가 보거나 들은 것을 기초로 언어 수정하기' },
  { label: 'JA1.5 파트너와 내적 사고나 정신적 계획 공유하기' },
  { label: 'JA4.5 대화 주제에 대해 파트너가 알고 있는 지식을 기초로 필요한 정보 제공하기' },
  { label: 'JA4.6a 파트너에 따라 대화 차례의 길이 판단하기' },
  { head: '대화 규칙: 게임하는 방법 알기', center: true },
  { head: '상호성: 정보의 흐름 및 관련성' },
  { label: 'JA4.1 경험을 공유하기 위해 청자 및 화자의 역할을 바꾸어 가며 상호작용하기' },
  { label: 'JA4.2 다양한 대화 주제 시작하기' },
  { label: 'JA4.3 파트너의 관심에 맞게 대화를 시작하고 유지하기' },
  { label: 'JA4.4 관련된 정보를 요구하거나 제공하여 상호작용 유지하기' },
  { label: '파트너에 따라 대화 차례의 길이 판단하기' },
  { page: 9 },
  { head: '전략 수정하기: 지속하기' },
  { label: 'JA5.2 의사소통 실패를 복구하기 위해 반복하거나 수정하기' },
  { label: 'JA5.3 의사소통 실패를 인식하고 명료화 요구하기' },
  { label: 'JA5.4 파트너의 의견 변화에 따라 언어 및 행동 수정하기' },
  { label: 'JA5.5 파트너의 정서 반응에 따라 언어 및 행동 수정하기' },
  { label: 'JA5.6 상호작용 중에 성취감 및 자신감 표현하기' },
  { head: '관습: 전달 방법' },
  { label: 'SU4.1 맥락과 파트너에 맞게 적절한 얼굴 표정 사용하기' },
  { label: 'SU4.2 맥락과 파트너에 맞게 적절한 몸짓 사용하기' },
  { label: 'SU4.3 맥락과 파트너에 맞게 적절한 자세 및 근접성 사용하기' },
  { label: 'SU4.4 맥락과 파트너에 맞는 목소리 크기와 억양 사용하기' },
  { label: 'SU6.1 관습에 따라 대화 시작하고 차례 주고받기' },
  { label: 'SU6.2 관습에 따라 대화 주제 전환하기' },
  { label: 'SU6.3 관습에 따라 대화 종료하기' },
  { label: 'SU6.4 예의범절에 대한 관습 따르고 표현하기' },
];
const EMOTION_COLS = ['정서 단어 이해하기', '정서 단어 사용하기', '다른 사람의 정서 상태 묘사하기', '정서를 표현하는 비구어 단서 사용하기', '단계적인 정서 이해하고 사용하기', '정서를 표현하는 비구어 단서 이해하기', '자신 및 다른 사람의 정서에 대한 타당한 원인 요소 설명하기'];
const EMOTION_ROWS = [
  { head: '초기 정서 단어', center: true },
  { head: '긍정적 정서' }, ...['기쁜', '익살스러운', '재미있는', '좋은'].map((label) => ({ label })),
  { head: '부정적 정서' }, ...['화난', '분노한', '슬픈', '아픈', '피곤한'].map((label) => ({ label })),
  { head: '상위 수준 정서 단어', center: true },
  { head: '긍정적 정서' }, ...['만족스러운', '희망적인', '신나는', '자랑스러운', '즐거운', '흥미로운'].map((label) => ({ label })),
  { head: '부정적 정서' }, ...['좌절스러운', '무서운', '걱정되는', '지루한', '스트레스 받는', '공포스러운', '당황스러운', '죄책감 느끼는', '질투 나는'].map((label) => ({ label })),
];
const LANG_ELEMENT_ROWS = [
  { head: '상위 수준 관계 의미' },
  { use: 5, form: '의문사', ex: ['무엇, 어디, 누구, 누구의, 어느 것, 언제, 어떻게, 왜'] },
  { use: 5, form: '시간 관계', ex: ['지금, 나중에, 전에, 후에, 그때부터, 그때, 그때까지, 금방, 하루 사이, 1주일 뒤, 한동안'] },
  { use: 5, form: '물리적 관계', ex: ['색깔, 형태, 딱딱한/부드러운, 큰/작은, 무거운/가벼운, 긴/짧은, 두꺼운/얇은'] },
  { use: 5, form: '수 관계', ex: ['숫자, 적은, 약간, 많은, 더/덜'] },
  { use: 5, form: '장소 어휘', ex: ['안에, 위에, 아래에, 옆에, 뒤에, 앞에, ~보다 위에, ~보다 아래에, 왼쪽/오른쪽'] },
  { use: 5, form: '친족 어휘', ex: ['엄마, 아빠, 동생, 형, 아들, 딸, 할머니, 할아버지, 이(고)모, 삼촌, 사촌, 조카'] },
  { use: 5, form: '원인 어휘', ex: ['그러나, 그래서, 왜냐하면, 만일, 그렇지 않으면'] },
  { head: '참조: 의도된 참조를 찾도록 도와주기' },
  { use: 5, form: '주격 대명사', ex: ['나/너, 그/그녀, 그것, 우리/그들'] },
  { use: 5, form: '기타 대명사', subs: [['•목적어', '나를/너를, 그를/그녀를, 그것을, 우리를, 그들을'], ['•소유격', '너의/나의, 너의 것/나의 것, 그의/그녀의, 우리의, 그들의'], ['•부정사', '누군가, 어떤, 아무도, 모든, 모두, 많은, 매우, 어떤 것, 아무것도, 어느 것, 모든 것'], ['•지시대명사', '이것, 저것, 이것들, 저것들']] },
  { use: 5, form: '관사', ex: ['정관사(the), 부정관사(a)'] },
  { use: 5, form: '복수', ex: ['고양이들, 과자들, 소들, 양들'] },
  { head: '동사구: 사건의 시간과 태도를 명확히 하는 데 도움주기' },
  { use: 5, form: '본동사', subs: [['•상태 변경', '열다, 부수다, 멈추다, 찾다, 떨어뜨리다, 죽다'], ['•활동', '달리다, 미소짓다, 점프하다, 핥다, 그리다, 보다, 잡다'], ['•지속적 상태', '되다, 갖다, 사랑하다'], ['•정신적 상태', '생각하다, 알다, 추측하다, 기억하다, 바라다, 내기하다, 바라다, 느끼다']] },
  { page: 12 },
  { use: 5, form: '시제', subs: [['•현재 진행형', '걷고 있다, 가고 있다, 달리고 있다'], ['•3인칭', '짖다, 치다, 달리다, 가다, 하다, 갖다'], ['•과거 시제', '떨어졌다, 쏟았다, 부셔졌다, 왔다, 가져왔다, ~였다, 가졌다, 했다'], ['•미래 시제', '~할 것이다, 할 수 있다, 아마도, 반드시, ∼하고 싶다, ∼할 것이다, ∼해야 한다']] },
  { use: 5, form: '조동사', ex: ['has, have, had, do, does, did, am, is, are, was, were, been'] },
  { use: 5, form: '법조동사', subs: [['•초기', '∼하고 싶다, ∼할 것이다, ∼해야 한다'], ['•상위수준', '∼일 것이다, ∼이었을 것이다, ∼할 수 있다, ∼할 수 있었다, ∼할 것이다, 했을 것이다, ∼해야 한다']] },
  { use: 5, form: '부정어', ex: ['아니, 아니다, 아닐 것이다, ∼할 수 없다, ∼하지 않는다, 아니었다, 아니었을 것이다.'] },
];
const SENTENCE_ROWS = [
  { use: 5, form: '능동형 평서문', ex: ['나는 휴식이 필요해.', '소년이 자전거를 타고 있다.', '그는 새 차를 갖고 있다.'] },
  { use: 5, form: '명령문', ex: ['지금 밖으로 나가.', '장난감 들어.', '이거 집에 가져가서 엄마께 드려.'] },
  { use: 5, form: '부정문', ex: ['몰라요.', '나는 완두콩을 원하지 않아요.', '나 그거 못해요.'] },
  { use: 5, form: '의문문', subs: [['•예/아니요 질문', '도와줄래?\n이 병을 열어 줄래?\n준수가 공을 찼니?'], ['•wh-질문', '그 집에 누가 있니?\n너는 뭘 생각하니?\n어떤 게 맞아?\n우리가 언제 다 했지?\n왜 집에 가니?']] },
  { use: 5, form: '삽입문', subs: [['•전치사구', '새가 새장 안에 있다.\n개가 침대 위에 있다.'], ['•부정사구', '나는 밖에 가고 싶어.\n나는 화장실에 가야 해.'], ['•목적격 명사구', '내가 먼저 가야 한다고 생각해.\n너도 조금 갖고 있다고 생각해.\n여기 빙글빙글 도는 놀잇감이 있어.'], ['•주격 명사구', '옆집에 사는 아이가 저녁 먹으러 온다.\n풍선 파는 사람이 아이에게 풍선 한 개를 팔았다.']] },
  { use: 5, form: '복합문', ex: ['어린 소년이 있고, 그 소년은 집으로 뛰어가고 있다.', '소년이 넘어져서 울고 있다.', '저녁을 다 먹으면 디저트를 먹을 것이다.', '하지만 네가 괜찮다고 했으니까 내가 좀 가져야겠어.', '내 일을 다 하고 나면 밖에 나가서 놀 거야.'] },
];
const EXTRA_SHEETS = {
  social: [{ id: 'intent', title: '의도 및 정서 표현 기록지', page: 8, kind: 'intent', mr: true }],
  language: [
    { id: 'intent', title: '의도 및 정서 표현 기록지', page: 8, kind: 'intent', mr: false },
    { id: 'word', title: '단어 의미 기록지', page: 9, kind: 'word' },
    { id: 'relation', title: '단어 조합 내 관계적 의미 기록지', page: 11, kind: 'relation' },
  ],
  conversation: [
    { id: 'rules', title: '의도, 가정, 대화 규칙 기록지', page: 8, kind: 'rules' },
    { id: 'emotion', title: '정서표현 및 이해 기록지', page: 10, kind: 'emotion' },
    { id: 'element', title: '언어 요소 기록지', page: 11, kind: 'element', source: '출처: Owens (2000); Tomasello (2003).' },
    { id: 'sentence', title: '문장 구조 기록지', page: 13, kind: 'sentence', source: '출처: Owens (2000).' },
  ],
};

function ExtraSheetHeadRow({ ws, sheet, pageNo }) {
  return (
    <div className="xs-head">
      <span className="xs-stage">{STAGE_PROFILE[ws.meta.stage]?.headline.replace(/ 단계$/, '')}</span>
      <strong>SCERTS 진단-관찰 기록지</strong>
      <span className="xs-name">{sheet.title}</span>
      <span className="xs-no">({pageNo})</span>
    </div>
  );
}
function ExtraSheetMeta({ ws }) {
  return (
    <div className="xs-meta">
      <span>이름: <u>{ws.meta.childName || ' '.repeat(20)}</u></span>
      <span>날짜: <u>{' '.repeat(24)}</u></span>
      <span>상황/활동: <u>{' '.repeat(30)}</u></span>
      <span>파트너: <u>{' '.repeat(24)}</u></span>
    </div>
  );
}
function ExtraSheet({ ws, sheet }) {
  const pages = [];   // 책 쪽 나눔대로 쪼갠다
  const split = (rows) => { const out = [[]]; rows.forEach((r) => { if (r.page) out.push([]); else out[out.length - 1].push(r); }); return out; };
  const pageStart = (i, nodes) => (
    <section key={i} className={`xs-page ${i > 0 ? 'page-break-before' : ''}`}>
      {i === 0 ? <><ExtraSheetHeadRow ws={ws} sheet={sheet} pageNo={sheet.page} /><ExtraSheetMeta ws={ws} /></> : <div className="xs-cont">({sheet.page + i})</div>}
      {nodes}
    </section>
  );
  const sitPartner = (n) => (
    <>
      {[0, 1].map((k) => <td key={'s' + k} className="xs-tick" />)}
      {[0, 1, 2].map((k) => <td key={'p' + k} className="xs-tick" />)}
      {Array.from({ length: n }).map((_, k) => <td key={'c' + k} />)}
    </>
  );
  if (sheet.kind === 'intent') {
    const cols = [...INTENT_MEANS.pre, ...INTENT_MEANS.sym];
    const rows = INTENT_ROWS(sheet.mr);
    pages.push(pageStart(0, (
      <table className="report-table xs-table xs-intent">
        <thead>
          <tr><th rowSpan={3} className="xs-label-col" /><th colSpan={cols.length}>의사소통 수단</th></tr>
          <tr><th colSpan={INTENT_MEANS.pre.length}>상징전 수단</th><th colSpan={INTENT_MEANS.sym.length}>상징 수단</th></tr>
          <tr>{cols.map((c, i) => <th key={i} className="xs-vert"><span>{c}</span></th>)}</tr>
        </thead>
        <tbody>
          {rows.map((r, i) => r.head
            ? <tr key={i}><td colSpan={cols.length + 1} className={r.center ? 'xs-center' : 'xs-sub'}>{r.head}</td></tr>
            : <tr key={i}><td className="xs-label-col">{r.label}</td>{cols.map((_, k) => <td key={k} />)}</tr>)}
        </tbody>
      </table>
    )));
  } else if (sheet.kind === 'rules' || sheet.kind === 'emotion') {
    const isEmo = sheet.kind === 'emotion';
    const nCols = isEmo ? EMOTION_COLS.length : 0;
    split(isEmo ? EMOTION_ROWS : CONV_RULE_ROWS).forEach((rows, pi) => {
      pages.push(pageStart(pi, (
        <table className="report-table xs-table">
          <thead>
            {isEmo && pi === 0 && (
              <tr><th colSpan={5} className="xs-blank" /><th className="xs-blank" />{EMOTION_COLS.map((c) => <th key={c} className="xs-emo-col">{c}</th>)}</tr>
            )}
            {pi === 0 && <tr><th colSpan={2}>상황</th><th colSpan={3}>파트너</th><th className="xs-blank" />{isEmo && <th colSpan={nCols} className="xs-blank" />}</tr>}
            {pi === 0 && <tr>{[1, 2, 1, 2, 3].map((n, k) => <th key={k} className="xs-tick">{n}</th>)}<th className="xs-blank" />{isEmo && <th colSpan={nCols} className="xs-blank" />}</tr>}
          </thead>
          <tbody>
            {rows.map((r, i) => r.head
              ? <tr key={i}><td colSpan={5} className="xs-tick-blank" /><td colSpan={1 + nCols} className={r.center ? 'xs-center' : 'xs-sub'}>{r.head}</td></tr>
              : <tr key={i}>{sitPartner(0)}<td className="xs-label-col">{r.label}</td>{Array.from({ length: nCols }).map((_, k) => <td key={k} />)}</tr>)}
          </tbody>
        </table>
      )));
    });
  } else {
    // 관찰내용(사용) □ — 형태 — 정의/예 — (이해) □
    const conf = {
      word: { rows: WORD_MEANING_ROWS, h: ['관찰내용\n(사용)', '형태', '정의 및 예', '관찰내용\n(이해)'], both: true },
      relation: { rows: RELATION_ROWS, h: ['관찰내용\n(사용)', '관계적 의미', '예', '관찰내용\n(이해)'], both: true },
      element: { rows: LANG_ELEMENT_ROWS, h: ['관찰내용\n(사용)', '문장 형태', '예'], both: false },
      sentence: { rows: SENTENCE_ROWS, h: ['관찰내용\n(사용)', '문장 형태', '예'], both: false },
    }[sheet.kind];
    const nc = conf.both ? 4 : 3;
    const boxes = (n) => (n ? <span className="xs-boxes">{BOX(Math.min(n, 5))}{n > 5 ? <><br />{BOX(n - 5)}</> : null}</span> : null);
    split(conf.rows).forEach((rows, pi) => {
      pages.push(pageStart(pi, (
        <table className="report-table xs-table xs-list" style={{ tableLayout: 'fixed', width: '100%' }}>
          <colgroup><col style={{ width: 80 }} /><col style={{ width: conf.both ? 110 : 130 }} /><col />{conf.both && <col style={{ width: 80 }} />}</colgroup>
          {pi === 0 && <thead><tr>{conf.h.map((h) => <th key={h} style={{ whiteSpace: 'pre-line' }}>{h}</th>)}</tr></thead>}
          <tbody>
            {rows.map((r, i) => {
              if (r.head) return <tr key={i}><td className="xs-boxcol" /><td colSpan={nc - 1} className="xs-sub">{r.head}</td></tr>;
              if (r.sub) return <tr key={i}><td className="xs-boxcol" /><td className="xs-indent">{r.sub}</td><td>{r.ex}</td>{conf.both && <td className="xs-boxcol" />}</tr>;
              if (r.subs) return (
                <React.Fragment key={i}>
                  <tr><td className="xs-boxcol">{boxes(r.use)}</td><td>{r.form}</td><td>{r.def ? r.def[0] : ''}</td>{conf.both && <td className="xs-boxcol">{boxes(r.use)}</td>}</tr>
                  {r.subs.map(([a, b]) => <tr key={a}><td className="xs-boxcol" /><td className="xs-indent">{a}</td><td style={{ whiteSpace: 'pre-line' }}>{b}</td>{conf.both && <td className="xs-boxcol" />}</tr>)}
                </React.Fragment>
              );
              return (
                <tr key={i}>
                  <td className="xs-boxcol">{boxes(r.use)}</td>
                  <td>{r.form}</td>
                  <td>{(r.def || r.ex || []).map((t, k) => <div key={k} className={t.startsWith('••') ? 'xs-indent' : ''}>{t}</div>)}</td>
                  {conf.both && <td className="xs-boxcol">{boxes(r.use)}</td>}
                </tr>
              );
            })}
          </tbody>
        </table>
      )));
    });
    if (sheet.source) pages.push(<div key="src" className="xs-source">{sheet.source}</div>);
  }
  return <>{pages}</>;
}

function AssessExtraSheetsView({ ws }) {
  const list = EXTRA_SHEETS[ws.meta.stage] || [];
  const [pick, setPick] = useState(list[0]?.id || '');
  const sheet = list.find((x) => x.id === pick) || list[0];
  if (!sheet) return <div className="empty-hint" style={{ padding: 24 }}>단계가 결정되어야 추가 기록지를 볼 수 있습니다.</div>;
  return (
    <div className="observation-inner">
      <div className="info-box no-print">
        1권 부록 진단-관찰 기록지 뒤쪽의 추가 기록지입니다. 책 양식 그대로의 빈 양식이라 인쇄해서 관찰하면서 손으로 기록합니다.
      </div>
      <div className="no-print xs-pick">
        {list.map((x) => (
          <button key={x.id} className={`activity-nav-btn ${x.id === sheet.id ? 'active' : ''}`} onClick={() => setPick(x.id)}>{x.title}</button>
        ))}
        <button className="btn-primary" style={{ marginLeft: 'auto' }} onClick={printReport}>📄 빈 양식 인쇄</button>
      </div>
      <div id="printable-report" className="printable xs-sheet">
        <ExtraSheet ws={ws} sheet={sheet} />
      </div>
    </div>
  );
}

// ★ SCERTS 진단-관찰 기록지 1쪽 (1권 부록 422·441·461쪽) — 배경 정보·관찰 상황·관찰일·프로파일 요약·성장 지표
const OBS_BG_VARIABLES = ['1. 구조화된/비구조화된', '2. 의무적인/재미있는', '3. 성인 주도의/아동 주도의', '4. 동적인/정적인', '5. 익숙한/익숙하지 않은', '6. 선호하는/선호하지 않는', '7. 쉬운/어려운', '8. 언어 중심의/비언어적인', '9. 사회적인/혼자 하는', '10. 붐비는/차분한'];
const OBS_BG_ROWS = [
  { key: 'group', title: '집단 크기', boxes: [['oneToOne', '일대일'], ['small', '소집단'], ['large', '대집단']] },
  { key: 'partner', title: '파트너', boxes: [['famAdult', '친숙한 성인'], ['famPeer', '친숙한 또래/형제자매'], ['unfamAdult', '친숙하지 않은 성인'], ['unfamPeer', '친숙하지 않은 또래']] },
  { key: 'setting', title: '자연적 상황', boxes: [['home', '가정'], ['school', '학교'], ['community', '지역사회']] },
];
const OBS_BG_CRITERIA = [
  '2 = 최소 두 가지 상황에서 두 명의 파트너에 걸쳐 준거에 도달하는 행동을 일관성 있게 보임',
  '1 = 일관성 없이 또는 하나의 활동에서 또는 보조를 받아서 준거에 도달하는 행동을 보임',
  '0 = 관찰 또는 보고된 정보에 근거해 볼 때 준거에 도달하지 않았거나 도달할 것이라고 기대되지 않음',
];
function AssessBackgroundView({ ws, setWs, stageData }) {
  const bg = ws.observation?.background || {};
  const save = (patch) => setWs((s) => ({ ...s, observation: { ...s.observation, background: { ...(s.observation?.background || {}), ...patch } } }));
  const box = (row, id) => (bg[row] || {})[id] || {};
  const setBox = (row, id, patch) => save({ [row]: { ...(bg[row] || {}), [id]: { ...box(row, id), ...patch } } });
  const trans = bg.transitions || ['', '', ''];
  const quarters = bg.quarters || {};
  const setQ = (q, k, v) => save({ quarters: { ...quarters, [q]: { ...(quarters[q] || {}), [k]: v } } });
  // 분기별 점수: 이 단계 세션 중 그 분기로 적힌 세션(같은 분기가 여럿이면 가장 최근 날짜)
  const byQ = {};
  (ws._allSessions || []).forEach((se) => {
    const q = Number(se.quarter);
    if (!q) return;
    if (!byQ[q] || (se.date || '') >= (byQ[q].date || '')) byQ[q] = se;
  });
  const total = (se, d) => {
    if (!se) return '';
    let sum = 0, any = false;
    d.groups.forEach((g) => g.items.forEach((it) => { const v = se.scores?.[it.id]; if (typeof v === 'number') { sum += v; any = true; } }));
    return any ? String(sum) : '';
  };
  const plain = (t) => String(t || '').replace(/\s*\([A-Za-z][^)]*\)\s*$/, '');
  return (
    <div className="observation-inner">
      <div className="no-print" style={{ textAlign: 'right', marginBottom: 12 }}>
        <button className="btn-primary" onClick={printReport}>📄 기록지 1쪽 인쇄</button>
      </div>
      <div id="printable-report" className="printable">
        <ReportHeader title={`${STAGE_LABELS[ws.meta.stage] || ''} SCERTS 진단-관찰 기록지 (1)`} ws={ws} />
        <table className="report-table obs-bg-table">
          <tbody>
            <tr>
              <th style={{ width: '16%' }}>배경 정보</th>
              <td><textarea rows={3} value={bg.info || ''} onChange={(e) => save({ info: e.target.value })} aria-label="배경 정보" /></td>
              <th style={{ width: '10%' }}>팀<br />구성원</th>
              <td style={{ width: '28%' }}><textarea rows={3} value={bg.team || ''} onChange={(e) => save({ team: e.target.value })} aria-label="팀 구성원" /></td>
            </tr>
            <tr><th colSpan={4} style={{ textAlign: 'center' }}>관찰 상황</th></tr>
            {OBS_BG_ROWS.map((r) => (
              <tr key={r.key}>
                <th>{r.title}</th>
                <td colSpan={3}>
                  <div className="obs-bg-boxes">
                    {r.boxes.map(([id, label]) => (
                      <label key={id} className="obs-bg-box">
                        <input type="checkbox" checked={!!box(r.key, id).on} onChange={(e) => setBox(r.key, id, { on: e.target.checked })} />
                        {label}:
                        <input type="text" value={box(r.key, id).text || ''} onChange={(e) => setBox(r.key, id, { text: e.target.value })} aria-label={`${r.title} ${label}`} />
                      </label>
                    ))}
                  </div>
                </td>
              </tr>
            ))}
            <tr>
              <th>활동 변인</th>
              <td colSpan={3}><div className="obs-bg-vars">{OBS_BG_VARIABLES.map((v) => <span key={v}>{v}</span>)}</div></td>
            </tr>
            <tr>
              <th>전이</th>
              <td colSpan={3}>
                <div className="obs-bg-boxes">
                  {[0, 1, 2].map((i) => (
                    <label key={i} className="obs-bg-box">{i + 1}.
                      <input type="text" value={trans[i] || ''} onChange={(e) => { const t = [...trans]; t[i] = e.target.value; save({ transitions: t }); }} aria-label={`전이 ${i + 1}`} />
                    </label>
                  ))}
                </div>
              </td>
            </tr>
          </tbody>
        </table>

        <div className="obs-bg-two">
          <table className="report-table">
            <thead><tr><th>관찰일</th><th>관찰 소요 시간</th></tr></thead>
            <tbody>
              {[1, 2, 3, 4].map((q) => (
                <tr key={q}>
                  <td>{q}/4 분기 시작일: <input type="date" value={quarters[q]?.start || ''} onChange={(e) => setQ(q, 'start', e.target.value)} aria-label={`${q}/4 분기 시작일`} /></td>
                  <td>총 관찰 길이: <input type="text" style={{ width: 90 }} value={quarters[q]?.length || ''} onChange={(e) => setQ(q, 'length', e.target.value)} aria-label={`${q}/4 분기 총 관찰 길이`} /></td>
                </tr>
              ))}
            </tbody>
          </table>
          <table className="report-table">
            <thead><tr><th style={{ textAlign: 'left' }}>사회-정서 성장 지표<br />프로파일</th>{[1, 2, 3, 4].map((q) => <th key={q}>{q}/4</th>)}</tr></thead>
            <tbody>
              {SES_INDICATORS.map((ind) => (
                <tr key={ind.id}>
                  <td>{ind.label}</td>
                  {[1, 2, 3, 4].map((q) => {
                    const v = byQ[q] ? sesOf(byQ[q], ws.meta.stage)[ind.id] : undefined;
                    return <td key={q} style={{ textAlign: 'center' }}>{typeof v === 'number' ? v : ''}/10</td>;
                  })}
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        <div className="obs-bg-two">
          <table className="report-table">
            <thead><tr><th style={{ textAlign: 'left' }}>SCERTS<br />프로파일 요약</th>{[1, 2, 3, 4].map((q) => <th key={q}>{q}/4 분기</th>)}</tr></thead>
            <tbody>
              {DOMAIN_GROUPS.map((g) => (
                <React.Fragment key={g.title}>
                  <tr><th colSpan={5} style={{ textAlign: 'left' }}>{plain(g.title)}</th></tr>
                  {g.domains.map((dk) => {
                    const d = stageData[dk];
                    if (!d) return null;
                    return (
                      <tr key={dk}>
                        <td style={{ paddingLeft: 14 }}>{plain(d.label)}</td>
                        {[1, 2, 3, 4].map((q) => <td key={q} style={{ textAlign: 'center' }}>{total(byQ[q], d)}/{d.maxScore}</td>)}
                      </tr>
                    );
                  })}
                </React.Fragment>
              ))}
            </tbody>
          </table>
          <div className="obs-bg-criteria">
            <strong>채점 기준:</strong>
            {OBS_BG_CRITERIA.map((c) => <div key={c}>{c}</div>)}
          </div>
        </div>
        <p className="hint no-print" style={{ marginTop: 8 }}>
          분기별 점수와 성장 지표는 진단 세션에 적힌 분기(1/4~4/4)의 점수로 자동으로 채워집니다. 같은 분기 세션이 여럿이면 가장 최근 날짜 세션을 씁니다.
        </p>
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
  const recommendedGoals = useMemo(
    () => computeRecommendedGoals(ws.meta.stage, ws.assessment.scores, ws.familyPriorities),
    [ws.assessment.scores, ws.meta.stage, ws.familyPriorities],
  );

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
    const pct = (a, b) => b ? Math.round((a / b) * 100) : 0;

    // MR/SR 패턴 식별
    const mrPct = domainTotals.mutualReg ? domainTotals.mutualReg.score / domainTotals.mutualReg.max : 0;
    const srPct = domainTotals.selfReg ? domainTotals.selfReg.score / domainTotals.selfReg.max : 0;
    const mrSrPattern = classifyMrSr(mrPct, srPct);  // ★ 진단 분석·중간보고서와 같은 기준

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
    // ★ 문장 끝에서 자른다. 문장 끝을 못 찾아 중간에서 잘린 경우 '…'를 남겨 잘린 것이 보이게 한다
    const q_sc1_cut = q_sc1 ? clipText(q_sc1, 100) : '';
    // ★ 보호자 말은 따옴표로 묶어 보고서 문체(~하였다)와 섞이지 않게 한다
    const quoteRago = (t) => {   // "…"라고 / "…"이라고 (따옴표 안 끝 글자의 받침으로 고름)
      const ch = t.slice(-1); const code = ch.charCodeAt(0) - 0xac00;
      return (code >= 0 && code <= 11171 && code % 28 !== 0) ? '이라고' : '라고';
    };
    const q_sc1_clean = !q_sc1_cut ? '' : `"${q_sc1_cut.trim()}"${quoteRago(q_sc1_cut.trim())} 한다. `;
    // ★ 목표 문장은 실제 진단 점수에서 고른 교수목표로 만든다 (단계·아이마다 달라짐)
    const plan = buildGoalPlan(ws.meta.stage, ws.assessment.scores, ws.familyPriorities, ws.iep);
    const nPartner = partnerCountWord(ws.meta.stage);
    const stripPartner = (t) => t.replace(/^파트너는\s*/, '');
    const titlesOf = (arr) => uniqTitles(arr).map((t) => `「${stripPartner(t)}」`).join('·');
    const listOf = (arr) => arr.map((g, i) => `${'①②③④⑤⑥⑦⑧'[i]} ${goalRef(g)}`).join('\n');
    // 구성 요소 점수 문구: "11/20점(55%)"
    const compScore = (k) => {
      const d = domainTotals[k] || { score: 0, max: 0 };
      return `${d.score || 0}/${d.max || 0}점(${pct(d.score || 0, d.max || 0)}%)`;
    };
    // ★ 책 1권 265쪽: 장기목표마다 칸(1점=1칸)의 절반 이상이면 상대적 강점, 절반 미만이면 상대적 요구
    //   모든 교수목표를 채점한 장기목표만 판정한다(채점하지 않은 문항은 빈칸이 아니라 '아직 모름')
    const sc0 = ws.assessment.scores || {};
    const longGoalProfile = (k) => {
      const d = stageData[k]; const strong = [], need = []; let unscored = 0;
      (d?.groups || []).forEach((g) => {
        const vals = g.items.map((it) => sc0[it.id]);
        if (vals.some((v) => typeof v !== 'number')) { unscored += 1; return; }
        const sum = vals.reduce((x, v) => x + v, 0);
        const t = `「${stripPartner(g.title.replace(/^\d+\.\s*/, '')).replace(/[.。]\s*$/, '')}」`;
        (sum >= g.items.length ? strong : need).push(t);
      });
      return { strong, need, unscored, label: (d?.label || '').replace(/\s*\(.*\)\s*$/, ''), score: domainTotals[k]?.score || 0, max: d?.maxScore || domainTotals[k]?.max || 0 };
    };
    const profileSentence = (k) => {
      const pr = longGoalProfile(k);
      // ★ 채점한 교수목표가 하나도 없으면 '0점'이 아니라 '아직 채점하지 않음'
      const anyScored = (stageData[k]?.groups || []).some((g) => g.items.some((it) => typeof sc0[it.id] === 'number'));
      if (!anyScored) return `${pr.label}${hasJongseong(pr.label) ? '은' : '는'} 아직 채점하지 않았다.`;
      const parts = [];
      if (pr.strong.length) parts.push(`상대적 강점은 ${pr.strong.join('·')}`);
      if (pr.need.length) parts.push(`상대적 요구는 ${pr.need.join('·')}`);
      if (!parts.length) return `${pr.label}(${pr.score}/${pr.max}점)은 채점하지 않은 교수목표가 있어 장기목표별 강점과 요구를 판정하지 않았다.`;
      const un = pr.unscored ? ` 채점하지 않은 교수목표가 있는 장기목표 ${pr.unscored}개는 판정하지 않았다.` : '';
      return `${pr.label}(${pr.score}/${pr.max}점)의 ${parts.join(', ')}이다.${un}`;
    };
    // ★ 사회-정서 성장 지표(1권 265쪽): 5개 교수목표가 모두 채점된 지표만 5칸 기준으로 판정
    const sesNow = computeSes(ws.meta.stage, sc0);
    const sesStrong = [], sesNeed = [];
    if (sesNow) SES_INDICATORS.forEach((ind) => {
      const d = sesNow.detail[ind.id];
      if (!d || d.unscored) return;
      (sesNow.values[ind.id] >= 5 ? sesStrong : sesNeed).push(ind.label);
    });
    const sesSentence = (sesStrong.length || sesNeed.length)
      ? `사회-정서 성장 지표에서 ${[sesStrong.length ? `상대적 강점은 ${sesStrong.join('·')}` : '', sesNeed.length ? `상대적 요구는 ${sesNeed.join('·')}` : ''].filter(Boolean).join(', ')}이다. `
      : '';
    const currentLevel = {
      // ★ 책은 백분율·패턴 이름을 쓰지 않고, 장기목표별 강점과 요구로 요약한다(1권 264~266쪽 진단 요약지)
      sc: `${nmEunNeun(cName)} ${profile.headline}로 진단되었다. ` +
          `${profileSentence('joinAttention')} ${profileSentence('symbolUse')} ` +
          (q_sc1_clean ? `보호자 보고에 따르면 ${q_sc1_clean}` : '') +
          `주간 교수목표는 기능성, 가족의 우선순위, 발달적 적합성을 기준으로 선정하였다.`,
      er: `${profileSentence('mutualReg')} ${profileSentence('selfReg')} ` +
          sesSentence +
          (q_er_strength ? `흥미를 보이는 활동은 ${clipText(q_er_strength, 80).replace(/[.。]?\s*$/, '')}이며, ` : '') +
          (q_er_challenge ? `어려움을 보이는 상황은 ${clipText(q_er_challenge, 80).replace(/[.。]?\s*$/, '')}이다.` : ''),
      // ★ 교류 지원은 파트너(어른·환경)에 대한 평가라 아이를 주어로 쓰지 않음(1권 250~251쪽)
      ts: `${profileSentence('interpersonalSupport')} ${profileSentence('learningSupport')}`,
    };
    Object.keys(currentLevel).forEach((k) => { currentLevel[k] = currentLevel[k].trim(); });

    // 가족 우선순위가 있으면 단기 목표에 반영

    const filled = {
      currentLevel,
      // ★ 장기목표 = 고른 교수목표가 속한 장기목표(JA1, SU5 …), 단기목표 = 교수목표 + 책의 2점 기준(1권 253·274쪽)
      annualGoals: {
        sc: plan.sc.length
          // ★ 가족 우선순위는 목표를 고를 때 반영하고 문장에는 적지 않는다(책 2권 33~35쪽: 선정 기준)
          ? `${nmEunNeun(cName)} 일상 활동에서 장기목표 ${titlesOf(plan.sc)}에 해당하는 교수목표에 도달한다.`
          : '',
        er: plan.er.length
          ? `${nmEunNeun(cName)} 일상 활동에서 장기목표 ${titlesOf(plan.er)}에 해당하는 교수목표에 도달한다.`
          : '',
        ts: plan.ts.length
          ? (titlesOf(plan.ts)
            ? `파트너는 교류 지원 장기목표 ${titlesOf(plan.ts)}에 해당하는 지원을 일관성 있게 제공한다.`
            : `파트너는 다음 단기목표의 교류 지원을 일관성 있게 제공한다.`)
          : '',
      },
      shortGoals: {
        sc: plan.sc.length
          ? `${nmEunNeun(cName)} 두 가지 이상의 상황에서 ${nPartner} 명 이상의 파트너와 함께 다음 교수목표에 일관성 있게 도달한다.\n${listOf(plan.sc)}`
          : '',
        er: plan.er.length
          ? `${nmEunNeun(cName)} 두 가지 이상의 상황에서 ${nPartner} 명 이상의 파트너와 함께 다음 교수목표에 일관성 있게 도달한다.\n${listOf(plan.er)}`
          : '',
        ts: plan.ts.length
          ? `파트너는 두 가지 이상의 활동에서 다음 교류 지원을 일관성 있게 제공한다.\n${listOf(plan.ts)}`
          : '',
      },
      // ★ 전략 = 점수가 낮은 교류 지원 문항(대인관계 지원·학습 지원) 중 그 영역을 돕는 것
      strategies: {
        sc: plan.scSupports.length ? listOf(plan.scSupports) : '',
        er: plan.erSupports.length ? listOf(plan.erSupports) : '',
        // ★ 교류 지원은 아동 목표를 다루는 활동 안에서 함께 제공한다 (2권 4장: 아동 목표와 파트너 목표의 연계)
        ts: plan.ts.length
          ? `위 교류 지원(${plan.ts.map((g) => g.id || g.label).join('·')})은 ${(plan.sc.length + plan.er.length) ? `아동 목표(${[...plan.sc, ...plan.er].map((g) => g.id).join('·')})를` : '아동 목표를'} 다루는 활동마다 활동 계획서에 함께 표시하여 가정과 기관의 파트너가 같은 방식으로 제공한다.`
          : '',
      },
      // ★ 평가 = 활동 일지 → 주간 기록지(목표별 0·1·2점) → 분기별 재진단 (2권 350쪽, 1권 7장)
      measures: {
        sc: '활동 일지를 바탕으로 주간 기록지에 교수목표별 0·1·2점을 기록하고, 분기마다 SCERTS 진단-관찰로 다시 평가한다.',
        er: '활동 일지를 바탕으로 주간 기록지에 교수목표별 0·1·2점을 기록하고, 분기마다 SCERTS 진단-관찰로 다시 평가한다.',
        ts: '주간 기록지에 파트너의 교류 지원 실행을 0·1·2점으로 기록하고, 분기마다 다시 평가한다.',
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
          if (generated[k]) filledCount++;   // 비워 둔 칸은 채운 개수에 넣지 않음
        } else {
          preservedCount++;
        }
      });
      return out;
    };
    // ★ 채운 개수는 지금 화면의 값으로 먼저 센다(저장 처리는 나중에 실행되어 거기서 세면 0으로 나옴)
    ['currentLevel', 'annualGoals', 'shortGoals', 'strategies', 'measures'].forEach((f) => merge(ws.iep?.[f] || {}, filled[f]));
    const countMerge = merge;
    const mergeQuiet = (existing, generated) => { const fc = filledCount, pc = preservedCount; const out = countMerge(existing, generated); filledCount = fc; preservedCount = pc; return out; };
    setWs((s) => ({
      ...s,
      iep: {
        ...s.iep,
        currentLevel: mergeQuiet(s.iep.currentLevel || {}, filled.currentLevel),
        annualGoals: mergeQuiet(s.iep.annualGoals || {}, filled.annualGoals),
        shortGoals: mergeQuiet(s.iep.shortGoals || {}, filled.shortGoals),
        strategies: mergeQuiet(s.iep.strategies || {}, filled.strategies),
        measures: mergeQuiet(s.iep.measures || {}, filled.measures),
      },
    }));
    if (showToast) {
      const msg = preservedCount > 0
        ? `${filledCount}개 필드 자동 채움 · ${preservedCount}개 기존 입력 보존`
        : `${filledCount}개 필드를 자동으로 채웠습니다`;
      showToast(msg);
    }
    // ★ 0~1점 문항이 없어 목표를 만들 수 없던 영역은 비워 두고 이유를 알려 준다 (인쇄물에 안내 문구가 섞이지 않게)
    const AREA = { sc: '사회 의사소통', er: '정서 조절', ts: '교류 지원' };
    const blankAreas = Object.keys(AREA).filter((k) => !filled.shortGoals[k] && !(ws.iep.shortGoals?.[k] || '').trim());
    if (blankAreas.length > 0) {
      await appAlert(`${blankAreas.map((k) => AREA[k]).join('·')} 연간/단기목표는 0~1점으로 채점된 문항이 없어 비워 두었습니다.\n채점을 더 하거나 우선순위 목표를 고른 뒤 다시 눌러 주세요.`);
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
          <ReportHeader title="SCERTS 개별화 프로그램 계획안 (IEP)" ws={ws} centerDoc
            dateValue={ws.iep.reportDate}
            dateOnChange={(v) => setWs((s) => ({ ...s, iep: { ...s.iep, reportDate: v } }))} />

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
              추천 순서는 책의 교수목표 선정 기준(기능성·가족의 우선순위·발달적 적합성, 2권 32~35쪽)에 따라
              <strong>가족 우선 항목 → 1점(연습 중) → 0점(배우는 중)</strong>, 같은 점수는 앞 장기목표·앞 교수목표 순입니다.
              기능성(아이 생활에 바로 쓰이는지)은 선생님이 판단해 고릅니다.
              <span className="legend-tag family">❤️ 가족 우선</span>은 가족 우선순위에서 선택한 항목,
              <span className="legend-tag partner-legend">👥 파트너</span>는 교류 지원 영역으로, 클릭 시 우측 "파트너 교류 지원" 칸에 추가됩니다.
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
                    className={`goal-chip ${selected ? 'selected' : ''} ${g.isFamilyChoice ? 'family-choice' : ''} ${!g.prereqsMet ? 'prereq-unmet' : ''} ${isPartnerDomain ? 'partner-domain' : ''}`}
                    onClick={() => toggleGoal(g)}
                    title={`${g.score}점(${g.score === 1 ? '연습 중' : '배우는 중'})${g.isFamilyChoice ? ' · 가족 우선' : ''}${isPartnerDomain ? ' · 파트너 교류 지원 목표' : ''}`}
                  >
                    {rank < 5 && <span className="goal-rank">#{rank + 1}</span>}
                    <span className="goal-chip-id">{g.id}</span>
                    {isPartnerDomain && <span className="goal-tag partner-tag">👥</span>}
                    {g.isFamilyChoice && <span className="goal-tag family-tag">❤️</span>}
                    {!g.prereqsMet && <span className="goal-tag prereq-tag">⚠</span>}
                    <span>{g.label}</span>
                    {g.sameAs && <span className="goal-tag" title="책에서 같은 문항으로 표시된 짝">= {g.sameAs.join(', ')}</span>}
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

          <ApprovalBlock reportDate={ws.iep.reportDate || ws.meta.reportDate} therapist={ws.meta.therapist} />
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
      let pre = 0, post = 0, mismatch = false;
      domain.groups.forEach((g) =>
        g.items.forEach((it) => {
          const a = typeof ws.pre.scores[it.id] === 'number', b = typeof ws.post.scores[it.id] === 'number';
          if (a) pre += ws.pre.scores[it.id];
          if (b) post += ws.post.scores[it.id];
          if (a !== b) mismatch = true;   // ★ 한쪽에서만 채점한 교수목표가 있음
        }),
      );
      result.push({
        mismatch,
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

  // ★ 장기목표 강점/요구(1권 265쪽: 칸 절반 이상 = 상대적 강점) — 모든 교수목표를 채점한 장기목표만
  const groupStrength = (scores, g) => {
    const vals = g.items.map((it) => scores?.[it.id]);
    if (vals.some((v) => typeof v !== 'number')) return null;
    return vals.reduce((a, v) => a + v, 0) >= g.items.length ? 'strong' : 'need';
  };
  const gTitle = (g) => `「${g.title.replace(/^\d+\.\s*/, '').replace(/^파트너는\s*/, '').replace(/[.。]\s*$/, '')}」`;

  // 진단·활동기록·MR-SR 분석을 통합한 자동 채움
  const autoFillInterim = async () => {
    // ★ 중간 점검 글이 남은 채로 종결(또는 반대)로 자동 채움을 누르면, 그 보고서 유형 문장으로 새로 채울지 먼저 묻는다
    const filledAs = ws.interim.autoFilledAs
      || (/다음 기간에도 계속 다루는|새로운 목표로 바꾼다|다음 기간에는/.test(ws.interim.direction || '') ? 'interim'
        : /이후 환경에서/.test(ws.interim.direction || '') ? 'closing' : '');
    const nowAs = isClosing ? 'closing' : 'interim';
    let redo = false;
    if (filledAs && filledAs !== nowAs) {
      const from = filledAs === 'closing' ? '종결' : '중간 점검';
      redo = await appConfirm(`${from} 보고서 자동 채움 글이 남아 있습니다.\n\n확인: 요약·영역별 진전·관찰·향후 방향을 ${isClosing ? '종결' : '중간 점검'} 문장으로 새로 채움 (그 칸에 직접 고친 내용도 바뀜)\n취소: 빈 칸만 채움`);
    }
    const profile = STAGE_PROFILE[ws.meta.stage];
    const cName = ws.meta.childName || '';

    // 1) 현재 발달 수준 요약 - 진단 점수 + 단계 특징 + 사전/사후 변화 + 가족 우선순위 + 강점/과제
    let summary = `${nmEunNeun(cName)} ${profile.headline}에 해당한다. ` +
                  `이번 평가 기간 동안 SCERTS 세 영역(사회 의사소통, 정서 조절, 교류 지원)을 중심으로 중재를 진행하였다. `;
    if (compareData) {
      // ★ 총점은 쓰지 않는다 — 책(1권 254·265쪽)은 6개 구성 요소 점수를 따로 기록함
      //   아동 구성 요소(공동관심·상징 사용·상호조절·자기조절)와 파트너(교류 지원)를 나눠 쓴다
      const TS_KEYS = ['interpersonalSupport', 'learningSupport'];
      const childDomains = compareData.filter((d) => !TS_KEYS.includes(d.domain));
      const partnerDomains = compareData.filter((d) => TS_KEYS.includes(d.domain));
      const fmt = (d) => `${d.label} ${d.pre}→${d.post}/${d.max}점`;   // ★ 책 관찰 기록지 프로파일 요약처럼 만점 표시(백분율은 쓰지 않음)
      if (childDomains.length > 0) {
        summary += `구성 요소별 진단 점수는 사전에서 사후로 ${childDomains.map(fmt).join(', ')}으로 나타났다. `;
      }
      // 가장 진전이 큰 아동 구성 요소 한 가지 강조 (교류 지원은 파트너 점수라 제외)
      const topGains = [...childDomains].filter((d) => d.delta > 0 && !d.mismatch).sort((a, b) => b.delta - a.delta);
      if (topGains.length > 0) {
        summary += `특히 ${topGains[0].label}에서 ${topGains[0].delta}점의 가장 큰 향상이 관찰되었다. `;
      }
      if (partnerDomains.length > 0) {
        summary += `파트너의 교류 지원은 ${partnerDomains.map(fmt).join(', ')}으로 나타났다. `;
      }
      // ★ 사전·사후에 채점한 교수목표가 다른 구성 요소는 총점을 그대로 비교할 수 없음을 한 번에 밝힌다
      const mm = compareData.filter((d) => d.mismatch).map((d) => d.label);
      if (mm.length) summary += `다만 ${mm.join('·')}${hasJongseong(mm[mm.length - 1]) ? '은' : '는'} 사전·사후에 채점한 교수목표가 달라 점수를 그대로 비교하기 어렵다. `;
      // ★ 분기 재진단(1권 269쪽): 사전에 상대적 요구였다가 사후에 상대적 강점이 된 장기목표
      const turned = [];
      Object.entries(stageData).forEach(([k, d]) => {
        if (TS_KEYS.includes(k)) return;
        d.groups.forEach((g) => { if (groupStrength(ws.pre?.scores, g) === 'need' && groupStrength(ws.post?.scores, g) === 'strong') turned.push(gTitle(g)); });
      });
      if (turned.length) summary += `사전 진단에서 상대적 요구였던 장기목표 중 ${turned.join('·')}${hasJongseong(turned[turned.length - 1].slice(0, -1)) ? '은' : '는'} 사후 진단에서 상대적 강점(칸의 절반 이상)이 되었다. `;
    }
    // (단계 특징 문장은 쓰지 않는다 — 실제로 무엇을 지원했는지는 주간 목표·기록으로 적는다)
    // 가족 우선순위 인용
    const familyFocus = (ws.familyPriorities?.focusOne || '').trim();
    const familyHope = (ws.familyPriorities?.threeMonthHope || '').trim();
    if (familyFocus || familyHope) {
      // ★ 안에 따옴표가 이미 있으면 「」로 묶어 따옴표가 겹치지 않게 한다
      const qt = (t) => (/["“”]/.test(t) ? `「${t}」` : `"${t}"`);
      summary = summary.trim() + `\n\n가족 우선순위로는 `;
      if (familyFocus) summary += qt(familyFocus);
      // ★ 조사 을/를을 앞말 받침에 맞춤
      if (familyHope) summary += `${familyFocus ? eulReul(familyFocus) + ' 중점 영역으로 두고, ' : ''}3개월 내 ${qt(familyHope)}${eulReul(familyHope)} 단기 희망으로 공유하였다.`;
      else summary += `${eulReul(familyFocus)} 중심으로 지원하였다.`;
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
                improvedItems.push(`${it.id} 「${it.label}」`);
              }
            }),
          );
        }
        // ★ 책 관찰 기록지 프로파일 요약처럼 만점을 함께 적는다(백분율은 쓰지 않음). 점수 변화 + 장기목표 강점/요구 변화 + 점수가 오른 교수목표
        let progress = `사전 ${d.pre}/${d.max}점에서 사후 ${d.post}/${d.max}점으로 ${d.delta > 0 ? `${d.delta}점 높아졌다` : d.delta < 0 ? `${Math.abs(d.delta)}점 낮아졌다` : '변화가 없었다'}.`;
        if (d.mismatch) progress += ' 사전·사후에 채점한 교수목표가 달라 점수를 그대로 비교하기 어렵다.';
        const toStrong = [], toNeed = [];
        (stageData[d.domain]?.groups || []).forEach((g) => {
          const a = groupStrength(preScores, g), b = groupStrength(postScores2, g);
          if (a === 'need' && b === 'strong') toStrong.push(gTitle(g));
          if (a === 'strong' && b === 'need') toNeed.push(gTitle(g));
        });
        if (toStrong.length) progress += ` 상대적 요구에서 상대적 강점이 된 장기목표: ${toStrong.join('·')}.`;
        if (toNeed.length) progress += ` 상대적 강점에서 상대적 요구가 된 장기목표: ${toNeed.join('·')}.`;
        if (improvedItems.length > 0) {
          progress += ` 점수가 오른 교수목표: ${improvedItems.slice(0, 3).join('·')}${improvedItems.length > 3 ? ` 외 ${improvedItems.length - 3}개` : ''}.`;
        }
        domainSummary[d.domain] = { behavior: '', progress };
      });
    }

    // 3) 관찰 예시 - 활동 일지 I의 최근 회기에서 추출
    const logs = ws.activities?.logI || [];
    let observations = '';
    // ★ 주간 기록지(1권 268쪽): 목표별 주간 0·1·2점 흐름 — 책의 진도 점검 도구
    const wRows = weeklyGoalRows(ws).map((r) => ({ ...r, hist: weeklyHistory(ws, r.key) })).filter((r) => r.hist.length);
    if (wRows.length) {
      const nW = Math.max(...wRows.map((r) => r.hist.length));
      const line = (r) => `  · ${r.id ? `${r.id} ` : ''}「${r.label}」: ${r.hist.map((h) => h.score).join(' → ')}`;
      const ch = wRows.filter((r) => r.group === 'child'), pt = wRows.filter((r) => r.group === 'partner');
      observations += `주간 기록지(최대 ${nW}주 기록)의 목표별 점수 흐름은 다음과 같다.\n`;
      if (ch.length) observations += `▸ 아동 목표\n${ch.map(line).join('\n')}\n`;
      if (pt.length) observations += `▸ 파트너 교류 지원 목표\n${pt.map(line).join('\n')}\n`;
      const stuck = wRows.filter((r) => zeroRun(r.hist).now >= 3);
      if (stuck.length) observations += `3주 연속 0점인 목표: ${stuck.map((r) => r.id || r.label).join(', ')}\n`;
      observations += '\n';
    }
    if (logs.length > 0) {
      observations += `활동 일지 ${logs.length}건 중 최근 기록의 유의점은 다음과 같다.\n\n`;
      const recentLogs = logs.slice(-3); // 최근 3회기
      recentLogs.forEach((log, i) => {
        if (isBookLog(log)) {
          // ★ 책 활동 일지: 목표마다 '활동'과 '유의점'
          observations += `▸ ${log.date || `회기 ${i + 1}`}\n`;
          const lines = [...(log.bookChild || []), ...(log.bookPartner || [])].filter(Boolean).flatMap((r) => (r.note || []).map((n, j) => ({ r, n, a: (r.act || [])[j] })))
            .filter((x) => x.n && x.n.trim()).slice(0, 3)
            .map((x) => `  · ${x.r.goal ? `${x.r.goal} — ` : ''}${x.a && x.a.trim() ? `활동: ${x.a.trim()} / ` : ''}유의점: ${x.n.trim()}`);
          if (lines.length) observations += lines.join('\n') + '\n';
          observations += '\n';
          return;
        }
        observations += `▸ ${log.date || `회기 ${i + 1}`} - ${log.fields?.activity || '활동'}\n`;
        const allObs = [
          ...(log.goalsSocial || []).filter((g) => g?.observed),
          ...(log.goalsEmo || []).filter((g) => g?.observed),
        ];
        if (allObs.length > 0) {
          observations += allObs.slice(0, 2).map((g) => `  · ${g.observed}${(g.rating || '').trim() ? ` (${g.rating.trim()})` : ''}`).join('\n') + '\n';
        }
        if (log.notes) observations += `  메모: ${log.notes.slice(0, 100)}\n`;
        observations += '\n';
      });
    }
    // ★ 기록이 없으면 칸을 비워 둔다(안내 문장은 화면 위 안내줄에만 — 보고서 본문·인쇄에 들어가지 않게)

    // 4) 향후 중재 방향 — 책의 분기 점검(1권 269쪽, 2권 350쪽):
    //   2점에 도달한 목표는 새 목표로, 0·1점 목표는 계속하거나 수정, 3주 연속 0점이면 더 낮은 수준의 목표나 지원 수정,
    //   다음 목표는 사후 프로파일에서 기능성·가족의 우선순위·발달적 적합성으로 고른다
    const postScores = ws.post?.scores || ws.assessment.scores;
    const PW = ws.post ? '사후' : '현재';   // ★ 사후로 지정한 세션이 없으면 지금 열린 진단 점수이므로 '현재'
    const plan = buildGoalPlan(ws.meta.stage, postScores, ws.familyPriorities, null);
    const nextWord = isClosing ? '이후 환경에서는' : '다음 기간에는';
    const lk = itemLookup(ws.meta.stage);
    const iepRows = weeklyGoalRows(ws).map((r) => ({ ...r, score: r.id ? postScores[r.id] : undefined, hist: weeklyHistory(ws, r.key) }));
    const ref = (g) => `${g.id ? `${g.id} ` : ''}「${g.label}」`;
    const numbered = (arr, f) => arr.map((g, i) => `${i + 1}. ${f ? f(g) : ref(g)}`).join('\n');
    const parts = [];
    ['child', 'partner'].forEach((grp) => {
      const rowsG = iepRows.filter((r) => r.group === grp);
      if (!rowsG.length) return;
      const nm = grp === 'child' ? 'IEP 주간 목표' : '파트너 교류 지원 목표';
      const reached = rowsG.filter((g) => g.score === 2);
      const ongoing = rowsG.filter((g) => g.score !== 2);
      if (reached.length) parts.push(`${nm} 중 ${PW} 진단에서 일관성 있게 도달(2점)한 목표이다. ${isClosing ? '이후 환경에서 유지되는지 확인한다.' : '새로운 목표로 바꾼다.'}\n${numbered(reached)}`);
      if (ongoing.length) parts.push(`${nm} 중 ${isClosing ? '이후 환경에서도 계속 지원이 필요한' : '다음 기간에도 계속 다루는'} 목표이다.\n${numbered(ongoing, (g) => `${ref(g)}${typeof g.score === 'number' ? ` (${PW} ${g.score}점)` : ` (${PW} 미채점)`}`)}`);
    });
    const stuckRows = iepRows.filter((r) => zeroRun(r.hist).now >= 3);
    if (stuckRows.length) parts.push(`주간 기록지에서 3주 연속 0점인 목표는 더 낮은 수준의 목표로 바꾸거나 활동·교류 지원을 수정한다.\n${numbered(stuckRows)}`);
    const nextChild = [...plan.sc, ...plan.er].filter((g) => !iepRows.some((r) => r.id === g.id));
    if (nextChild.length) parts.push(`${nextWord} ${PW} 진단에서 아직 일관되지 않은 다음 교수목표를 후보로 검토한다(사회 의사소통·정서 조절).\n${numbered(nextChild, (g) => `${goalRef(g)} (${PW} ${g.score}점)`)}`);
    const nextTs = plan.ts.filter((g) => !iepRows.some((r) => r.id === g.id));
    if (nextTs.length) parts.push(`이 목표를 돕기 위해 파트너가 보완할 교류 지원 후보이다.\n${numbered(nextTs, goalRef)}`);
    const hope3 = (ws.familyPriorities?.threeMonthHope || '').trim();
    if (!isClosing && hope3) parts.push(`다음 3개월의 주간 목표는 ${(nextChild.length || nextTs.length) ? '위 후보 가운데 ' : ''}기능성, 가족의 우선순위(${hope3.replace(/[.。]\s*$/, '')}), 발달적 적합성을 기준으로 정한다.`);
    let direction = parts.join('\n\n');

    // 빈 필드만 자동 채움 (사용자 입력 보존)
    const isEmpty = (v) => redo || !v || (typeof v === 'string' && v.trim() === '');
    let filledCount = 0;
    let preservedCount = 0;
    if (isEmpty(ws.interim.summary)) { updateInterim('summary', summary); filledCount++; } else preservedCount++;
    if (redo || Object.keys(ws.interim.domainSummary || {}).length === 0) { updateInterim('domainSummary', domainSummary); filledCount++; } else preservedCount++;
    observations = observations.trim();
    if (isEmpty(ws.interim.observations)) { updateInterim('observations', observations); filledCount++; } else preservedCount++;
    if (isEmpty(ws.interim.direction)) { updateInterim('direction', direction); filledCount++; updateInterim('autoFilledAs', nowAs); } else preservedCount++;   // ★ 향후 방향을 실제로 새로 채웠을 때만 '어느 보고서 문장인지' 기록

    // [종결 모드] 목표 달성도(IEP 끌어오기) + 향후 권고 자동 채움
    if (isClosing) {
      if ((ws.interim.goalAchievement || []).length === 0) {
        // ★ 목표 달성도 = IEP 주간 목표(아동)·파트너 목표마다 사후 진단 점수(책 0·1·2점 기준)와 주간 기록지 흐름
        const stLabel = ACHIEVE_LABEL;
        const scoreWord = { 2: '준거에 일관성 있게 도달', 1: '준거에 일관성 없이 도달하거나 보조를 받아서 수행함', 0: '준거에 도달하지 못함' };
        const goals = iepRows.map((g) => {
          const sc = typeof g.score === 'number' ? g.score : null;
          const notes = [];
          if (sc !== null) notes.push(`${PW} ${sc}점(${scoreWord[sc]})`);
          if (g.hist.length) notes.push(`주간 기록지: ${g.hist.map((h) => h.score).join(' → ')}`);
          return { goal: `${g.group === 'partner' ? '[파트너] ' : ''}${ref(g)}`, status: sc !== null ? stLabel[sc] : '', note: notes.join(' / ') };
        });
        if (goals.length > 0) { updateInterim('goalAchievement', goals); filledCount++; }
      } else preservedCount++;
      if (isEmpty(ws.interim.recommendation)) {
        // ★ IEP 목표의 사후 결과로 권고: 계속 지원할 아동 목표 / 다음 파트너에게 전할 교류 지원(2점) / 보완할 교류 지원(0·1점) / 가족 희망
        const parts = [];
        const contChild = iepRows.filter((g) => g.group === 'child' && (g.score === 0 || g.score === 1));   // 사후 미채점 목표는 판단하지 않음
        const tsDone = iepRows.filter((g) => g.group === 'partner' && g.score === 2);
        const tsWeak = iepRows.filter((g) => g.group === 'partner' && (g.score === 0 || g.score === 1));
        const list = (arr) => arr.map(ref).join(', ');
        if (contChild.length) parts.push(`아직 일관되게 도달하지 않은 교수목표(${list(contChild)})를 다음 환경에서 계속 지원한다`);
        else if (iepRows.length === 0 && (plan.sc.length || plan.er.length)) parts.push(`아직 일관되게 도달하지 않은 교수목표(${[...plan.sc, ...plan.er].map(goalRef).join(', ')})를 다음 환경에서 계속 지원한다`);
        if (tsDone.length) parts.push(`일관되게 제공된 교류 지원(${list(tsDone)})을 다음 환경의 파트너에게 전달한다`);
        else if (iepRows.length === 0 && plan.tsStrong.length) parts.push(`일관되게 제공되고 있는 교류 지원(${plan.tsStrong.map(goalRef).join(', ')})을 다음 환경의 파트너에게 전달한다`);
        if (tsWeak.length) parts.push(`아직 일관되지 않은 교류 지원(${list(tsWeak)})을 가정과 다음 환경에서 함께 보완한다`);
        else if (iepRows.length === 0 && plan.ts.length) parts.push(`아직 일관되지 않은 교류 지원(${plan.ts.map(goalRef).join(', ')})을 가정과 다음 환경에서 함께 보완한다`);
        const hope = (ws.familyPriorities?.threeMonthHope || '').trim();
        if (hope) parts.push(`다음 환경의 목표는 기능성, 가족의 우선순위(${hope.replace(/[.。]\s*$/, '')}), 발달적 적합성을 기준으로 정한다`);
        updateInterim('recommendation', parts.length
          ? '가정 및 다음 환경(학교/기관)에서의 일관된 지원을 위해 다음을 권고한다. ' + parts.map((t, i) => `${'①②③④'[i]} ${t}.`).join(' ')
          : '');
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
          <ReportHeader title={`SCERTS ${reportLabel}`} ws={ws} centerDoc
            dateValue={ws.interim.reportDate}
            dateOnChange={(v) => updateInterim('reportDate', v)}
            extras={[
            { label: isClosing ? '치료 기간' : '보고 기간', editable: true, value: ws.interim.period,
              onChange: (v) => updateInterim('period', v) },
          ]} />

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
                      <select className="closing-status-sel" value={ACHIEVE_OLD[g.status] !== undefined ? ACHIEVE_LABEL[ACHIEVE_OLD[g.status]] : g.status} onChange={(e) => { const arr=[...ws.interim.goalAchievement]; arr[i]={...arr[i],status:e.target.value}; updateInterim('goalAchievement',arr); }}>
                        <option value="">선택</option>
                        {[2, 1, 0].map((n) => <option key={n} value={ACHIEVE_LABEL[n]}>{ACHIEVE_LABEL[n]}</option>)}
                        {/* ★ 예전에 고른 값(달성/부분 달성/미달성 등)도 지우지 않고 그대로 보이게 */}
                        {g.status && !Object.values(ACHIEVE_LABEL).includes(g.status) && ACHIEVE_OLD[g.status] === undefined && <option value={g.status}>{g.status} (예전 선택)</option>}
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

          <ApprovalBlock reportDate={ws.interim.reportDate || ws.meta.reportDate} therapist={ws.meta.therapist} />
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
                <button className="btn-ghost" onClick={() => onLoad(a.snapshot, a)}>불러오기</button>
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
function ReportHeader({ title, ws, extras, dateValue, dateOnChange, centerDoc }) {
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
      {centerDoc && <div className="center-doc-tag no-print">센터 문서 (책 양식 아님)</div>}
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
            <th>단 계</th><td colSpan={3}>{STAGE_LABELS[ws.meta.stage]}</td>
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
    // 예전에 '글 한 덩어리'로 적어 둔 임시저장이 있으면 __old로 남겨 둔다
    const cur = a[id] && typeof a[id] === 'object' ? { ...a[id] } : (typeof a[id] === 'string' && a[id].trim() ? { __old: a[id] } : {});
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
      } else if (type === 'emotionsRows' || type === 'emotionPairs' || type === 'recoveryPair' || type === 'scale02List') {
        // 값이 있는 필드만 남김 (선생님 렌더 형식과 동일한 객체 구조 유지)
        if (typeof v === 'string') {
          // 예전 임시저장(글 한 덩어리)은 그대로 보낸다 → 선생님 화면에서 '받은 답'으로 보임
          if (v.trim()) out[id] = v;
        } else if (v && typeof v === 'object') {
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
      ) : q.type === 'emotionPairs' ? (
        // ★ 긍정/부정 감정 짝 — 감정별로 나눠서 작성 (선생님 화면 칸과 같은 형식)
        <div>
          {(() => {
            const old = typeof value === 'string' ? value : (value && value.__old) || '';
            return old.trim() ? (
              <div style={{ fontSize: 12.5, color: '#6b5320', background: '#fef7e6', border: '1px dashed #c19a3a', borderRadius: 6, padding: '7px 10px', marginBottom: 8, whiteSpace: 'pre-wrap' }}>
                이전에 적어 두신 답: {old}
              </div>
            ) : null;
          })()}
          {(q.pairs || []).flat().map((emo) => (
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
      Object.keys(incoming).forEach((k) => { if (k !== '__writer') merged[k] = keepOldAnswer(merged[k], incoming[k]); });
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
      Object.keys(incoming).forEach((k) => { if (k !== '__writer') merged[k] = keepOldAnswer(merged[k], incoming[k]); });
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

          {/* ★ 질문지를 책(1권 부록) 문장대로 바꾸기 전에 받은 답 — 지우지 않고 여기에 보관 */}
          {(() => {
            const retired = (RETIRED_INTERVIEW_QUESTIONS[ws.meta.stage] || [])
              .filter((q) => answerHasContent(ws.interview.answers[q.id]));
            if (retired.length === 0) return null;
            return (
              <section className="report-section interview-section interview-retired">
                <h3 className="report-h3">예전 질문지에 받은 답</h3>
                <p className="hint" style={{ marginTop: 0 }}>
                  질문지를 책(1권 부록) 문장대로 바꾸기 전에 받은 답입니다. 지금 질문지에는 없는 질문이라 지우지 않고 여기에 보관합니다.
                </p>
                <div className="interview-questions">
                  {retired.map((q, idx) => (
                    <InterviewQuestion
                      key={q.id}
                      q={{ ...q, q: `[예전 · ${q.section}] ${q.q}` }}
                      index={idx + 1}
                      value={ws.interview.answers[q.id]}
                      onChange={(v) => updateAnswer(q.id, v)}
                    />
                  ))}
                </div>
              </section>
            );
          })()}
        </div>
      </div>
    </div>
  );
}

// ★ 칸이 여러 개인 문항에 예전 방식으로 '글 한 덩어리'가 들어온 경우: 그 글을 지우지 않고 보여 주기만 한다
//   칸에 새로 입력해도 그 글은 '__old'에 그대로 남는다 (objAnswer 참고)
function OldTextNote({ value }) {
  const old = typeof value === 'string' ? value : (value && typeof value === 'object' ? value.__old : '');
  if (typeof old !== 'string' || !old.trim()) return null;
  return (
    <div className="iq-old-text">
      <b>받은 답(한 덩어리로 들어온 글):</b> {old}
    </div>
  );
}
// 칸이 여러 개인 문항의 답: 예전 '글 한 덩어리'면 __old에 담아 두고 칸 입력은 따로 받는다
// 부모 답을 다시 받아 덮어쓸 때, 칸 여러 개 문항에 있던 예전 '글 한 덩어리'(또는 __old)는 남겨 둔다
// 답에 실제 내용이 있는지 (빈 글·빈 칸·체크 해제만 있으면 false)
function answerHasContent(v) {
  if (v === null || v === undefined) return false;
  if (typeof v === 'string') return v.trim().length > 0;
  if (typeof v === 'number') return true;
  if (typeof v === 'boolean') return v;
  if (Array.isArray(v)) return v.some(answerHasContent);
  if (typeof v === 'object') return Object.values(v).some(answerHasContent);
  return false;
}
function keepOldAnswer(prev, incoming) {
  // 칸별로 적어 둔 답(prev 객체)이 있는데 글 한 덩어리가 다시 들어오면: 칸 답은 두고 그 글은 __old로
  if (typeof incoming === 'string') {
    if (prev && typeof prev === 'object' && !Array.isArray(prev) && Object.keys(prev).some((k) => k !== '__old')) {
      return incoming.trim() ? { ...prev, __old: incoming } : prev;
    }
    return incoming;
  }
  if (!incoming || typeof incoming !== 'object' || Array.isArray(incoming)) return incoming;
  const old = typeof prev === 'string' ? prev : (prev && typeof prev === 'object' ? prev.__old : '');
  if (typeof old === 'string' && old.trim() && !incoming.__old) return { ...incoming, __old: old };
  return incoming;
}
function objAnswer(value) {
  if (typeof value === 'string') return value.trim() ? { __old: value } : {};
  return (value && typeof value === 'object') ? value : {};
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
          {/* ★ 질문지 보기를 책대로 바꾸기 전에 고른 답: 지우지 않고 보여 준다 */}
          {(() => {
            const known = new Set([...(q.options || []), ...((q.withText || []).map((w) => w.id))]);
            const extra = Object.keys(v.checked || {}).filter((k) => v.checked[k] && !known.has(k));
            return extra.length > 0
              ? <div className="iq-old-text"><b>예전 보기에서 고른 것:</b> {extra.join(', ')}</div>
              : null;
          })()}
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
    const v = objAnswer(value);
    if (q.type === 'emotionsRows') {
      return (
        <div className="iq-row">
          <div className="iq-q"><span className="iq-idx">{index}.</span> {q.q}</div>
          <OldTextNote value={value} />
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
        <OldTextNote value={value} />
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
    const v = objAnswer(value);
    return (
      <div className="iq-row">
        <div className="iq-q"><span className="iq-idx">{index}.</span> {q.q}</div>
        <OldTextNote value={value} />
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
    const v = objAnswer(value);
    return (
      <div className="iq-row">
        <div className="iq-q"><span className="iq-idx">{index}.</span> {q.q}</div>
        <OldTextNote value={value} />
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
        <p className="hint">책의 순서대로 활동 일지에 매일 기록하고, 그 기록으로 주간 기록지에 목표별 0·1·2점을 매깁니다(1권 268쪽). 활동 계획서에는 하루 활동마다 다룰 목표를 표시합니다.</p>

        <div className="activity-nav no-print">
          {[
            { id: 'logI', label: '활동 일지 I·II' },
            { id: 'weeklyScores', label: '주간 기록지' },
            { id: 'plan', label: '활동 계획서' },
            { id: 'logII', label: '주간 메모 (센터 양식)' },
            { id: 'stats', label: '📊 진도 보기' },
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
        {view === 'weeklyScores' && <WeeklyScoreSheet ws={ws} setWs={setWs} />}
        {view === 'plan' && <ActivityPlan ws={ws} setWs={setWs} />}
        {view === 'stats' && <ActivityStats ws={ws} />}
      </div>
    </div>
  );
}

// ★ 회기 목표 표에서 아래 줄부터 쓰면 위의 빈 줄이 '구멍'으로 남아 나중에 멈춤을 일으킴 → 빈 줄로 채워 둔다
function fillRows(rows, uptoIdx) {
  const arr = [...(rows || [])];
  for (let k = 0; k <= uptoIdx; k++) if (!arr[k]) arr[k] = { goal: '', observed: '', rating: '' };
  return arr;
}

// ★ 책 활동 일지 I·II (1권 부록 482·483쪽): 이름·의사소통 단계·날짜 / 아동 목표 줄·파트너 목표 줄
//   목표 줄마다 '활동:'과 '유의점:' (II는 목표마다 활동 칸 2개)
const BOOK_LOG_MIN_ROWS = 5;
const BOOK_LOG_GUIDE = [
  '활동: 집단 크기, 파트너, 맥락, 활동 변인의 특징이 잘 나타나도록 묘사할 것',
  '유의점: 아동 또는 파트너의 수행을 기록하거나(예: 시작행동의 수, 올바른 시도의 수) 활동 중 아동이나 파트너가 보인 최상의 행동을 묘사할 것',
];
function isBookLog(log) { return !!log && Array.isArray(log.bookChild); }
function bookRow(goal = '') { return { goal, act: ['', ''], note: ['', ''] }; }
function padBookRows(rows) {
  const arr = (rows || []).map((r) => ({ goal: r?.goal || '', act: [r?.act?.[0] || '', r?.act?.[1] || ''], note: [r?.note?.[0] || '', r?.note?.[1] || ''] }));
  while (arr.length < BOOK_LOG_MIN_ROWS) arr.push(bookRow());
  return arr;
}
function bookLogGoalsFromIEP(ws) {
  const rows = weeklyGoalRows(ws);
  const name = (r) => `${r.id ? r.id + ' ' : ''}${r.label}`;
  return {
    child: padBookRows(rows.filter((r) => r.group === 'child').map((r) => bookRow(name(r)))),
    partner: padBookRows(rows.filter((r) => r.group === 'partner').map((r) => bookRow(name(r)))),
  };
}
// 예전 템플릿(목표 표 방식)을 책 일지 줄로 바꿈 — 목표 이름과 활동 이름만 옮김
function bookRowsFromOldTemplate(tpl) {
  const act = tpl?.fields?.activity || '';
  const g = (x) => String(x?.goal || '').replace(/^\[([A-Z]{2}\d+\.\d+)\]\s*/, '$1 ');
  return {
    child: padBookRows([...(tpl?.goalsSocial || []), ...(tpl?.goalsEmo || [])].filter((x) => x && x.goal).map((x) => ({ goal: g(x), act: [act, ''], note: ['', ''] }))),
    partner: padBookRows((tpl?.partnerGoals || []).filter((x) => x && x.goal).map((x) => ({ goal: g(x), act: [act, ''], note: ['', ''] }))),
  };
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

  const bookGoals = useMemo(() => bookLogGoalsFromIEP(ws), [ws.iep, ws.meta.stage]);
  const addLog = () => {
    setWs((s) => {
      const next = [...s.activities.logI, {
        id: 'log_' + Date.now(),
        date: new Date().toISOString().slice(0, 10),
        kind: 'I',
        // ★ 책 활동 일지: IEP 주간 우선순위 목표·파트너 교류 지원 목표가 목표 줄로 들어온다
        bookChild: bookGoals.child,
        bookPartner: bookGoals.partner,
      }];
      return { ...s, activities: { ...s.activities, logI: next } };
    });
    setActiveIdx(logs.length);
    const nGoals = bookGoals.child.concat(bookGoals.partner).filter((r) => r.goal).length;
    if (nGoals > 0) {
      showToast(`IEP 목표 ${nGoals}개를 목표 줄에 불러왔습니다`);
    }
  };

  // 기존 회기에 IEP 목표 다시 불러오기
  const reimportFromIEP = async () => {
    if (!await appConfirm('현재 회기의 목표 행을 IEP 선정 목표로 덮어씁니다. 진행하시겠습니까?')) return;
    setWs((s) => {
      const arr = [...s.activities.logI];
      const cur = arr[activeIdx];
      if (isBookLog(cur)) {
        // 목표 이름만 바꾸고, 같은 줄에 적어 둔 활동·유의점은 그대로 둔다
        const keep = (oldRows, newRows) => padBookRows(newRows.map((r, i) => ({ ...(oldRows?.[i] || bookRow()), goal: r.goal })).concat((oldRows || []).slice(newRows.length).filter((r) => r && ((r.act || []).some(Boolean) || (r.note || []).some(Boolean)))));
        arr[activeIdx] = { ...cur, bookChild: keep(cur.bookChild, bookGoals.child), bookPartner: keep(cur.bookPartner, bookGoals.partner) };
      } else {
        arr[activeIdx] = {
          ...cur,
          goalsSocial: [...importedGoals.social],
          goalsEmo: [...importedGoals.emo],
          partnerGoals: [...importedGoals.partner],
        };
      }
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

  // ★ 서버에 저장된 템플릿을 받아 온다 (다른 기기에서 만든 템플릿도 보이게).
  //   서버에 아직 없으면 이 기기 것을 서버로 올려 둔다.
  useEffect(() => {
    let alive = true;
    (async () => {
      try {
        if (!window.storage) return;
        const r = await window.storage.get('gd-aba-templates', true);
        if (!alive || (r && r.error)) return;
        let server = [];
        try { const v = r?.value ? JSON.parse(r.value) : []; if (Array.isArray(v)) server = v; } catch (e) {}
        // ★ 서버 것과 이 기기 것을 합친다 (어느 한쪽 템플릿이 사라지지 않게). 불러오는 사이 새로 저장한 것도 포함
        // 지운 템플릿 목록(서버 + 이 기기)을 합쳐서, 지운 것은 다시 넣지 않는다
        const rd = await window.storage.get('gd-aba-templates-deleted', true);
        if (!alive || (rd && rd.error)) return;
        let delServer = [];
        try { const v = rd?.value ? JSON.parse(rd.value) : []; if (Array.isArray(v)) delServer = v; } catch (e) {}
        const deleted = new Set([...delServer, ...loadDeletedTemplateIds()]);
        if (deleted.size > delServer.length) saveDeletedTemplateIds([...deleted].slice(-500));
        const local = loadTemplates();  // 기다리는 사이 새로 저장한 템플릿도 포함되도록 마지막에 읽는다
        const byId = new Map();
        [...server, ...local].forEach((t) => { if (t && t.id && !deleted.has(t.id) && !byId.has(t.id)) byId.set(t.id, t); });
        const merged = [...byId.values()].sort((a, b) => String(b.createdAt || '').localeCompare(String(a.createdAt || '')));
        setTemplates(merged);
        const serverIds = new Set(server.map((t) => t && t.id));
        const changed = merged.length !== server.length || merged.some((t) => !serverIds.has(t.id));
        if (changed) saveTemplates(merged);
        else { try { localStorage.setItem(lsKey(LS_TEMPLATES), JSON.stringify(merged)); } catch (e) {} }
      } catch (e) {}
    })();
    return () => { alive = false; };
  }, []);

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
      // ★ 책 일지: 목표 이름·활동은 저장, 유의점은 비움(재사용 시 새로 기록)
      ...(isBookLog(log) ? {
        kind: log.kind || 'I',
        bookChild: log.bookChild.filter(Boolean).map((r) => ({ goal: r.goal || '', act: [...(r.act || ['', ''])], note: ['', ''] })),
        bookPartner: (log.bookPartner || []).filter(Boolean).map((r) => ({ goal: r.goal || '', act: [...(r.act || ['', ''])], note: ['', ''] })),
      } : {}),
      // 평가는 비워둠 (재사용 시 새로 평가)
      goalsSocial: (log.goalsSocial || []).map((g) => ({ goal: g?.goal || '', observed: '', rating: '' })),
      goalsEmo: (log.goalsEmo || []).map((g) => ({ goal: g?.goal || '', observed: '', rating: '' })),
      partnerGoals: (log.partnerGoals || []).map((g) => ({ goal: g?.goal || '', observed: '', rating: '' })),
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
    if (isBookLog(log)) {
      const b = tpl.bookChild ? { child: padBookRows(tpl.bookChild), partner: padBookRows(tpl.bookPartner) } : bookRowsFromOldTemplate(tpl);
      updateLog({ kind: tpl.kind || log.kind || 'I', bookChild: b.child, bookPartner: b.partner });
    } else {
      updateLog({
        fields: { ...tpl.fields },
        goalsSocial: (tpl.goalsSocial || []).map((g) => ({ ...g })),
        goalsEmo: (tpl.goalsEmo || []).map((g) => ({ ...g })),
        partnerGoals: (tpl.partnerGoals || []).map((g) => ({ ...g })),
      });
    }
    if (showToast) showToast(`템플릿 "${tpl.name}" 적용됨`);
    setShowTemplateMenu(false);
  };

  const deleteTemplate = async (id, name) => {
    if (!await appConfirm(`템플릿 "${name}"을 삭제하시겠습니까?`)) return;
    const updated = templates.filter((t) => t.id !== id);
    markTemplateDeleted(id);  // ★ 다른 기기에 남은 사본이 합쳐지면서 되살아나지 않게 '지운 것'으로 기록
    saveTemplates(updated);
    setTemplates(updated);
  };

  // 템플릿으로 새 회기 추가
  const addLogFromTemplate = (tpl) => {
    setWs((s) => {
      const next = [...s.activities.logI, {
        id: 'log_' + Date.now(),
        date: new Date().toISOString().slice(0, 10),
        kind: tpl.kind || 'I',
        ...(() => { const b = tpl.bookChild ? { child: padBookRows(tpl.bookChild), partner: padBookRows(tpl.bookPartner) } : bookRowsFromOldTemplate(tpl); return { bookChild: b.child, bookPartner: b.partner }; })(),
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
        .filter(Boolean)  // ★ 비어 있는 줄이 있어도 멈추지 않게
        .map((g) => `${g.goal || ''} ${g.observed || ''}`).join(' ').toLowerCase()
        + ' ' + [...(l.bookChild || []), ...(l.bookPartner || [])].filter(Boolean).map((r) => `${r.goal || ''} ${(r.act || []).join(' ')} ${(r.note || []).join(' ')}`).join(' ').toLowerCase();
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
                        목표 {tpl.bookChild ? tpl.bookChild.concat(tpl.bookPartner || []).filter((r) => r && r.goal).length : (tpl.goalsSocial?.length || 0) + (tpl.goalsEmo?.length || 0)}개 ·
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

      {log && isBookLog(log) && (
        <BookActivityLog ws={ws} log={log} updateLog={updateLog}
          onReimport={reimportFromIEP} onRemove={() => removeLog(activeIdx)} />
      )}

      {log && !isBookLog(log) && (
        <div id="printable-report" className="printable">
          <div className="hint no-print" style={{ background: '#fbf6e9', border: '1px solid #e2d6b5', borderRadius: 6, padding: '8px 10px', marginBottom: 10 }}>
            예전 양식으로 적어 둔 회기 기록입니다(책 양식 아님 · 지우지 않고 보관). '+ 새 회기'부터는 책의 활동 일지 I·II 양식으로 기록됩니다.
          </div>
          <ReportHeader title="회기 기록 (예전 양식)" ws={ws} />

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
            // ★ 책 활동 일지(1권 268쪽·부록 482쪽): 목표마다 '유의점' — 시작행동/올바른 반응마다 + 표시, 또는 최상의 행동 묘사
            { title: '아동의 사회 의사소통 목표', key: 'goalsSocial', cols: ['목표', '유의점: 활동 중 보인 최상의 행동', '+ 표시 (시작·올바른 반응마다)'], rows: 6 },
            { title: '아동의 정서 조절 목표', key: 'goalsEmo', cols: ['목표', '유의점: 활동 중 보인 최상의 행동', '+ 표시 (시작·올바른 반응마다)'], rows: 4 },
            { title: '파트너의 교류 지원 목표', key: 'partnerGoals', cols: ['목표', '유의점: 파트너가 제공한 지원', '+ 표시 (제공할 때마다)'], rows: 6 },
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
                              const arr = fillRows(log[s.key], i);
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
                              const arr = fillRows(log[s.key], i);
                              arr[i] = { ...arr[i], observed: v };
                              updateLog({ [s.key]: arr });
                            }}
                            multiline
                          />
                        </td>
                        <td>
                          {/* ★ 예전에 고른 −, +/−, + 값도 그대로 보이고 고칠 수 있다 */}
                          <Editable
                            value={item.rating}
                            onChange={(v) => {
                              const arr = fillRows(log[s.key], i);
                              arr[i] = { ...arr[i], rating: v };
                              updateLog({ [s.key]: arr });
                            }}
                            placeholder="+ + +"
                          />
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

function BookActivityLog({ ws, log, updateLog, onReimport, onRemove }) {
  const kind = log.kind === 'II' ? 'II' : 'I';
  const nAct = kind === 'II' ? 2 : 1;
  const setCell = (key, i, field, j, v) => {
    const rows = padBookRows(log[key]);
    const r = { ...rows[i], act: [...rows[i].act], note: [...rows[i].note] };
    if (field === 'goal') r.goal = v; else r[field][j] = v;
    rows[i] = r;
    updateLog({ [key]: rows });
  };
  const addRow = (key) => updateLog({ [key]: [...padBookRows(log[key]), bookRow()] });
  const section = (key, title) => {
    const rows = padBookRows(log[key]);
    return (
      <section className="report-section">
        <h3 className="report-h3 book-log-h">{title}</h3>
        <table className="report-table book-log-table">
          <tbody>
            {rows.map((r, i) => (
              <tr key={i}>
                <td className="book-log-goal">
                  <Editable value={r.goal} onChange={(v) => setCell(key, i, 'goal', 0, v)} placeholder="목표" multiline />
                </td>
                {Array.from({ length: nAct }).map((_, j) => (
                  <td key={j} className="book-log-cell">
                    <div className="book-log-line"><span>활동:</span>
                      <Editable value={r.act[j]} onChange={(v) => setCell(key, i, 'act', j, v)} placeholder="" multiline />
                    </div>
                    <div className="book-log-line"><span>유의점:</span>
                      <Editable value={r.note[j]} onChange={(v) => setCell(key, i, 'note', j, v)} placeholder="" multiline />
                    </div>
                  </td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
        <div className="no-print" style={{ textAlign: 'right', marginTop: 4 }}>
          <button className="btn-ghost btn-small" onClick={() => addRow(key)}>+ 목표 줄 추가</button>
        </div>
      </section>
    );
  };
  return (
    <div id="printable-report" className="printable">
      <div className="no-print book-log-kind">
        일지 종류:
        {['I', 'II'].map((k) => (
          <label key={k}><input type="radio" name={`kind_${log.id}`} checked={kind === k} onChange={() => updateLog({ kind: k })} /> 활동 일지 {k}</label>
        ))}
        <span className="hint" style={{ margin: 0 }}>II는 목표마다 활동 칸이 2개입니다.</span>
      </div>
      <h1 className="report-title book-log-title">SCERTS 활동 일지 {kind}</h1>
      <div className="book-log-meta">
        <span>이름: {ws.meta.childName}</span>
        <span>의사소통 단계: {STAGE_LABELS[ws.meta.stage] || ''}</span>
        <span>날짜: <input type="date" className="no-print" value={log.date || ''} onChange={(e) => updateLog({ date: e.target.value })} /><span className="print-only">{log.date}</span></span>
      </div>
      {section('bookChild', '아동: 사회 의사소통 및 정서 조절 목표')}
      {section('bookPartner', '파트너: 교류 지원 목표')}
      <div className="book-log-guide">{BOOK_LOG_GUIDE.map((t) => <div key={t}>{t}</div>)}</div>
      <div className="no-print" style={{ marginTop: 16, textAlign: 'right' }}>
        <button className="btn-ghost" onClick={onReimport}>📥 IEP 목표 다시 불러오기</button>
        <button className="btn-danger" style={{ marginLeft: 8 }} onClick={onRemove}>이 회기 삭제</button>
        <button className="btn-primary" style={{ marginLeft: 8 }} onClick={printReport}>인쇄 / PDF</button>
      </div>
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
      <ReportHeader title="주간 메모 (센터 양식)" ws={ws} centerDoc extras={[
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

// =====================================================================
// ★ SCERTS 주간 기록지 (1권 268쪽·부록 484쪽): 주간 목표 × 1~12주, 목표마다 0·1·2점
//   목표 줄은 IEP에서 고른 주간 우선순위 목표(아동)와 파트너 교류 지원 목표를 그대로 쓴다
// =====================================================================
const WEEKS = 12;
function weeklyGoalRows(ws) {
  const stageData = STAGE_DATA[ws.meta?.stage] || {};
  const childIds = new Set();
  Object.entries(stageData).forEach(([k, d]) => {
    if (k === 'interpersonalSupport' || k === 'learningSupport') return;
    d.groups.forEach((g) => g.items.forEach((it) => childIds.add(it.id)));
  });
  // 이름: 선생님이 고쳐 쓴 목표(customGoal) → 책 문항 이름 → 저장된 이름
  const lk = itemLookup(ws.meta?.stage);
  const nameOf = (id, custom, stored) => (custom || '').trim() || lk[id]?.label || (stored || '').trim();
  const child = (ws.iep?.selectedGoals || [])
    .filter((g) => g && g.id)
    .map((g) => ({ key: g.id, id: g.id, label: nameOf(g.id, g.customGoal, g.label), group: (childIds.has(g.id) || !/^(IS|LS)\d/.test(g.id)) ? 'child' : 'partner' }));
  const partner = (ws.iep?.partnerGoals || []).map((p) => {
    if (p && typeof p === 'object' && p.id) return { key: p.id, id: p.id, label: nameOf(p.id, p.customGoal, p.label), group: 'partner' };
    const t = typeof p === 'string' ? p.trim() : '';
    if (!t) return null;
    const m = t.match(/^\[([A-Z]{2}\d+\.\d+)\]\s*(.*)$/);
    return m ? { key: m[1], id: m[1], label: m[2], group: 'partner' } : { key: 'p:' + t, id: '', label: t, group: 'partner' };
  }).filter(Boolean);
  const seen = new Set();
  return [...child, ...partner].filter((r) => (seen.has(r.key) ? false : (seen.add(r.key), true)));
}
function weeklyData(ws) {
  const w = ws.activities?.weeklyScores || {};
  return { startDates: w.startDates || Array(WEEKS).fill(''), scores: w.scores || {} };
}
// 기록한 주만 순서대로 [{week, date, score}]
function weeklyHistory(ws, key) {
  const { startDates, scores } = weeklyData(ws);
  return (scores[key] || []).map((v, i) => ({ week: i + 1, date: startDates[i] || '', score: v }))
    .filter((x) => x.score === 0 || x.score === 1 || x.score === 2);
}
// ★ 책(2권 350쪽): 3주 연속 0점이면 프로그램 결정을 재고한다
function zeroRun(hist) {
  let run = 0, max = 0;
  hist.forEach((h) => { run = h.score === 0 ? run + 1 : 0; max = Math.max(max, run); });
  return { max, now: run };
}

function WeeklyScoreSheet({ ws, setWs }) {
  const rows = weeklyGoalRows(ws);
  const { startDates, scores } = weeklyData(ws);
  const save = (patch) => setWs((s) => {
    const cur = s.activities?.weeklyScores || {};
    return { ...s, activities: { ...s.activities, weeklyScores: { startDates: cur.startDates || Array(WEEKS).fill(''), scores: cur.scores || {}, ...patch(cur) } } };
  });
  const setDate = (i, v) => save((cur) => { const d = [...(cur.startDates || Array(WEEKS).fill(''))]; d[i] = v; return { startDates: d }; });
  const setScore = (key, i, v) => save((cur) => {
    const all = { ...(cur.scores || {}) };
    const arr = [...(all[key] || Array(WEEKS).fill(null))];
    arr[i] = v === '' ? null : Number(v);
    all[key] = arr;
    return { scores: all };
  });
  const legend = scoringLegendFor(ws.meta?.stage);
  const stuck = rows.filter((r) => zeroRun(weeklyHistory(ws, r.key)).now >= 3);
  const groups = [
    { id: 'child', title: '아동: 사회 의사소통 및 정서 조절 목표' },
    { id: 'partner', title: '파트너: 교류 지원 목표' },
  ];
  return (
    <div id="printable-report" className="printable">
      <ReportHeader title="SCERTS 주간 기록지" ws={ws} />
      {rows.length === 0 ? (
        <div className="empty-hint" style={{ padding: 24, textAlign: 'center' }}>
          IEP 탭에서 주간 우선순위 목표와 파트너 교류 지원 목표를 먼저 고르면, 그 목표가 여기 줄로 들어옵니다.
        </div>
      ) : (
        <>
          {stuck.length > 0 && (
            <div className="hint no-print" style={{ color: '#b54a3a', marginBottom: 8 }}>
              ⚠ 최근 3주 연속 0점인 목표: {stuck.map((r) => r.id || r.label).join(', ')} — 더 낮은 수준의 목표로 바꾸거나 활동·교류 지원을 수정할지 검토하세요(1권 269쪽, 2권 350쪽).
            </div>
          )}
          <div style={{ overflowX: 'auto' }}>
            <table className="report-table weekly-score-table">
              <thead>
                <tr>
                  <th style={{ minWidth: 220, textAlign: 'left' }}>목표</th>
                  {startDates.map((d, i) => (
                    <th key={i} style={{ minWidth: 58 }}>
                      {i + 1}주
                      <input type="date" className="no-print" value={d || ''} onChange={(e) => setDate(i, e.target.value)}
                        style={{ width: 56, fontSize: 10, display: 'block', margin: '2px auto 0' }} title={`${i + 1}주 시작일`} />
                      <span className="print-only" style={{ fontSize: 10 }}>{d ? d.slice(5).replace('-', '/') : ''}</span>
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {groups.map((g) => {
                  const list = rows.filter((r) => r.group === g.id);
                  return (
                    <React.Fragment key={g.id}>
                      <tr><th colSpan={WEEKS + 1} style={{ textAlign: 'left', background: '#ede6d5' }}>{g.title}</th></tr>
                      {list.length === 0 && (
                        <tr><td colSpan={WEEKS + 1} className="hint">IEP에서 고른 목표가 없습니다.</td></tr>
                      )}
                      {list.map((r) => {
                        const arr = scores[r.key] || [];
                        const run = zeroRun(weeklyHistory(ws, r.key)).now >= 3;
                        return (
                          <tr key={r.key}>
                            <td style={{ textAlign: 'left', color: run ? '#b54a3a' : undefined }}>{r.id ? `${r.id} ` : ''}{r.label}</td>
                            {Array.from({ length: WEEKS }).map((_, i) => (
                              <td key={i} style={{ textAlign: 'center', padding: 2 }}>
                                <select className="rating-select" value={arr[i] === 0 || arr[i] === 1 || arr[i] === 2 ? String(arr[i]) : ''}
                                  onChange={(e) => setScore(r.key, i, e.target.value)} aria-label={`${r.id || r.label} ${i + 1}주 점수`}>
                                  <option value="">—</option><option value="0">0</option><option value="1">1</option><option value="2">2</option>
                                </select>
                              </td>
                            ))}
                          </tr>
                        );
                      })}
                    </React.Fragment>
                  );
                })}
              </tbody>
            </table>
          </div>
          <p className="hint" style={{ marginTop: 8 }}>
            점수 산출 기준: {legend.map((l) => `${l.score}, ${l.desc}`).join('; ')}
          </p>
        </>
      )}
      <div className="no-print" style={{ marginTop: 16, textAlign: 'right' }}>
        <button className="btn-primary" onClick={printReport}>인쇄 / PDF</button>
      </div>
    </div>
  );
}

// ★ SCERTS 활동 계획서 (1권 267쪽·부록 485쪽, 2권 1장): 하루 활동을 열로 놓고
//   활동마다 시간·사회적 복잡성·집단 크기·파트너를 적고, 주간 아동 목표/파트너 목표 줄에 다룰 목표를 표시, 맨 아래 교류 지원 샘플
const PLAN_COLS = 6;
const blankPlanCol = () => ({ name: '', time: '', complexity: '', group: '', partners: '', ts: '' });
function ActivityPlan({ ws, setWs }) {
  const data = ws.activities.plan || {};
  const book = data.book || {};
  const cols = Array.from({ length: PLAN_COLS }, (_, i) => ({ ...blankPlanCol(), ...((book.cols || [])[i] || {}) }));
  const checks = book.checks || {};
  const rows = weeklyGoalRows(ws);
  const saveBook = (fn) => setWs((s) => {
    const p0 = s.activities?.plan || {};
    const b0 = p0.book || {};
    return { ...s, activities: { ...s.activities, plan: { ...p0, book: { team: b0.team || '', cols: b0.cols || [], checks: b0.checks || {}, ...fn(b0) } } } };
  });
  const setCol = (i, k, v) => saveBook((b0) => {
    const arr = Array.from({ length: PLAN_COLS }, (_, j) => ({ ...blankPlanCol(), ...((b0.cols || [])[j] || {}) }));
    arr[i] = { ...arr[i], [k]: v };
    return { cols: arr };
  });
  const toggle = (key, i) => saveBook((b0) => {
    const all = { ...(b0.checks || {}) };
    const arr = [...(all[key] || Array(PLAN_COLS).fill(false))];
    arr[i] = !arr[i];
    all[key] = arr;
    return { checks: all };
  });
  // 예전 모양(활동 1개 기록)으로 적어 둔 내용이 있으면 지우지 않고 아래에 보여 준다
  const oldLines = [
    ...Object.entries(data.fields || {}).filter(([, v]) => String(v ?? '').trim()).map(([k, v]) => `${(ACTIVITY_PLAN.sections[0].items.find((it) => it.id === k) || {}).label || k}: ${v}`),
    String(data.steps ?? '').trim() && `활동 단계: ${data.steps}`,
    ...(data.goalsSocial || []).filter((v) => typeof v === 'string' && v.trim()).map((v) => `아동 목표(사회 의사소통): ${v}`),
    ...(data.goalsEmo || []).filter((v) => typeof v === 'string' && v.trim()).map((v) => `아동 목표(정서 조절): ${v}`),
    ...(data.partnerGoals || []).filter((v) => typeof v === 'string' && v.trim()).map((v) => `파트너 목표: ${v}`),
    String(data.challenges ?? '').trim() && `예상되는 어려움: ${data.challenges}`,
  ].filter(Boolean);
  const infoRows = [
    { k: 'name', label: '활동' },
    { k: 'time', label: '시간' },
    { k: 'complexity', label: '사회적 복잡성' },
    { k: 'group', label: '집단 크기' },
    { k: 'partners', label: '팀 구성원 및 파트너' },
  ];
  const groups = [
    { id: 'child', title: '주간 아동 목표' },
    { id: 'partner', title: '주간 파트너 목표' },
  ];
  return (
    <div id="printable-report" className="printable">
      <ReportHeader title="SCERTS 활동 계획서" ws={ws} />
      <section className="report-section">
        <table className="report-table">
          <tbody>
            <tr>
              <th style={{ width: '22%', textAlign: 'left' }}>팀 구성원 및 파트너</th>
              <td><Editable value={book.team} onChange={(v) => saveBook(() => ({ team: v }))} placeholder="예: 담임(T), 보조교사(A), 엄마(M), 언어치료사(S)" /></td>
            </tr>
          </tbody>
        </table>
      </section>
      <section className="report-section">
        <div style={{ overflowX: 'auto' }}>
          <table className="report-table plan-grid">
            <tbody>
              {infoRows.map((r) => (
                <tr key={r.k}>
                  <th style={{ width: '22%', textAlign: 'left' }}>{r.label}</th>
                  {cols.map((c, i) => (
                    <td key={i}><Editable value={c[r.k]} onChange={(v) => setCol(i, r.k, v)} placeholder={r.k === 'name' ? `활동 ${i + 1}` : ''} /></td>
                  ))}
                </tr>
              ))}
              {groups.map((g) => {
                const list = rows.filter((r) => r.group === g.id);
                return (
                  <React.Fragment key={g.id}>
                    <tr><th colSpan={PLAN_COLS + 1} style={{ textAlign: 'left', background: '#ede6d5' }}>{g.title} <span className="hint no-print" style={{ fontWeight: 400 }}>(IEP에서 고른 목표가 자동으로 들어옵니다)</span></th></tr>
                    {list.length === 0 && <tr><td colSpan={PLAN_COLS + 1} className="hint">IEP에서 고른 목표가 없습니다.</td></tr>}
                    {list.map((r) => (
                      <tr key={r.key}>
                        <td style={{ textAlign: 'left' }}>{r.id ? `${r.id} ` : ''}{r.label}</td>
                        {cols.map((_, i) => {
                          const on = !!(checks[r.key] || [])[i];
                          return (
                            <td key={i} style={{ textAlign: 'center', cursor: 'pointer' }} onClick={() => toggle(r.key, i)}
                              role="checkbox" aria-checked={on} aria-label={`${r.id || r.label} — 활동 ${i + 1}`}>
                              {on ? '✓' : <span className="no-print" style={{ color: '#ccc' }}>·</span>}
                            </td>
                          );
                        })}
                      </tr>
                    ))}
                  </React.Fragment>
                );
              })}
              <tr>
                <th style={{ textAlign: 'left' }}>교류 지원 샘플</th>
                {cols.map((c, i) => (
                  <td key={i}><Editable value={c.ts} onChange={(v) => setCol(i, 'ts', v)} multiline placeholder="예: 그림 선택판" /></td>
                ))}
              </tr>
            </tbody>
          </table>
        </div>
        <p className="hint" style={{ fontSize: 11 }}>
          지침: 왼쪽 상단의 팀 구성원 및 파트너 칸에 각 구성원이나 파트너의 수 또는 이름 약자를 기록한다. 그 아래 주간 아동 목표 및 주간 파트너 목표 옆의 빈 칸에
          아동의 주간 사회 의사소통 및 정서 조절 목표와 파트너의 교류 지원 목표를 기록한다. 활동 계획 하단에 각 제목에 따라 칸마다 활동과 시간, 사회적 복잡성 측
          면에서의 비율, 집단 크기, 활동에 참여하는 팀 구성원이나 파트너의 수 또는 이름 약자를 간단히 기록한다. 다음으로, 각 활동에서 초점을 둘 목표를 모두 표시
          한다. 마지막으로 각 활동에서 사용할 교류 지원 샘플에 대해 간략하게 기록한다.
        </p>
      </section>
      {oldLines.length > 0 && (
        <section className="report-section">
          <h3 className="report-h3">예전 양식으로 적은 활동 계획</h3>
          <p className="hint no-print" style={{ marginTop: 0 }}>양식을 책 모양으로 바꾸기 전에 적어 둔 내용입니다. 지워지지 않고 그대로 남아 있습니다.</p>
          <ul>{oldLines.map((t, i) => <li key={i} style={{ whiteSpace: 'pre-wrap' }}>{t}</li>)}</ul>
        </section>
      )}
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
    // ★ 세션마다 문항 점수로 성장 지표를 계산(표 7-5)
    return list.map((s) => ({ ...s, ses: sesOf(s, ws.meta?.stage) }))
      .filter((s) => s.ses && Object.keys(s.ses).length > 0);
  }, [ws._allSessions, ws.meta?.stage]);

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
// SCERTS 진단 요약지 — 1권 부록 (사회적 파트너 430~434쪽 / 언어 파트너 449~453쪽 / 대화 파트너 472~476쪽) 1~5쪽 그대로
//   1~2쪽 SCERTS 프로파일(장기목표마다 칸: 교수목표 수×2칸, 얻은 점수만큼 왼쪽부터 채움 — 1권 269쪽)
//   3쪽 사회-정서 성장 지표 프로파일(10칸) + 가족의 견해 및 우선순위
//   4쪽 SCERTS 주간 교수목표의 우선순위(아동 8줄 / 파트너 8줄)
//   5쪽 후속 진단 · 활동 계획 · 가족 지원 계획 · 전문가와 서비스 제공자를 위한 지원 계획
// =====================================================================
const SAP_DOMAIN_HEAD = { joinAttention: '공동관심', symbolUse: '상징 사용', mutualReg: '상호조절', selfReg: '자기조절', interpersonalSupport: '대인관계 지원', learningSupport: '학습 지원' };
const SAP_GROUP_HEAD = [
  { head: '<사회 의사소통>', domains: ['joinAttention', 'symbolUse'] },
  { head: '<정서 조절>', domains: ['mutualReg', 'selfReg'] },
  { head: '<교류 지원>', domains: ['interpersonalSupport', 'learningSupport'] },
];
// 진단 요약지 1~2쪽에 관찰 기록지와 글자가 다르게 적힌 장기목표(요약지 글자 그대로 씀)
const SAP_TITLE_BOOK = {
  social: { SU6: '2~3개의 익숙한 단어 이해하기' },
  language: { JA1: '상호적 상호작용 참여하기', SU1: '익숙하거나 익숙하지 않은 행동과 단어를 관찰하고 모방하여 학습하기' },
};
const SAP_FAMILY_Q = [
  { k: 'profileAccurate', q: '이 프로파일은 자녀에 대해 정확하게 묘사하고 있습니까? 만일 그렇지 않다면, 어떤 점에서 그러한지 설명해 주십시오.' },
  { k: 'additionalInfo', q: '자녀를 위한 교육을 계획하는 데 필요하다고 생각되는 추가 정보가 있습니까?' },
  { k: 'focusOne', q: '만일 자녀를 위해 한 가지 일에 집중해야 한다면 어떤 것에 집중하겠습니까?' },
  { k: 'threeMonthHope', q: '앞으로 3개월 내에 자녀가 배우기를 바라는 기술은 무엇입니까?' },
];
function SapBoxes({ total, filled }) {
  return (
    <span className="sap-boxes" aria-label={`${filled}/${total}칸`}>
      {Array.from({ length: total }).map((_, i) => <span key={i} className={`sap-box ${i < filled ? 'on' : ''}`} />)}
    </span>
  );
}
function SapPageHead({ ws, no }) {
  return (
    <div className="sap-page-head">
      <span>{STAGE_PROFILE[ws.meta.stage]?.headline.replace(/ 단계$/, '')}</span>
      <strong>SCERTS 진단 요약지</strong>
      <span>({no})</span>
    </div>
  );
}

function SapSummary({ ws, setWs }) {
  const stageData = STAGE_DATA[ws.meta.stage];
  if (!stageData) {
    return <div className="empty-hint" style={{ padding: 24 }}>단계가 결정되어야 진단 요약지가 생성됩니다.</div>;
  }
  const session = (ws._allSessions || []).find((x) => x.id === ws._sessionId) || null;
  const scores = ws.assessment?.scores || {};
  const ses = ws.assessment?.ses || {};
  const bg = ws.observation?.background || {};
  const q = Number(ws.assessment?.quarter) || Number(session?.quarter) || 0;
  const qStart = (q && bg.quarters?.[q]?.start) || session?.date || '';
  const fp = ws.familyPriorities || {};
  const rows = weeklyGoalRows(ws);
  const childRows = rows.filter((r) => r.group === 'child');
  const partnerRows = rows.filter((r) => r.group === 'partner');
  const sm = ws.observation?.sapSummary || {};
  const saveSm = (patch) => setWs && setWs((s) => ({ ...s, observation: { ...s.observation, sapSummary: { ...(s.observation?.sapSummary || {}), ...patch } } }));
  const groupRow = (dk, g, gi) => {
    const code = stageData[dk].code || '';
    const n = g.items.length * 2;
    const got = g.items.reduce((a, it) => a + (typeof scores[it.id] === 'number' ? scores[it.id] : 0), 0);
    const title = SAP_TITLE_BOOK[ws.meta.stage]?.[`${code}${gi + 1}`] || g.title.replace(/^\d+\.\s*/, '');
    return (
      <div key={g.title} className="sap-prof-row">
        <SapBoxes total={n} filled={got} />
        <span className="sap-prof-label">{code}{gi + 1} {title}</span>
      </div>
    );
  };
  return (
    <div id="printable-report" className="printable sap-book">
      <div className="no-print" style={{ textAlign: 'right', marginBottom: 16 }}>
        <button className="btn-primary" onClick={printReport}>📄 진단 요약지 인쇄</button>
      </div>
      <p className="hint no-print" style={{ marginTop: 0 }}>
        1권 부록 진단 요약지 1~5쪽과 같은 모양입니다. 프로파일 칸은 지금 열려 있는 진단 세션({session?.label || '—'}) 점수로 왼쪽부터 채워지며,
        칸의 절반 미만이 채워진 목표는 상대적 요구, 절반 이상이면 상대적 강점입니다(1권 269쪽).
      </p>

      {/* (1)~(2) SCERTS 프로파일 */}
      <section className="sap-page">
        <SapPageHead ws={ws} no={1} />
        <div className="sap-meta">
          <span>이름: {ws.meta.childName}</span>
          <span>관찰분기 시작일: {qStart}</span>
          <span>나이: {calcAge(ws.meta.birthDate, qStart || undefined)}</span>
        </div>
        <div className="sap-band">SCERTS 프로파일</div>
        {SAP_GROUP_HEAD.map((G) => (
          <div key={G.head}>
            <div className="sap-ghead">{G.head}</div>
            {G.domains.map((dk) => stageData[dk] && (
              <div key={dk} className="sap-domain">
                {dk === 'selfReg' && <div className="page-break-before" style={{ marginTop: 16 }}><SapPageHead ws={ws} no={2} /></div>}
                <div className="sap-dhead">{SAP_DOMAIN_HEAD[dk]}</div>
                {stageData[dk].groups.map((g, gi) => groupRow(dk, g, gi))}
              </div>
            ))}
          </div>
        ))}
      </section>

      {/* (3) 사회-정서 성장 지표 프로파일 + 가족의 견해 및 우선순위 */}
      <section className="sap-page page-break-before">
        <SapPageHead ws={ws} no={3} />
        <div className="sap-band">사회-정서 성장 지표 프로파일</div>
        {SES_INDICATORS.map((ind, i) => (
          <div key={ind.id} className="sap-prof-row">
            <SapBoxes total={10} filled={typeof ses[ind.id] === 'number' ? ses[ind.id] : 0} />
            <span className="sap-prof-label">{i + 1}. {ind.label}</span>
          </div>
        ))}
        <div className="sap-band">가족의 견해 및 우선순위</div>
        {SAP_FAMILY_Q.map((x) => (
          <div key={x.k} className="sap-q">
            <div>{x.q}</div>
            <div className="sap-a">{fp[x.k] || ''}</div>
          </div>
        ))}
        <p className="hint no-print">가족의 답은 진단 탭의 '가족의 견해 및 우선순위'에서 적습니다.</p>
      </section>

      {/* (4) SCERTS 주간 교수목표의 우선순위 */}
      <section className="sap-page page-break-before">
        <SapPageHead ws={ws} no={4} />
        <div className="sap-band">SCERTS 주간 교수목표의 우선순위</div>
        <table className="report-table sap-week">
          <thead><tr><th>아동: 사회 의사소통 및 정서 조절 목표</th><th>파트너: 교류 지원 목표</th></tr></thead>
          <tbody>
            {Array.from({ length: Math.max(8, childRows.length, partnerRows.length) }).map((_, i) => (
              <tr key={i}>
                <td>{i + 1}. {childRows[i] ? `${childRows[i].id ? childRows[i].id + ' ' : ''}${childRows[i].label}` : ''}</td>
                <td>{i + 1}. {partnerRows[i] ? `${partnerRows[i].id ? partnerRows[i].id + ' ' : ''}${partnerRows[i].label}` : ''}</td>
              </tr>
            ))}
          </tbody>
        </table>
        <p className="hint no-print">목표는 IEP 탭에서 고른 주간 우선순위 목표와 파트너 교류 지원 목표가 들어옵니다.</p>
      </section>

      {/* (5) 후속 진단 · 활동 계획 · 지원 계획 */}
      <section className="sap-page page-break-before">
        <SapPageHead ws={ws} no={5} />
        <div className="sap-band">후속 진단-주요 결과 또는 기타 권고사항</div>
        <Editable value={sm.followUp || ''} onChange={(v) => saveSm({ followUp: v })} placeholder="후속 진단-주요 결과 또는 기타 권고사항" multiline minLines={3} />
        <div className="sap-band">활동 계획</div>
        <div style={{ textAlign: 'center' }}>SCERTS 활동 계획서를 사용할 핵심 활동</div>
        <div className="sap-ampm">
          <label><input type="checkbox" checked={!!sm.am} onChange={(e) => saveSm({ am: e.target.checked })} /> 오전 일정</label>
          <label><input type="checkbox" checked={!!sm.pm} onChange={(e) => saveSm({ pm: e.target.checked })} /> 오후 일정</label>
        </div>
        <div className="sap-band">가족 지원 계획</div>
        <BookSupportPlan ws={ws} setWs={setWs} which="familySupport" />
        <div className="sap-band">전문가와 서비스 제공자를 위한 지원 계획</div>
        <BookSupportPlan ws={ws} setWs={setWs} which="profSupport" />
      </section>
    </div>
  );
}

// ★ 지원 계획 표 (1권 부록 진단 요약지 5쪽): 교육 지원 | 정서 지원 — 각각 '활동'과 '얼마나 자주(제공 빈도)'
const SUPPORT_ROWS = 4;
function BookSupportPlan({ ws, setWs, which }) {
  const plan = ws[which]?.bookPlan || {};
  const list = (k) => {
    const arr = plan[k] || [];
    return arr.length >= SUPPORT_ROWS ? arr : [...arr, ...Array(SUPPORT_ROWS - arr.length).fill(null).map(() => ({ act: '', freq: '' }))];
  };
  const edu = list('edu'); const emo = list('emo');
  const save = (k, i, f, v) => setWs && setWs((s) => {
    const cur = s[which] || {};
    const bp = cur.bookPlan || {};
    const arr = [...list(k)];
    arr[i] = { ...arr[i], [f]: v };
    return { ...s, [which]: { ...cur, bookPlan: { ...bp, [k]: arr } } };
  });
  const addRow = () => setWs && setWs((s) => {
    const cur = s[which] || {};
    const bp = cur.bookPlan || {};
    return { ...s, [which]: { ...cur, bookPlan: { ...bp, edu: [...edu, { act: '', freq: '' }], emo: [...emo, { act: '', freq: '' }] } } };
  });
  const n = Math.max(edu.length, emo.length);
  const cell = (k, arr, i, f, ph) => (
    <Editable value={arr[i]?.[f] || ''} onChange={(v) => save(k, i, f, v)} placeholder={ph} multiline />
  );
  return (
    <>
      <table className="report-table sap-support">
        <thead>
          <tr><th colSpan={2}>교육 지원</th><th className="sap-gap" /><th colSpan={2}>정서 지원</th></tr>
          <tr><th>활동</th><th style={{ width: '17%' }}>얼마나 자주<br />(제공 빈도)</th><th className="sap-gap" /><th>활동</th><th style={{ width: '17%' }}>얼마나 자주<br />(제공 빈도)</th></tr>
        </thead>
        <tbody>
          {Array.from({ length: n }).map((_, i) => (
            <tr key={i}>
              <td>{cell('edu', edu, i, 'act', '활동')}</td>
              <td>{cell('edu', edu, i, 'freq', '빈도')}</td>
              <td className="sap-gap" />
              <td>{cell('emo', emo, i, 'act', '활동')}</td>
              <td>{cell('emo', emo, i, 'freq', '빈도')}</td>
            </tr>
          ))}
        </tbody>
      </table>
      {setWs && <div className="no-print" style={{ textAlign: 'right', marginTop: 4 }}><button className="btn-ghost btn-small" onClick={addRow}>+ 줄 추가</button></div>}
    </>
  );
}

// 예전 양식으로 쓴 내용 — 지우지 않고 그대로 보여 준다(새 화면에는 책 양식만)
function LegacyPlanView({ data, fields }) {
  const lines = [];
  fields.forEach(([k, label]) => {
    const v = data?.[k];
    if (!v) return;
    if (typeof v === 'string') { if (v.trim()) lines.push([label, v]); return; }
    if (Array.isArray(v)) {
      const t = v.map((x) => (typeof x === 'string' ? x : Object.values(x || {}).filter(Boolean).join(' / '))).filter((x) => x && x.trim()).join('\n');
      if (t && !(k === 'homeStrategies' && v.every((x) => !x.strategy && !x.whenToUse && !x.resourcesNeeded)) && !(k === 'roleResponsibilities' && v.every((x) => !x.name && !x.responsibilities))) lines.push([label, t]);
      return;
    }
    if (typeof v === 'object') {
      const t = Object.values(v).filter((x) => typeof x === 'string' && x.trim()).join(' / ');
      if (t) lines.push([label, t]);
    }
  });
  if (!lines.length) return null;
  return (
    <details className="legacy-plan no-print" style={{ marginTop: 16 }}>
      <summary>예전 양식으로 적어 둔 내용 보기 (책 양식 아님 · 지우지 않고 보관)</summary>
      <table className="report-table" style={{ marginTop: 8 }}>
        <tbody>
          {lines.map(([l, v]) => <tr key={l}><th style={{ width: '22%' }}>{l}</th><td style={{ whiteSpace: 'pre-wrap' }}>{v}</td></tr>)}
        </tbody>
      </table>
    </details>
  );
}

function FamilySupportForm({ ws, setWs }) {
  return (
    <div id="printable-report" className="printable">
      <div className="no-print" style={{ marginBottom: 16, textAlign: 'right' }}>
        <button className="btn-primary" onClick={printReport}>📄 가족 지원 계획 인쇄</button>
      </div>
      <ReportHeader title="가족 지원 계획" ws={ws} />
      <p className="hint no-print">1권 부록 진단 요약지 5쪽의 '가족 지원 계획' 표입니다. 진단 요약지 5쪽에도 같은 내용이 들어갑니다.</p>
      <BookSupportPlan ws={ws} setWs={setWs} which="familySupport" />
      <LegacyPlanView data={ws.familySupport} fields={[
        ['meta', '계획 주간·면담 일자·참여자'], ['currentConcerns', '가족의 주된 관심사·우려'], ['childStrengths', '아동의 강점·흥미'],
        ['familyGoals', '가족이 우선시하는 목표'], ['homeStrategies', '가정 내 적용 전략'], ['educationTopics', '가족 교육·정보 제공 주제'],
        ['followUp', '후속 조치 사항'], ['nextMeeting', '다음 면담 일정'],
      ]} />
    </div>
  );
}

function ProfSupportForm({ ws, setWs }) {
  return (
    <div id="printable-report" className="printable">
      <div className="no-print" style={{ marginBottom: 16, textAlign: 'right' }}>
        <button className="btn-primary" onClick={printReport}>📄 지원 계획 인쇄</button>
      </div>
      <ReportHeader title="전문가와 서비스 제공자를 위한 지원 계획" ws={ws} />
      <p className="hint no-print">1권 부록 진단 요약지 5쪽의 '전문가와 서비스 제공자를 위한 지원 계획' 표입니다. 진단 요약지 5쪽에도 같은 내용이 들어갑니다.</p>
      <BookSupportPlan ws={ws} setWs={setWs} which="profSupport" />
      <LegacyPlanView data={ws.profSupport} fields={[
        ['meta', '계획 주간·회의 일자·팀 구성원'], ['sharedObservations', '공유된 관찰'], ['currentChallenges', '현재 어려움'],
        ['collaborativeGoals', '팀 공동 목표'], ['roleResponsibilities', '역할 분담'], ['communicationPlan', '소통 계획'],
        ['caseConferenceNotes', '사례 회의 기록'], ['nextReview', '다음 검토 일정'],
      ]} />
    </div>
  );
}

function ActivityStats({ ws }) {
  const logs = ws.activities?.logI || [];
  const rows = weeklyGoalRows(ws);
  const list = rows.map((r) => {
    const hist = weeklyHistory(ws, r.key);
    const last = hist.length ? hist[hist.length - 1].score : null;
    const zr = zeroRun(hist);
    const logCount = logs.filter((l) => ['goalsSocial', 'goalsEmo', 'partnerGoals'].some((k) => (l[k] || []).some((g) =>
      g && (g.observed || g.rating) && (r.id ? (g.goal || '').includes(r.id) : (g.goal || '').trim() === r.label)))
      || [...(l.bookChild || []), ...(l.bookPartner || [])].some((b) => b && (b.note || []).some((n) => n && n.trim())
        && (r.id ? (b.goal || '').includes(r.id) : (b.goal || '').trim() === r.label))).length;
    const status = hist.length === 0 ? 'noData' : zr.now >= 3 ? 'stalled' : last === 2 ? 'mastered' : 'progressing';
    return { ...r, hist, last, logCount, status };
  });
  const datesByMonth = {};
  logs.forEach((l) => { if (l.date) { const ym = l.date.slice(0, 7); datesByMonth[ym] = (datesByMonth[ym] || 0) + 1; } });
  const stalled = list.filter((g) => g.status === 'stalled');
  const statusText = { mastered: '최근 2점', progressing: '진행 중', stalled: '3주 연속 0점', noData: '— 기록 없음' };
  const section = (group, title) => {
    const items = list.filter((g) => g.group === group);
    if (items.length === 0) return null;
    return (
      <section className="report-section" key={group}>
        <h3 className="report-h3">{title}</h3>
        <table className="report-table stats-table">
          <thead>
            <tr>
              <th style={{ width: '42%' }}>목표</th>
              <th style={{ textAlign: 'center' }}>활동 일지 기록</th>
              <th style={{ textAlign: 'center' }}>주간 점수 흐름</th>
              <th style={{ textAlign: 'center' }}>상태</th>
            </tr>
          </thead>
          <tbody>
            {items.map((g) => (
              <tr key={g.key} className={`stats-row stats-row-${g.status}`}>
                <td>{g.id ? `${g.id} ` : ''}{g.label}</td>
                <td style={{ textAlign: 'center' }}>{g.logCount}회</td>
                <td style={{ textAlign: 'center' }}>{g.hist.length ? g.hist.map((h) => h.score).join(' → ') : '—'}</td>
                <td style={{ textAlign: 'center' }}><span className={`status-badge status-${g.status}`}>{statusText[g.status]}</span></td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>
    );
  };
  if (rows.length === 0 && logs.length === 0) {
    return (
      <div className="empty-hint" style={{ padding: 30, textAlign: 'center' }}>
        아직 기록이 없습니다.<br />IEP에서 주간 목표를 고르고, 활동 일지와 주간 기록지를 쓰면 여기에 진도가 정리됩니다.
      </div>
    );
  }
  return (
    <div className="activity-stats">
      <div className="stats-summary-grid">
        <div className="stats-summary-card"><div className="stats-num">{logs.length}</div><div className="stats-label">기록된 회기</div></div>
        <div className="stats-summary-card"><div className="stats-num">{list.filter((g) => g.hist.length).length}</div><div className="stats-label">주간 점수가 있는 목표</div></div>
        <div className="stats-summary-card mastered"><div className="stats-num">{list.filter((g) => g.status === 'mastered').length}</div><div className="stats-label">최근 주 2점 목표</div></div>
        <div className="stats-summary-card stalled"><div className="stats-num">{stalled.length}</div><div className="stats-label">3주 연속 0점 목표</div></div>
      </div>
      {stalled.length > 0 && (
        <div className="info-box" style={{ borderColor: '#b54a3a', background: '#fef0e0' }}>
          <strong>⚠ 3주 연속 0점인 목표 {stalled.length}개</strong><br />
          책은 이런 목표를 더 낮은 수준의 목표로 바꾸거나 활동·교류 지원을 수정하라고 안내합니다(1권 269쪽).
        </div>
      )}
      {section('child', '아동 목표 (주간 기록지)')}
      {section('partner', '파트너 교류 지원 목표 (주간 기록지)')}
      <section className="report-section">
        <h3 className="report-h3">월별 회기 분포</h3>
        <div className="month-distribution">
          {Object.entries(datesByMonth).sort(([x], [y]) => x.localeCompare(y)).map(([month, count]) => (
            <div key={month} className="month-bar">
              <div className="month-label">{month}</div>
              <div className="month-bar-bar"><div className="month-bar-fill" style={{ width: `${Math.min(100, count * 12)}%` }}>{count}회</div></div>
            </div>
          ))}
          {Object.keys(datesByMonth).length === 0 && <div className="empty-hint" style={{ padding: 16 }}>날짜가 기록된 회기가 없습니다.</div>}
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
        centerDoc
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

      <ApprovalBlock therapist={ws.meta.therapist} />
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
        centerDoc
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

      <ApprovalBlock therapist={ws.meta.therapist} />
    </div>
  );
}

function ApprovalBlock({ reportDate, therapist }) {
  // ★ 담당 교사 칸은 그 아이의 '치료사' 이름으로 (전에는 모든 보고서에 원장님 이름이 고정)
  const teacherName = String(therapist || '').trim();
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
            <td>{teacherName ? `${teacherName} (서명)` : '(서명)'}</td>
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
                  onClick={async () => {
                    // ★ 이미 쓴 글이 있으면 지우기 전에 먼저 묻는다
                    if (value && String(value).trim() && !await appConfirm('지금 칸에 쓴 글을 지우고 이 예시로 바꿀까요?')) return;
                    onChange(ex); setShowEx(false);
                  }}
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
.ses-row-calc { grid-template-columns: 170px 1fr 150px; }
.ses-formula { font-size: 12px; color: #6b6b6b; line-height: 1.5; }
.ses-unscored { color: #b54a3a; }
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
.iq-old-text { font-size: 12.5px; color: #6b5320; background: #fef7e6; border: 1px dashed #c19a3a; border-radius: 6px; padding: 7px 10px; margin-bottom: 8px; white-space: pre-wrap; }
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
.score-subs { display: flex; flex-wrap: wrap; gap: 4px 12px; width: 100%; margin-top: 6px; font-size: 12.5px; }
.score-sub { display: inline-flex; align-items: center; gap: 4px; cursor: pointer; }
.score-sub input[type=checkbox] { width: 15px; height: 15px; margin: 0; }
.score-sub-other { width: 120px; height: 24px; font-size: 12px; padding: 2px 6px; margin-left: 4px; }
.obs-bg-table textarea { width: 100%; min-height: 54px; font-size: 13px; }
.obs-bg-boxes { display: flex; flex-wrap: wrap; gap: 6px 18px; }
.obs-bg-box { display: inline-flex; align-items: center; gap: 4px; font-size: 13px; }
.obs-bg-box input[type=text] { width: 130px; height: 26px; font-size: 12.5px; padding: 2px 6px; }
.obs-bg-vars { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 2px 12px; font-size: 12.5px; }
.obs-bg-two { display: grid; grid-template-columns: minmax(0, 1fr) minmax(0, 1fr); gap: 12px; margin-top: 12px; align-items: start; }
.obs-bg-two input[type=date] { font-size: 12px; height: 26px; }
.obs-bg-criteria { font-size: 12.5px; line-height: 1.6; border: 1px solid #d9d1bd; border-radius: 6px; padding: 8px 10px; }
@media (max-width: 720px) { .obs-bg-two { grid-template-columns: minmax(0, 1fr); } .obs-bg-vars { grid-template-columns: minmax(0, 1fr); } }
.center-doc-tag { text-align: center; font-size: 11.5px; color: #8a7a55; margin: -6px 0 10px; }
.sap-page { margin-bottom: 18px; }
.sap-page-head { display: flex; justify-content: space-between; align-items: center; border: 1px solid #3a6ea5; border-radius: 4px; padding: 6px 10px; margin-bottom: 10px; font-size: 13px; }
.sap-page-head strong { font-size: 15px; }
.sap-meta { display: flex; flex-wrap: wrap; gap: 6px 28px; font-size: 13px; margin-bottom: 10px; }
.sap-band { background: #e8f2fb; border: 1px solid #b7cfe6; text-align: center; padding: 5px; font-size: 13.5px; font-weight: 600; margin: 12px 0 8px; }
.sap-ghead { text-align: right; font-size: 12.5px; margin: 8px 0 2px; }
.sap-dhead { font-size: 13px; font-weight: 600; margin: 6px 0 4px; }
.sap-prof-row { display: flex; align-items: center; gap: 10px; margin: 3px 0; }
.sap-boxes { display: inline-flex; flex: 0 0 auto; width: 260px; border: 1px solid #555; }
.sap-box { flex: 1 1 0; height: 16px; border-right: 1px solid #555; }
.sap-box:last-child { border-right: none; }
.sap-box.on { background: #7aa7d6; }
.sap-prof-label { font-size: 13px; }
.sap-q { margin: 10px 0; font-size: 13px; }
.sap-a { min-height: 40px; border-bottom: 1px dashed #c9bfa6; padding: 4px 2px; white-space: pre-wrap; }
.sap-ampm { display: flex; justify-content: center; gap: 40px; margin: 6px 0 10px; font-size: 13px; }
.sap-support .sap-gap { width: 10px; background: #f3efe4; border-top: none; border-bottom: none; padding: 0; }
.sap-book .sap-box.on { -webkit-print-color-adjust: exact; print-color-adjust: exact; }
@media (max-width: 720px) { .sap-boxes { width: 150px; } }
.book-log-kind { display: flex; flex-wrap: wrap; align-items: center; gap: 8px 16px; font-size: 13px; margin-bottom: 10px; }
.book-log-kind label { display: inline-flex; align-items: center; gap: 4px; }
.book-log-title { text-align: center; }
.book-log-meta { display: flex; flex-wrap: wrap; gap: 6px 28px; font-size: 13px; margin: 6px 0 12px; }
.book-log-meta input[type=date] { height: 26px; font-size: 12.5px; }
.book-log-h { font-size: 13.5px; }
.book-log-table td { vertical-align: top; }
.book-log-goal { width: 34%; }
.book-log-line { display: flex; gap: 6px; align-items: flex-start; font-size: 13px; }
.book-log-line > span { flex: 0 0 auto; color: #5a5242; padding-top: 4px; }
.book-log-line > *:last-child { flex: 1 1 auto; min-width: 0; }
.book-log-guide { font-size: 12px; line-height: 1.6; margin-top: 8px; }
.xs-head { display: grid; grid-template-columns: auto 1fr auto auto; gap: 10px; align-items: center; border: 1px solid #3a6ea5; border-radius: 4px; padding: 6px 10px; font-size: 13px; }
.xs-head strong { text-align: center; font-size: 15px; }
.xs-name { font-weight: 600; }
.xs-meta { display: grid; grid-template-columns: 1fr 1fr; gap: 6px 24px; font-size: 13px; margin: 10px 0; }
.xs-cont { text-align: right; font-size: 12px; margin-bottom: 4px; }
.xs-table { font-size: 11.5px; }
.xs-table td, .xs-table th { padding: 3px 4px; }
.xs-table td { height: 20px; }
.xs-center { text-align: center; font-weight: 600; background: #eef5fb; }
.xs-sub { font-weight: 600; background: #f7f3e8; }
.xs-label-col { min-width: 150px; }
.xs-intent .xs-label-col { width: 150px; }
.xs-vert { writing-mode: vertical-rl; text-orientation: upright; letter-spacing: -2px; padding: 4px 0 !important; font-weight: 400; height: 196px; vertical-align: top; white-space: nowrap; font-size: 11px; line-height: 1; }
.xs-table th { background: #e8f2fb !important; color: #1f3550 !important; }
.xs-tick { width: 22px; text-align: center; }
.xs-blank { border-top: none !important; background: transparent; }
.xs-emo-col { font-weight: 400; font-size: 10.5px; width: 62px; vertical-align: bottom; }
.xs-boxcol { width: 74px; text-align: center; font-size: 14px; letter-spacing: 1px; }
.xs-boxes { line-height: 1.2; }
.xs-indent { padding-left: 14px !important; }
.xs-list td { height: auto; vertical-align: top; }
.xs-source { font-size: 12px; margin-top: 6px; }
.xs-pick { display: flex; flex-wrap: wrap; gap: 6px; align-items: center; margin-bottom: 12px; }
.xs-sheet { overflow-x: auto; }
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
