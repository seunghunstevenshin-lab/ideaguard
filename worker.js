/**
 * IdeaGuard — Cloudflare Workers API
 * Lead Architect: Claude
 * Zero-Knowledge 원칙: 원본 텍스트/파일은 절대 이 Worker를 경유하지 않음
 * 오직 해시값 + 메타데이터만 처리
 */

import { createClient } from '@supabase/supabase-js';

// ──────────────────────────────────────────────────────────────────────────────
// 보안 헤더
// ──────────────────────────────────────────────────────────────────────────────
function addSecurityHeaders(response, env) {
  const headers = new Headers(response.headers);
  const isProd = env.ENVIRONMENT === 'production';

  headers.set('Access-Control-Allow-Origin', isProd ? 'https://ideaguard.app' : '*');
  headers.set('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  headers.set('Access-Control-Allow-Headers', 'Content-Type, Authorization');

  if (isProd) {
    headers.set('Strict-Transport-Security', 'max-age=31536000; includeSubDomains; preload');
    headers.set('X-Content-Type-Options', 'nosniff');
    headers.set('X-Frame-Options', 'DENY');
    headers.set('X-XSS-Protection', '1; mode=block');
    headers.set('Content-Security-Policy',
      "default-src 'self'; " +
      "script-src 'self' 'unsafe-inline' cdn.jsdelivr.net; " +
      "style-src 'self' 'unsafe-inline' fonts.googleapis.com cdn.jsdelivr.net; " +
      "font-src fonts.gstatic.com cdn.jsdelivr.net; " +
      "img-src 'self' data: blob:; " +
      "connect-src 'self' *.supabase.co;"
    );
  }

  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers,
  });
}

// ──────────────────────────────────────────────────────────────────────────────
// 유틸리티
// ──────────────────────────────────────────────────────────────────────────────
function jsonResponse(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

function errorResponse(message, status = 400) {
  return jsonResponse({ error: message }, status);
}

async function sha256(text) {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text));
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
}

/** Supabase 클라이언트 생성 (요청마다 service key로) */
function getSupabase(env) {
  return createClient(env.SUPABASE_URL, env.SUPABASE_SERVICE_KEY, {
    auth: { persistSession: false },
  });
}

// ──────────────────────────────────────────────────────────────────────────────
// 입력값 검증
// ──────────────────────────────────────────────────────────────────────────────
function isValidHash(hash) {
  return typeof hash === 'string' && /^[0-9a-f]{64}$/i.test(hash);
}
function isValidNickname(nick) {
  return typeof nick === 'string' && nick.trim().length >= 1 && nick.trim().length <= 30;
}
function isValidEmail(email) {
  return typeof email === 'string' && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}
function isValidRecipientName(name) {
  return typeof name === 'string' && name.trim().length >= 1 && name.trim().length <= 50;
}
const ALLOWED_COUNTRY_CODES = ['KR', 'US', 'UK', 'JP', 'SG', 'DE', 'FR', 'CN', 'AU', 'CA'];
function isValidCountryCode(code) {
  return ALLOWED_COUNTRY_CODES.includes(code);
}

// ──────────────────────────────────────────────────────────────────────────────
// 라우터
// ──────────────────────────────────────────────────────────────────────────────
async function handleRequest(request, env) {
  const url = new URL(request.url);
  const path = url.pathname;
  const method = request.method;

  if (method === 'OPTIONS') return new Response(null, { status: 204 });

  if (path === '/api/records' && method === 'POST') return handleRegister(request, env);
  if (path === '/api/records' && method === 'GET')  return handleGetTiles(request, env);
  if (path === '/api/records/verify' && method === 'POST') return handleVerify(request, env);
  if (path === '/api/nda' && method === 'POST') return handleCreateNDA(request, env);

  const ndaGetMatch  = path.match(/^\/api\/nda\/([^/]+)$/);
  if (ndaGetMatch  && method === 'GET')  return handleGetNDA(request, env, ndaGetMatch[1]);

  const ndaSignMatch = path.match(/^\/api\/nda\/([^/]+)\/sign$/);
  if (ndaSignMatch && method === 'POST') return handleSignNDA(request, env, ndaSignMatch[1]);

  // 헬스체크 — 프로덕션에서는 상세 정보 노출 않음
  if (path === '/api/health' && method === 'GET') {
    const isProd = env.ENVIRONMENT === 'production';
    return jsonResponse(isProd
      ? { status: 'ok' }
      : { status: 'ok', app: env.APP_NAME, env: env.ENVIRONMENT }
    );
  }

  return errorResponse('Not Found', 404);
}

// ──────────────────────────────────────────────────────────────────────────────
// 핸들러: 해시 등록
// ──────────────────────────────────────────────────────────────────────────────
async function handleRegister(request, env) {
  let body;
  try { body = await request.json(); } catch { return errorResponse('요청 형식 오류'); }

  // 해시 등록 단순화: hash만 필수. nickname/title은 NDA 생성 시 입력.
  const { hash, user_id } = body;

  if (!isValidHash(hash)) return errorResponse('유효하지 않은 해시값');

  const db = getSupabase(env);
  const { data, error } = await db.from('records').insert({
    hash: hash.toLowerCase(),
    nickname: '익명',           // 기본값 — 회원 로그인 후 NDA 시 실명 사용
    title:    '',               // 기본값 — NDA 생성 시 아이디어 제목 입력
    keywords: [],
    user_id: user_id || null,
  }).select().single();

  if (error) {
    if (error.code === '23505') return errorResponse('이미 등록된 해시값입니다', 409);
    console.error('[register error]', error.code, error.message);
    return errorResponse('등록 중 오류가 발생했습니다', 500);
  }

  return jsonResponse({ success: true, record: data }, 201);
}

// ──────────────────────────────────────────────────────────────────────────────
// 핸들러: 타일 보드 조회
// ──────────────────────────────────────────────────────────────────────────────
async function handleGetTiles(request, env) {
  const url = new URL(request.url);
  const page  = Math.max(1, parseInt(url.searchParams.get('page')  || '1'));
  const limit = Math.min(20, parseInt(url.searchParams.get('limit') || '12'));
  const offset = (page - 1) * limit;

  const db = getSupabase(env);
  const { data, error } = await db
    .from('records')
    .select('id, hash, nickname, title, keywords, created_at')
    .order('created_at', { ascending: false })
    .range(offset, offset + limit - 1);

  if (error) {
    console.error('[tiles error]', error.message, error.code, error.hint);
    return errorResponse('데이터 조회 중 오류가 발생했습니다', 500);
  }

  return jsonResponse({ records: data || [], page, limit });
}

// ──────────────────────────────────────────────────────────────────────────────
// 핸들러: 해시 검증
// ──────────────────────────────────────────────────────────────────────────────
async function handleVerify(request, env) {
  let body;
  try { body = await request.json(); } catch { return errorResponse('요청 형식 오류'); }

  const { hash } = body;
  if (!isValidHash(hash)) return errorResponse('유효하지 않은 해시값');

  const db = getSupabase(env);
  const { data, error } = await db
    .from('records')
    .select('id, hash, nickname, title, keywords, created_at')
    .eq('hash', hash.toLowerCase())
    .single();

  if (error && error.code !== 'PGRST116') {
    console.error('[verify error]', error.message);
    return errorResponse('검증 중 오류가 발생했습니다', 500);
  }

  if (!data) return jsonResponse({ verified: false, message: '등록된 해시값을 찾을 수 없습니다' });
  return jsonResponse({ verified: true, record: data });
}

// ──────────────────────────────────────────────────────────────────────────────
// 핸들러: NDA 생성
// ──────────────────────────────────────────────────────────────────────────────
async function handleCreateNDA(request, env) {
  let body;
  try { body = await request.json(); } catch { return errorResponse('요청 형식 오류'); }

  const { record_id, proposer_id, recipient_email, recipient_name, country_code, contract_text, is_custom_template } = body;

  if (!record_id)                            return errorResponse('record_id 필요');
  if (!proposer_id)                          return errorResponse('회원 전용 기능입니다', 401);
  if (!isValidEmail(recipient_email))        return errorResponse('유효하지 않은 이메일');
  if (!isValidRecipientName(recipient_name)) return errorResponse('수령자 이름은 1~50자');
  if (!isValidCountryCode(country_code))     return errorResponse('지원하지 않는 국가 코드');
  if (!contract_text || contract_text.trim().length < 50) return errorResponse('계약서 내용이 너무 짧습니다');

  const rawToken  = crypto.randomUUID() + '-' + Date.now();
  const tokenHash = await sha256(rawToken);

  const db = getSupabase(env);
  const { data, error } = await db.from('ndas').insert({
    record_id,
    proposer_id,
    recipient_email,
    recipient_name: recipient_name.trim(),
    country_code,
    contract_text: contract_text.trim(),
    is_custom_template: !!is_custom_template,
    status: 'pending',
    token_hash: tokenHash,
  }).select().single();

  if (error) {
    console.error('[nda create error]', error.message);
    return errorResponse('NDA 생성 중 오류가 발생했습니다', 500);
  }

  return jsonResponse({
    success: true,
    nda_id: data.id,
    message: '계약서가 생성되었습니다.',
    ...(env.ENVIRONMENT === 'development' ? { _dev_token: rawToken } : {}),
  }, 201);
}

// ──────────────────────────────────────────────────────────────────────────────
// 핸들러: NDA 조회
// ──────────────────────────────────────────────────────────────────────────────
async function handleGetNDA(request, env, tokenOrId) {
  const db = getSupabase(env);
  const isUUID = /^[0-9a-f-]{36}$/.test(tokenOrId);

  let query = db.from('ndas')
    .select('id, record_id, recipient_email, recipient_name, country_code, contract_text, is_custom_template, status, created_at');

  query = isUUID
    ? query.eq('id', tokenOrId)
    : query.eq('token_hash', await sha256(tokenOrId));

  const { data, error } = await query.single();

  if (error || !data) return errorResponse('유효하지 않은 링크입니다', 404);
  if (data.status === 'signed') return errorResponse('이미 서명이 완료된 계약서입니다', 410);

  return jsonResponse({ nda: data });
}

// ──────────────────────────────────────────────────────────────────────────────
// 핸들러: NDA 서명 (IP는 반드시 서버에서 캡처)
// ──────────────────────────────────────────────────────────────────────────────
async function handleSignNDA(request, env, token) {
  let body;
  try { body = await request.json(); } catch { return errorResponse('요청 형식 오류'); }

  const { signature_base64 } = body;
  if (!signature_base64 || typeof signature_base64 !== 'string') return errorResponse('서명 데이터가 필요합니다');
  if (signature_base64.length > 200000) return errorResponse('서명 이미지가 너무 큽니다');

  const tokenHash = await sha256(token);
  const db = getSupabase(env);

  const { data: nda, error: findErr } = await db
    .from('ndas').select('id, status').eq('token_hash', tokenHash).single();

  if (findErr || !nda) return errorResponse('유효하지 않은 링크입니다', 404);
  if (nda.status === 'signed') return errorResponse('이미 서명이 완료된 계약서입니다', 410);

  // IP 캡처 — 반드시 서버에서 (클라이언트 IP 신뢰 불가)
  const auditTrail = {
    ip:         request.headers.get('CF-Connecting-IP') || 'unknown',
    user_agent: request.headers.get('User-Agent')       || 'unknown',
    country:    request.headers.get('CF-IPCountry')     || 'unknown',
    signed_at:  new Date().toISOString(),
  };

  const { error: updateErr } = await db.from('ndas').update({
    status:               'signed',
    recipient_signature:  signature_base64,
    signed_at:            auditTrail.signed_at,
    audit_trail:          auditTrail,
  }).eq('id', nda.id);

  if (updateErr) {
    console.error('[nda sign error]', updateErr.message);
    return errorResponse('서명 처리 중 오류가 발생했습니다', 500);
  }

  return jsonResponse({ success: true, message: '서명이 완료되었습니다.', signed_at: auditTrail.signed_at });
}

// ──────────────────────────────────────────────────────────────────────────────
// 메인 fetch 핸들러
// ──────────────────────────────────────────────────────────────────────────────
export default {
  async fetch(request, env) {
    try {
      const response = await handleRequest(request, env);
      return addSecurityHeaders(response, env);
    } catch (err) {
      console.error('[IdeaGuard Worker Error]', err?.message || err);
      return addSecurityHeaders(errorResponse('서버 오류가 발생했습니다', 500), env);
    }
  },
};
