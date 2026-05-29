-- ============================================================
-- IdeaGuard — Supabase DB 스키마
-- Supabase SQL Editor에서 실행
-- Zero-Knowledge 원칙: originalContent 컬럼 없음
-- ============================================================

-- ──────────────────────────────────────────────────────────
-- 1. records — 해시 등록 테이블 (공개 타일 보드)
-- ──────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS records (
  id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  hash        TEXT        NOT NULL UNIQUE,           -- SHA-256 해시값 (소문자 hex 64자)
  nickname    TEXT        NOT NULL,                  -- 게스트/회원 표기명
  title       TEXT        NOT NULL,                  -- 아이디어 공개 제목
  keywords    TEXT[]      DEFAULT '{}',              -- 공개 키워드 (최대 5개)
  user_id     UUID        REFERENCES auth.users(id), -- NULL = 게스트
  created_at  TIMESTAMPTZ DEFAULT NOW()
);

-- 해시 조회 성능 인덱스
CREATE INDEX IF NOT EXISTS idx_records_hash ON records(hash);
CREATE INDEX IF NOT EXISTS idx_records_created_at ON records(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_records_user_id ON records(user_id);

-- ──────────────────────────────────────────────────────────
-- 2. ndas — 비밀유지계약 테이블
-- ──────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS ndas (
  id                   UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  record_id            UUID        NOT NULL REFERENCES records(id) ON DELETE CASCADE,
  proposer_id          UUID        NOT NULL REFERENCES auth.users(id),
  recipient_email      TEXT        NOT NULL,
  country_code         TEXT        NOT NULL DEFAULT 'KR',
  contract_text        TEXT        NOT NULL,
  is_custom_template   BOOLEAN     DEFAULT false,
  status               TEXT        NOT NULL DEFAULT 'pending'
                       CHECK (status IN ('pending', 'signed', 'expired', 'cancelled')),
  token_hash           TEXT        NOT NULL UNIQUE,  -- SHA-256(plaintext_token), plaintext는 DB 저장 금지
  recipient_signature  TEXT,                         -- Base64 PNG 서명 이미지
  signed_at            TIMESTAMPTZ,
  audit_trail          JSONB,                        -- { ip, user_agent, country, signed_at }
  created_at           TIMESTAMPTZ DEFAULT NOW(),
  expires_at           TIMESTAMPTZ DEFAULT (NOW() + INTERVAL '30 days')
);

CREATE INDEX IF NOT EXISTS idx_ndas_token_hash ON ndas(token_hash);
CREATE INDEX IF NOT EXISTS idx_ndas_proposer_id ON ndas(proposer_id);
CREATE INDEX IF NOT EXISTS idx_ndas_record_id ON ndas(record_id);
CREATE INDEX IF NOT EXISTS idx_ndas_status ON ndas(status);

-- ──────────────────────────────────────────────────────────
-- 3. RLS (Row Level Security) 정책
-- ──────────────────────────────────────────────────────────

-- records: 공개 읽기 허용, 삽입은 anon 포함 허용
ALTER TABLE records ENABLE ROW LEVEL SECURITY;

CREATE POLICY "records_public_read" ON records
  FOR SELECT USING (true);

CREATE POLICY "records_insert_anon" ON records
  FOR INSERT WITH CHECK (true);

-- 회원은 자신의 레코드만 수정/삭제 가능
CREATE POLICY "records_update_owner" ON records
  FOR UPDATE USING (auth.uid() = user_id);

CREATE POLICY "records_delete_owner" ON records
  FOR DELETE USING (auth.uid() = user_id);

-- ndas: 갑(proposer)과 을(recipient)만 읽기 가능
ALTER TABLE ndas ENABLE ROW LEVEL SECURITY;

-- 서비스 키(worker.js)에서만 조작 — 프론트에서 직접 접근 불가
-- (Supabase anon 키로는 ndas 접근 차단)
CREATE POLICY "ndas_service_only" ON ndas
  FOR ALL USING (false);  -- 모든 anon/user 직접 접근 차단, service_role만 가능

-- ──────────────────────────────────────────────────────────
-- 4. 만료 NDA 자동 처리 (선택 — Supabase pg_cron 활성화 필요)
-- ──────────────────────────────────────────────────────────
-- SELECT cron.schedule('expire-ndas', '0 * * * *', $$
--   UPDATE ndas SET status = 'expired'
--   WHERE status = 'pending' AND expires_at < NOW();
-- $$);

-- ──────────────────────────────────────────────────────────
-- 5. 타입 및 제약 확인용 뷰 (선택)
-- ──────────────────────────────────────────────────────────
-- CREATE VIEW public_tiles AS
--   SELECT id, hash, nickname, title, keywords, created_at
--   FROM records ORDER BY created_at DESC;
