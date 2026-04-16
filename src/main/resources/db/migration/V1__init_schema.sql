-- ═══════════════════════════════════════════════════════════════
-- V1 — Initial Schema
-- ═══════════════════════════════════════════════════════════════

-- pgvector extension (required for vector(1536) type and <=> operator)
CREATE EXTENSION IF NOT EXISTS vector;

-- ── Embeddings: RAG knowledge base ───────────────────────────────────
-- Stores chunked control definitions from NIST 800-53, CIS Benchmark, SOC2.
-- Section-aware chunking: each row = one complete control definition.
CREATE TABLE embeddings (
    id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    framework   VARCHAR(50) NOT NULL,           -- NIST-800-53 | CIS-AWS | SOC2
    control_id  VARCHAR(50) NOT NULL,           -- AC-3, SC-8, SI-2, etc.
    severity    VARCHAR(20),                     -- HIGH | MEDIUM | LOW
    content     TEXT        NOT NULL,            -- full control text chunk
    embedding   vector(1536),                   -- OpenAI text-embedding-ada-002
    created_at  TIMESTAMP   NOT NULL DEFAULT NOW()
);

-- ivfflat index for cosine similarity search (faster than exact scan)
CREATE INDEX embeddings_embedding_idx
    ON embeddings USING ivfflat (embedding vector_cosine_ops)
    WITH (lists = 100);

-- ── Scan runs: raw AWS environment snapshots ──────────────────────────
CREATE TABLE scan_runs (
    id            UUID      PRIMARY KEY DEFAULT gen_random_uuid(),
    snapshot_json JSONB     NOT NULL,
    created_at    TIMESTAMP NOT NULL DEFAULT NOW()
);

-- ── Violations: compliance findings ──────────────────────────────────
CREATE TABLE violations (
    id             UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_run_id    UUID        REFERENCES scan_runs(id),
    resource_id    VARCHAR(255) NOT NULL,
    resource_type  VARCHAR(100),
    control_id     VARCHAR(50)  NOT NULL,
    framework      VARCHAR(50)  NOT NULL,
    severity       VARCHAR(20)  NOT NULL,
    reasoning      TEXT         NOT NULL,
    cited_excerpt  TEXT,
    first_seen_at  TIMESTAMP    NOT NULL DEFAULT NOW(),
    is_new         BOOLEAN      NOT NULL DEFAULT TRUE,
    created_at     TIMESTAMP    NOT NULL DEFAULT NOW()
);

CREATE INDEX violations_scan_run_idx    ON violations(scan_run_id);
CREATE INDEX violations_framework_idx   ON violations(framework);
CREATE INDEX violations_severity_idx    ON violations(severity);
CREATE INDEX violations_is_new_idx      ON violations(is_new);

-- ── Remediation plans ─────────────────────────────────────────────────
CREATE TABLE remediation_plans (
    id               UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    violation_id     UUID        REFERENCES violations(id),
    steps            TEXT        NOT NULL,
    cli_commands     TEXT,
    terraform_patch  TEXT,
    auto_remediable  BOOLEAN     NOT NULL DEFAULT FALSE,
    approval_status  VARCHAR(20) NOT NULL DEFAULT 'PENDING',  -- PENDING | APPROVED | REJECTED
    created_at       TIMESTAMP   NOT NULL DEFAULT NOW(),
    updated_at       TIMESTAMP   NOT NULL DEFAULT NOW()
);

-- ── Compliance reports ────────────────────────────────────────────────
CREATE TABLE compliance_reports (
    id               UUID             PRIMARY KEY DEFAULT gen_random_uuid(),
    nist_score       DOUBLE PRECISION,
    cis_score        DOUBLE PRECISION,
    soc2_score       DOUBLE PRECISION,
    total_violations INTEGER,
    s3_key           VARCHAR(255),
    created_at       TIMESTAMP        NOT NULL DEFAULT NOW()
);

-- ── Pipeline runs ─────────────────────────────────────────────────────
CREATE TABLE pipeline_runs (
    id               UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    start_time       TIMESTAMP   NOT NULL DEFAULT NOW(),
    end_time         TIMESTAMP,
    status           VARCHAR(20) NOT NULL DEFAULT 'RUNNING',  -- RUNNING | COMPLETED | FAILED
    violations_found INTEGER     DEFAULT 0,
    new_violations   INTEGER     DEFAULT 0,
    error_message    TEXT
);

-- ── False-positive feedback ───────────────────────────────────────────
-- Logged decisions used as few-shot examples in the Analyzer prompt
CREATE TABLE false_positive_feedback (
    id           UUID      PRIMARY KEY DEFAULT gen_random_uuid(),
    violation_id UUID      REFERENCES violations(id),
    reason       TEXT      NOT NULL,
    created_at   TIMESTAMP NOT NULL DEFAULT NOW()
);
