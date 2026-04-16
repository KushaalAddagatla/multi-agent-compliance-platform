# Multi-Agent Cloud Compliance Intelligence Platform

An agentic AI system that continuously monitors an AWS environment, cross-references findings against RAG-indexed security frameworks (NIST 800-53, CIS AWS Benchmark, SOC2), and coordinates four specialized AI agents to detect violations, generate contextual remediation plans, and answer natural language compliance questions — with cited sources from actual framework documents.

> **Status:** Week 1 complete — RAG pipeline fully operational. Week 2 in progress (Scanner + Analyzer agents).

---

## Architecture

```
PDF Documents (NIST 800-53, CIS AWS Benchmark, SOC2)
    → Section-aware chunking (per control ID: AC-3, SC-8, SI-2)
    → EmbeddingModel.embed(chunkText) → float[1536]
    → INSERT INTO embeddings (framework, control_id, severity, content, embedding vector(1536))
    → ivfflat index on embedding column

Query path (all four agents):
    Resource state / user question
    → embed question
    → SELECT ... ORDER BY embedding <=> queryVec LIMIT 5  (cosine similarity)
    → retrieved chunks + AWS state → Claude prompt → grounded answer
```

### Four Specialized Agents (Week 2+)

| Agent | Role |
|-------|------|
| **Scanner** | Calls AWS APIs (EC2, IAM, S3, ECS), outputs structured `EnvironmentSnapshot` |
| **Analyzer** | RAG retrieval per resource + Claude reasoning → violations with framework citations |
| **Remediator** | Generates step-by-step fix, AWS CLI commands, Terraform patches. Never auto-executes — human-in-the-loop gate |
| **Reporter** | Aggregates violations, scores per framework, uploads markdown report to S3, sends SES email |
| **Orchestrator** | `@Scheduled(cron = "0 0 2 * * *")` nightly job. Coordinates all agents, delta detection for new vs. persistent violations |

---

## Tech Stack

| Layer | Technology | Why |
|-------|-----------|-----|
| Backend | Spring Boot 3.3 + Spring AI 1.0 | Java AI stack is rare and differentiated vs. Python LangChain |
| LLM | Claude API (Anthropic) | Direct API; same code works with AWS Bedrock via env var swap |
| Embeddings | OpenAI text-embedding-ada-002 | 1536-dim vectors, strong semantic quality |
| Vector store | pgvector (PostgreSQL extension) | Reuses existing PostgreSQL — no separate Pinecone/Weaviate infra |
| AWS scanning | AWS SDK v2 | EC2, IAM, S3, ECS, Secrets Manager. No AWS Config (saves ~$15/mo) |
| Async | AWS SQS | Decouples Scanner from Analyzer |
| Storage/Email | AWS S3 + SES | Report archival + nightly compliance summary email |
| Local dev | Docker Compose + LocalStack | Full local environment, zero AWS spend during development |
| Frontend | React + Vite + Recharts | Compliance dashboard, violations table, RAG-powered Q&A chat |
| CI/CD | GitHub Actions → ECR → EC2 | Build → test → Docker → deploy |

---

## Local Development Setup

### Prerequisites

- Java 21+, Maven 3.9+
- Docker Desktop
- Node.js 18+ (Week 3 frontend)
- Anthropic API key — [console.anthropic.com](https://console.anthropic.com)
- OpenAI API key — [platform.openai.com](https://platform.openai.com) (embeddings only)

### 1. Start local infrastructure

```bash
docker-compose up -d    # postgres/pgvector:pg16 + LocalStack
```

Flyway runs automatically on startup and creates all tables (see `V1__init_schema.sql`).

### 2. Environment variables

Copy `.env.example` and fill in your keys:

```bash
cp .env.example .env
# Edit .env — never commit this file
```

Required variables:

```
ANTHROPIC_API_KEY=sk-ant-...
OPENAI_API_KEY=sk-...
AWS_ACCESS_KEY_ID=...
AWS_SECRET_ACCESS_KEY=...
AWS_REGION=us-east-1
AWS_ENDPOINT_OVERRIDE=http://localhost:4566   # local profile only
```

### 3. Run the backend

```bash
mvn spring-boot:run -Dspring-boot.run.profiles=local
```

### 4. Ingest compliance framework PDFs

Download the PDFs and place them in `~/compliance-docs/`:

- **NIST 800-53 Rev 5** — [csrc.nist.gov](https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final) (free)
- **CIS AWS Benchmark** — [cisecurity.org](https://www.cisecurity.org/benchmark/amazon_web_services) (free registration)

Then run the one-time ingestion:

```bash
# Confirm files are visible
curl http://localhost:8080/api/ingestion/files

# Chunk + embed + store NIST 800-53
curl -X POST "http://localhost:8080/api/ingestion/ingest?filename=nist-800-53.pdf&framework=NIST-800-53"

# Chunk + embed + store CIS AWS Benchmark
curl -X POST "http://localhost:8080/api/ingestion/ingest?filename=cis-aws.pdf&framework=CIS-AWS"

# Verify row count
curl http://localhost:8080/api/ingestion/count
```

### 5. Validate RAG retrieval

```bash
# AC-3 should be the top result
curl "http://localhost:8080/api/retrieval/search?question=What+does+AC-3+require+for+access+enforcement&topK=3"

# SI-2 should surface for patch management
curl "http://localhost:8080/api/retrieval/search?question=What+are+the+requirements+for+patch+management&topK=3"
```

---

## REST API

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/ingestion/files` | List PDFs in configured pdf-dir |
| POST | `/api/ingestion/preview` | Chunk a PDF and preview results (no embedding) |
| POST | `/api/ingestion/ingest` | Chunk + embed + store to pgvector |
| GET | `/api/ingestion/count` | Total rows in embeddings table |
| GET | `/api/retrieval/search` | Semantic search over embeddings |
| GET | `/api/violations` | List violations (Week 2+) |
| GET | `/api/violations/{id}/remediation` | Remediation plan (Week 4+) |
| POST | `/api/chat` | RAG-powered Q&A (Week 3+) |
| GET | `/api/compliance-score` | Per-framework scores (Week 3+) |
| POST | `/api/pipeline/trigger` | Manual pipeline run (Week 4+) |

Full OpenAPI docs available at `http://localhost:8080/swagger-ui.html` when the app is running.

---

## Database Schema

```sql
embeddings          -- RAG knowledge base: one row per control definition
scan_runs           -- Raw AWS environment snapshots (JSON)
violations          -- Compliance findings with cited framework excerpts
remediation_plans   -- Step-by-step fixes + CLI commands + Terraform patches
compliance_reports  -- Per-run scores (NIST/CIS/SOC2) + S3 report link
pipeline_runs       -- Orchestrator run history (RUNNING/COMPLETED/FAILED)
false_positive_feedback  -- User-flagged false positives, injected as few-shot examples
```

Schema migrations managed by Flyway (`src/main/resources/db/migration/`).

---

## Key Technical Decisions

**1. Section-boundary chunking over sliding window**
Each PDF chunk maps to exactly one control ID (AC-3, SC-8, SI-2). Naive character-count splitting breaks control definitions across boundaries, corrupting citations. The regex detects control header lines (e.g. `AC-3 ACCESS ENFORCEMENT`) and flushes a new chunk on each match.

**2. pgvector over Pinecone**
Reuses existing PostgreSQL. Eliminates a separate managed vector DB, saves ~$70/mo at scale, and the `<=>` cosine similarity operator with an `ivfflat` index gives equivalent retrieval performance for this workload.

**3. Human-in-the-loop Remediator**
The Remediator generates fixes but never executes them. Approval status (`PENDING/APPROVED/REJECTED`) is stored in the DB. This is an intentional architectural safety gate, not a limitation.

**4. Delta detection**
Each Orchestrator run compares new violations against the previous run's `(resource_id, control_id)` pairs. `is_new = true` only on first appearance — enables separating new violations from persistent ones in the email and dashboard.

**5. Feedback loop**
False-positive feedback is stored and injected as few-shot examples into the Analyzer prompt on subsequent runs. Demonstrates that production AI systems require continuous feedback loops.

**6. Claude API direct vs. Bedrock**
Same application code. Switching to AWS Bedrock is an environment variable change (`ANTHROPIC_API_KEY` → Bedrock endpoint config). Cost during development: ~$3–5/month.

---

## Running Tests

```bash
# Unit + integration tests (integration tests skip if DB/API keys not configured)
mvn test

# Integration tests require:
#   - docker-compose up -d (PostgreSQL running)
#   - OPENAI_API_KEY set to a real key
#   - Embeddings table populated (run ingest first)
mvn test -Dspring.profiles.active=test
```

---

## Cost Profile

| Component | Monthly Cost |
|-----------|-------------|
| Claude API (nightly scans + chat) | ~$3–5 |
| EC2 t3.micro + PostgreSQL | ~$0–8 |
| S3, SQS, SES | ~$1 |
| AWS Config / Security Hub | $0 (replaced by Scanner Agent) |
| **Total** | **~$5–15** |
