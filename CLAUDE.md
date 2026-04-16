# Multi-Agent Cloud Compliance Intelligence Platform

## Security Rules

**NEVER read the `.env` file.** It contains real API keys and credentials. Reference `.env.example` for variable names instead.

## Project Overview

An agentic AI system that continuously monitors an AWS environment, cross-references findings against RAG-indexed security frameworks (NIST 800-53, CIS AWS Benchmark, SOC2 controls), and coordinates four specialized AI agents to detect violations, generate contextual remediation plans, and answer natural language compliance questions — with cited sources from actual framework documents.

**This is not a chatbot.** It is an autonomous, scheduled, multi-agent pipeline with memory, grounded reasoning, and a human-in-the-loop remediation gate.

---

## Tech Stack

| Layer | Technology | Rationale |
|-------|-----------|-----------|
| Backend framework | Spring Boot + Spring AI | Orchestration, scheduled jobs, REST API. Java AI stack is rare and differentiated vs. Python LangChain. |
| Agent orchestration | LangChain4j (Java) | Agent tool-binding where Spring AI needs augmentation |
| Vector store | pgvector (PostgreSQL extension) | Reuses existing PostgreSQL — no separate Pinecone/Weaviate infra |
| LLM | Claude API (Anthropic) | Direct API for personal use (~$3–5/mo). Resume notes AWS Bedrock for enterprise (identical code, endpoint swap) |
| AWS scanning | AWS SDK v2 (direct calls) | EC2, IAM, S3, ECS, Secrets Manager. No AWS Config (eliminates ~$15/mo) |
| Async messaging | AWS SQS | Decouples Scanner from Analyzer, handles burst load |
| Storage | AWS S3 | Framework PDF storage + compliance report archival |
| Email | AWS SES | Nightly compliance summary email |
| Local dev | Docker Compose + LocalStack | Full local environment, real AWS only for live demo |
| Frontend | React + Vite | Compliance dashboard, violations table, Q&A chat |
| CI/CD | GitHub Actions | Build → test → Docker image → ECR → EC2 deploy |

---

## Architecture

### Four Specialized Agents

| Agent | Role |
|-------|------|
| **Scanner Agent** | Calls AWS APIs (EC2, IAM, S3, ECS, Secrets Manager), outputs structured JSON `EnvironmentSnapshot` |
| **Analyzer Agent** | Receives snapshot, queries pgvector RAG per resource, uses Claude to reason violations with framework citations |
| **Remediator Agent** | Generates step-by-step fix, AWS CLI commands, Terraform patches per violation. Flags `auto_remediable`. Does NOT execute — human-in-the-loop is intentional. |
| **Reporter Agent** | Aggregates violations, scores per framework, generates markdown report, uploads to S3, sends SES email |
| **Orchestrator** | `@Scheduled(cron = "0 0 2 * * *")` nightly job. Coordinates all four agents, detects new vs. persistent violations, publishes to CloudWatch |

### RAG Pipeline

```
PDF Documents (NIST 800-53, CIS AWS Benchmark, SOC2)
    → Section-aware chunking (per control ID: AC-3, SC-8, SI-2 — NOT sliding window)
    → EmbeddingModel.embed(chunkText) → float[1536]
    → INSERT INTO embeddings (framework, control_id, severity, content, embedding vector(1536))
    → ivfflat index on embedding column

Query path:
    User question / resource state
    → embed question
    → SELECT ... ORDER BY embedding <=> queryVec LIMIT 5  (cosine similarity)
    → retrieved chunks + AWS state → Claude prompt → grounded answer
```

**Critical design decision:** Section-boundary-aware chunking keyed on control IDs. Naive character-count splitting destroys semantic integrity of control definitions and breaks retrieval precision.

### Agent Memory & Delta Detection

- Each agent run stores structured output to PostgreSQL
- Orchestrator reads prior run state before each execution
- Delta detection: compare new violations against prior `(resource_id, control_id)` pairs
- `is_new` boolean column — new violations get a "New" badge in the UI
- SES email separates "New violations this run" from "Persistent violations"

### Feedback Loop

- False-positive button on each violation → stored to `false_positive_feedback` table
- Accumulated feedback examples injected as few-shot examples into Analyzer prompt
- Demonstrates AI systems require feedback loops, not just one-shot inference

---

## Database Schema

```sql
-- Framework embeddings
embeddings (id, framework, control_id, severity, content TEXT, embedding vector(1536))
-- ivfflat index on embedding

-- AWS scan state
scan_runs (id, timestamp, snapshot_json)

-- Violations
violations (id, scan_run_id, resource_id, control_id, framework, severity, reasoning,
            cited_excerpt, first_seen_at, is_new BOOLEAN)

-- Remediation
remediation_plans (id, violation_id FK, steps, cli_commands, terraform_patch,
                   auto_remediable BOOLEAN, approval_status ENUM(PENDING/APPROVED/REJECTED))

-- Reporting
compliance_reports (id, timestamp, nist_score, cis_score, soc2_score, total_violations, s3_key)

-- Pipeline tracking
pipeline_runs (run_id, start_time, end_time, status ENUM(RUNNING/COMPLETED/FAILED),
               violations_found, new_violations)

-- Feedback
false_positive_feedback (id, violation_id FK, reason, created_at)
```

---

## REST API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/violations` | List violations; query params: `framework`, `severity`, `limit` |
| GET | `/api/violations/{id}` | Violation detail |
| GET | `/api/violations/{id}/remediation` | Remediation plan for violation |
| PATCH | `/api/remediations/{id}/status` | Approve or reject remediation |
| POST | `/api/violations/{id}/feedback` | Submit false-positive feedback |
| GET | `/api/compliance-score` | Per-framework scores (NIST, CIS, SOC2) |
| GET | `/api/scan-runs` | Scan history |
| GET | `/api/pipeline-runs` | Pipeline run history |
| POST | `/api/pipeline/trigger` | Trigger a manual pipeline run |
| POST | `/api/chat` | Q&A chat (session ID in header, Spring AI ChatMemory) |

---

## React Dashboard Routes & Components

| Route | Component |
|-------|-----------|
| `/` | Overview: `ComplianceSummary` (3 score cards) + `ComplianceRadarChart` (Recharts RadarChart) |
| `/violations` | `ViolationsTable`: Resource, Control ID, Framework, Severity chip, Timestamp, View Detail |
| `/chat` | `ChatInterface`: session-based Q&A with cited control chips |
| `/history` | Pipeline run history |

Key UI details:
- Severity chips are color-coded (HIGH/MEDIUM/LOW)
- Violations sortable; NEW violations at top with "New" badge
- `ViolationDetail` drawer: full reasoning, cited excerpt, resource ARN, approve/reject remediation, false-positive button
- Loading skeletons (no blank screens), empty states with icons
- "Last scanned: X minutes ago" in header
- Chat: user messages right-aligned, bot messages left-aligned with avatar, cited control IDs as chips

---

## Local Development Setup

### Prerequisites
- Java 17+, Maven, Docker Desktop, Node.js 18+
- AWS CLI configured (read-only IAM user)
- Anthropic API key

### Start local services
```bash
docker-compose up -d   # postgres (pgvector:pg16) + localstack
```

### Environment variables
```
ANTHROPIC_API_KEY=...
AWS_ACCESS_KEY_ID=...
AWS_SECRET_ACCESS_KEY=...
AWS_REGION=us-east-1
AWS_ENDPOINT_OVERRIDE=http://localhost:4566   # LocalStack (dev profile only)
```

### Run backend
```bash
mvn spring-boot:run -Dspring-boot.run.profiles=local
```

### Run frontend
```bash
cd dashboard && npm install && npm run dev
```

---

## Build Phases

### Phase 1 — RAG Pipeline (Week 1)
- Spring Boot project scaffolding
- Docker Compose with pgvector + LocalStack
- PDF ingestion (Apache PDFBox), section-aware chunking
- Embed chunks via Spring AI `EmbeddingModel`, store in pgvector
- `RetrievalService.search(question, topK)` with cosine similarity

### Phase 2 — Scanner + Analyzer Agents (Week 2)
- AWS SDK v2: EC2, IAM, S3, ECS scanning
- `EnvironmentSnapshot` record, stored to `scan_runs`
- `AnalyzerAgent`: RAG retrieval + Claude reasoning per resource
- Violation records with citations stored to DB
- SQS decoupling between Scanner and Analyzer
- REST endpoints: `/api/violations`, `/api/scan-runs`

### Phase 3 — React Dashboard + Chat (Week 3)
- All REST endpoints + CORS
- `POST /api/chat` with Spring AI `ChatMemory` (session-keyed)
- React app with Vite, all routes and components
- Violations table, radar chart, chat interface

### Phase 4 — Remediator + Reporter + Orchestrator (Week 4)
- `RemediatorAgent`: remediation plans with CLI commands + Terraform patches
- `ReporterAgent`: S3 upload + SES email
- `ComplianceOrchestrator`: nightly `@Scheduled`, delta detection
- CloudWatch metrics + SNS alarm if violations > 50
- False-positive feedback injected into Analyzer prompt as few-shot examples
- Rate limiting on `/api/chat` (20 req/min per session)

### Phase 5 — Deploy + Polish (Week 5)
- EC2 t3.micro, Docker Compose prod, nginx reverse proxy
- GitHub Actions CI/CD to ECR + EC2
- API key in AWS Secrets Manager (never hardcoded)
- OpenAPI/Swagger docs (`springdoc-openapi`)
- Architecture diagram (`docs/architecture.png`)
- Seed data (`seed.sql` with 10 sample violations)
- Postman collection

---

## Key Technical Decisions

1. **Section-boundary chunking over sliding window** — preserves semantic integrity of each control definition; critical for retrieval precision
2. **pgvector over Pinecone** — operational pragmatism; reuses existing PostgreSQL, eliminates separate infra
3. **Human-in-the-loop Remediator** — generates but never auto-executes; intentional architectural safety gate
4. **Delta detection** — stateful runs enable distinguishing new violations from persistent ones
5. **Feedback loop** — false-positive feedback as few-shot examples improves Analyzer over time
6. **Claude API direct vs. Bedrock** — same code, env variable controls endpoint; cost-optimized for dev (~$3–5/mo)
7. **No AWS Config or Security Hub** — Scanner Agent replaces both; eliminates ~$23/mo in costs
8. **LocalStack for local dev** — real AWS only for live demo; keeps dev bill near zero

---

## Cost Profile

| Component | Optimized Cost |
|-----------|----------------|
| Claude API | ~$3–5/mo |
| EC2 t3.micro + PostgreSQL | ~$0–8/mo |
| S3, SQS, SES | ~$1/mo |
| AWS Config / Security Hub | $0 (replaced by Scanner Agent) |
| **Total** | **~$5–15/mo** |
