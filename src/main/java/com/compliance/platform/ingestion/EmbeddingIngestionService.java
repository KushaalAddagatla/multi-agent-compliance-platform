package com.compliance.platform.ingestion;

import com.compliance.platform.model.ControlChunk;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.ai.embedding.EmbeddingModel;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;

import java.nio.file.Path;
import java.util.List;

/**
 * Embeds control chunks via Spring AI's EmbeddingModel (OpenAI text-embedding-ada-002)
 * and stores them in the pgvector embeddings table.
 *
 * <p>This is a one-time ingest step — run it once per framework PDF after downloading.
 * All four agents query against this table at runtime via cosine similarity search.
 */
@Service
public class EmbeddingIngestionService {

    private static final Logger log = LoggerFactory.getLogger(EmbeddingIngestionService.class);

    // Safety truncation: text-embedding-ada-002 max is 8191 tokens (~32k chars).
    // Most controls are <2000 chars; this guard prevents rare oversized chunks from failing.
    private static final int MAX_CONTENT_CHARS = 28_000;

    private final EmbeddingModel embeddingModel;
    private final JdbcTemplate jdbcTemplate;
    private final DocumentIngestionService documentIngestionService;

    public EmbeddingIngestionService(EmbeddingModel embeddingModel,
                                     JdbcTemplate jdbcTemplate,
                                     DocumentIngestionService documentIngestionService) {
        this.embeddingModel = embeddingModel;
        this.jdbcTemplate = jdbcTemplate;
        this.documentIngestionService = documentIngestionService;
    }

    /**
     * Chunk, embed, and store a framework PDF.
     *
     * @param pdfPath   path to the PDF file
     * @param framework one of NIST-800-53, CIS-AWS, SOC2
     * @param force     if true, delete existing rows for this framework before re-ingesting
     * @return number of chunks successfully embedded and stored
     */
    public IngestSummary ingestDocument(Path pdfPath, String framework, boolean force) {
        int existing = countExisting(framework);

        if (existing > 0 && !force) {
            log.info("Framework '{}' already has {} rows — skipping. Use force=true to re-ingest.",
                    framework, existing);
            return new IngestSummary(0, existing, "Already ingested — pass force=true to re-run");
        }

        if (force && existing > 0) {
            log.info("Force re-ingest: deleting {} existing rows for '{}'", existing, framework);
            jdbcTemplate.update("DELETE FROM embeddings WHERE framework = ?", framework);
        }

        // 1. Section-aware chunking (Phase 1C)
        List<ControlChunk> chunks = documentIngestionService.chunkDocument(pdfPath, framework);
        if (chunks.isEmpty()) {
            log.warn("No chunks extracted from {} — verify the PDF path and framework name", pdfPath);
            return new IngestSummary(0, 0, "No chunks extracted — check PDF and framework");
        }

        // 2. Phase 1D checkpoint: embed first chunk and log vector length
        float[] testVec = embeddingModel.embed(chunks.get(0).content());
        log.info("EmbeddingModel ready — vector length: {} (expected 1536 for text-embedding-ada-002)",
                testVec.length);
        insertEmbedding(chunks.get(0), testVec);
        int inserted = 1;

        // 3. Embed and store remaining chunks
        for (int i = 1; i < chunks.size(); i++) {
            ControlChunk chunk = chunks.get(i);
            try {
                String content = chunk.content();
                if (content.length() > MAX_CONTENT_CHARS) {
                    log.warn("Chunk {} truncated from {} to {} chars", chunk.controlId(),
                            content.length(), MAX_CONTENT_CHARS);
                    content = content.substring(0, MAX_CONTENT_CHARS);
                    chunk = new ControlChunk(chunk.controlId(), chunk.framework(), chunk.severity(), content);
                }

                float[] embedding = embeddingModel.embed(chunk.content());
                insertEmbedding(chunk, embedding);
                inserted++;

                if (inserted % 10 == 0 || inserted == chunks.size()) {
                    log.info("Progress: {}/{} chunks embedded and stored for '{}'",
                            inserted, chunks.size(), framework);
                }
            } catch (Exception e) {
                log.error("Skipping chunk {} ({}) — embed/store failed: {}",
                        chunk.controlId(), framework, e.getMessage());
            }
        }

        log.info("Ingestion complete: {}/{} chunks stored for framework='{}'",
                inserted, chunks.size(), framework);
        return new IngestSummary(inserted, 0, "OK");
    }

    // ── DB helpers ───────────────────────────────────────────────────────────

    private void insertEmbedding(ControlChunk chunk, float[] embedding) {
        jdbcTemplate.update("""
                INSERT INTO embeddings (framework, control_id, severity, content, embedding)
                VALUES (?, ?, ?, ?, CAST(? AS vector))
                """,
                chunk.framework(),
                chunk.controlId(),
                chunk.severity(),
                chunk.content(),
                toVectorString(embedding));
    }

    /**
     * Converts a float[] to pgvector literal format: [0.1,-0.2,0.3,...]
     */
    private String toVectorString(float[] vec) {
        StringBuilder sb = new StringBuilder("[");
        for (int i = 0; i < vec.length; i++) {
            if (i > 0) sb.append(',');
            sb.append(vec[i]);
        }
        sb.append(']');
        return sb.toString();
    }

    int countExisting(String framework) {
        Integer n = jdbcTemplate.queryForObject(
                "SELECT COUNT(*) FROM embeddings WHERE framework = ?", Integer.class, framework);
        return n == null ? 0 : n;
    }

    public int countAll() {
        Integer n = jdbcTemplate.queryForObject("SELECT COUNT(*) FROM embeddings", Integer.class);
        return n == null ? 0 : n;
    }

    // ── Result type ──────────────────────────────────────────────────────────

    public record IngestSummary(int inserted, int skipped, String message) {}
}
