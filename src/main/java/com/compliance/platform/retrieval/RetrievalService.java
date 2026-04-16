package com.compliance.platform.retrieval;

import com.compliance.platform.model.RetrievedChunk;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.ai.embedding.EmbeddingModel;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;

import java.util.List;

/**
 * Core RAG query path: embed a question and retrieve the most semantically similar
 * control chunks from pgvector using cosine similarity.
 *
 * <p>Every agent calls this service to ground its reasoning in actual framework text.
 * Retrieval quality depends entirely on the chunk boundaries set during ingest —
 * each chunk must be a single complete control definition.
 *
 * <p>SQL pattern:
 * <pre>
 *   SELECT ... , 1 - (embedding &lt;=&gt; queryVec) AS similarity
 *   FROM embeddings
 *   ORDER BY embedding &lt;=&gt; queryVec   -- ivfflat index on this column
 *   LIMIT topK
 * </pre>
 */
@Service
public class RetrievalService {

    private static final Logger log = LoggerFactory.getLogger(RetrievalService.class);

    private final EmbeddingModel embeddingModel;
    private final JdbcTemplate jdbcTemplate;

    public RetrievalService(EmbeddingModel embeddingModel, JdbcTemplate jdbcTemplate) {
        this.embeddingModel = embeddingModel;
        this.jdbcTemplate = jdbcTemplate;
    }

    /**
     * Search all frameworks.
     *
     * @param question  natural language question or resource state description
     * @param topK      number of chunks to return
     */
    public List<RetrievedChunk> search(String question, int topK) {
        log.debug("RAG search (all frameworks): topK={} question='{}'", topK, question);
        float[] vec = embeddingModel.embed(question);
        String v = toVectorLiteral(vec);

        return jdbcTemplate.query("""
                SELECT control_id, framework, severity, content,
                       1 - (embedding <=> CAST(? AS vector)) AS similarity
                FROM embeddings
                ORDER BY embedding <=> CAST(? AS vector)
                LIMIT ?
                """,
                (rs, row) -> mapRow(rs),
                v, v, topK);
    }

    /**
     * Search within a specific framework.
     *
     * @param question   natural language question
     * @param topK       number of chunks to return
     * @param framework  NIST-800-53 | CIS-AWS | SOC2
     */
    public List<RetrievedChunk> search(String question, int topK, String framework) {
        log.debug("RAG search (framework={}): topK={} question='{}'", framework, topK, question);
        float[] vec = embeddingModel.embed(question);
        String v = toVectorLiteral(vec);

        return jdbcTemplate.query("""
                SELECT control_id, framework, severity, content,
                       1 - (embedding <=> CAST(? AS vector)) AS similarity
                FROM embeddings
                WHERE framework = ?
                ORDER BY embedding <=> CAST(? AS vector)
                LIMIT ?
                """,
                (rs, row) -> mapRow(rs),
                v, framework, v, topK);
    }

    // ── helpers ──────────────────────────────────────────────────────────────

    private RetrievedChunk mapRow(java.sql.ResultSet rs) throws java.sql.SQLException {
        return new RetrievedChunk(
                rs.getString("control_id"),
                rs.getString("framework"),
                rs.getString("severity"),
                rs.getString("content"),
                rs.getDouble("similarity"));
    }

    /**
     * Converts a float[] to the pgvector text literal format: {@code [0.1,-0.2,0.3,...]}.
     * The CAST(? AS vector) in the SQL then converts this string to the vector type.
     */
    private String toVectorLiteral(float[] vec) {
        StringBuilder sb = new StringBuilder("[");
        for (int i = 0; i < vec.length; i++) {
            if (i > 0) sb.append(',');
            sb.append(vec[i]);
        }
        sb.append(']');
        return sb.toString();
    }
}
