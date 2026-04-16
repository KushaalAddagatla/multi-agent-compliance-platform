package com.compliance.platform.model;

/**
 * A control chunk returned from pgvector similarity search, enriched with a cosine similarity score.
 *
 * <p>Similarity is in the range [0.0, 1.0]:
 * <ul>
 *   <li>1.0 = identical (the query vector matches this chunk exactly)</li>
 *   <li>0.0 = completely unrelated</li>
 * </ul>
 */
public record RetrievedChunk(
        String controlId,
        String framework,
        String severity,
        String content,
        double similarity
) {}
