package com.compliance.platform.retrieval;

import com.compliance.platform.model.RetrievedChunk;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

/**
 * Debug/validation endpoint for the RAG retrieval path.
 * Also used by the Phase 3 chat endpoint to ground Q&A answers in framework text.
 */
@RestController
@RequestMapping("/api/retrieval")
public class RetrievalController {

    private final RetrievalService retrievalService;

    public RetrievalController(RetrievalService retrievalService) {
        this.retrievalService = retrievalService;
    }

    /**
     * Semantic search over the embeddings table.
     *
     * <p>Example — validate AC-3 surfaces for an access control question:
     * <pre>
     *   GET /api/retrieval/search?question=What+does+AC-3+require+for+access+enforcement%3F&topK=3
     * </pre>
     *
     * @param question   natural language question
     * @param topK       max results (default 5)
     * @param framework  optional — NIST-800-53 | CIS-AWS | SOC2; omit to search all
     */
    @GetMapping("/search")
    public ResponseEntity<List<Map<String, Object>>> search(
            @RequestParam String question,
            @RequestParam(defaultValue = "5") int topK,
            @RequestParam(required = false) String framework) {

        List<RetrievedChunk> results = framework != null
                ? retrievalService.search(question, topK, framework)
                : retrievalService.search(question, topK);

        List<Map<String, Object>> body = results.stream()
                .map(c -> Map.<String, Object>of(
                        "controlId", c.controlId(),
                        "framework", c.framework(),
                        "severity", c.severity(),
                        "similarity", String.format("%.4f", c.similarity()),
                        "contentPreview", c.content().substring(0, Math.min(400, c.content().length()))
                ))
                .toList();

        return ResponseEntity.ok(body);
    }
}
