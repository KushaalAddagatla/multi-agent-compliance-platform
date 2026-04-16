package com.compliance.platform.ingestion;

import com.compliance.platform.model.ControlChunk;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.io.File;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;

/**
 * REST endpoints for ingestion validation and execution.
 *
 * <p>Phase 1C: {@code POST /api/ingestion/preview} — chunk without embedding, inspect output.
 * <p>Phase 1D: {@code POST /api/ingestion/ingest} — chunk + embed + store to pgvector.
 */
@RestController
@RequestMapping("/api/ingestion")
public class IngestionController {

    private static final Logger log = LoggerFactory.getLogger(IngestionController.class);

    private final DocumentIngestionService ingestionService;
    private final EmbeddingIngestionService embeddingIngestionService;

    @Value("${ingestion.pdf-dir}")
    private String pdfDir;

    public IngestionController(DocumentIngestionService ingestionService,
                               EmbeddingIngestionService embeddingIngestionService) {
        this.ingestionService = ingestionService;
        this.embeddingIngestionService = embeddingIngestionService;
    }

    /**
     * Preview extracted chunks from a PDF without embedding or storing anything.
     * Use this to validate that section-boundary chunking is working correctly.
     *
     * <p>Example:
     * <pre>
     *   POST /api/ingestion/preview?filename=nist-800-53.pdf&framework=NIST-800-53&limit=10
     * </pre>
     *
     * @param filename  PDF filename relative to ingestion.pdf-dir
     * @param framework  NIST-800-53 | CIS-AWS | SOC2
     * @param limit     max number of chunks to include in the JSON response (default 10)
     */
    @PostMapping("/preview")
    public ResponseEntity<?> previewChunks(
            @RequestParam String filename,
            @RequestParam String framework,
            @RequestParam(defaultValue = "10") int limit) {

        Path pdfPath = Path.of(pdfDir, filename);
        File file = pdfPath.toFile();

        if (!file.exists()) {
            return ResponseEntity.badRequest().body(Map.of(
                    "error", "File not found: " + pdfPath,
                    "hint", "Place PDF files in the directory configured by ingestion.pdf-dir: " + pdfDir
            ));
        }

        List<ControlChunk> chunks = ingestionService.chunkDocument(pdfPath, framework);

        // Print first N chunks to the console — Phase 1C checkpoint
        log.info("═══ CHUNK PREVIEW: {} ({}) — {} total chunks ═══",
                filename, framework, chunks.size());
        int printCount = Math.min(limit, chunks.size());
        for (int i = 0; i < printCount; i++) {
            ControlChunk c = chunks.get(i);
            int previewLen = Math.min(400, c.content().length());
            log.info("\n[{}/{}] {} | {} | {}\n{}\n{}{}",
                    i + 1, chunks.size(),
                    c.controlId(), c.framework(), c.severity(),
                    "─".repeat(70),
                    c.content().substring(0, previewLen),
                    c.content().length() > 400 ? "\n... (" + c.content().length() + " chars total)" : ""
            );
        }

        List<Map<String, Object>> preview = chunks.stream()
                .limit(limit)
                .map(c -> Map.<String, Object>of(
                        "controlId", c.controlId(),
                        "framework", c.framework(),
                        "severity", c.severity(),
                        "contentLength", c.content().length(),
                        "contentPreview", c.content().substring(0, Math.min(400, c.content().length()))
                ))
                .toList();

        return ResponseEntity.ok(Map.of(
                "totalChunks", chunks.size(),
                "framework", framework,
                "filename", filename,
                "pdfDir", pdfDir,
                "previewCount", preview.size(),
                "chunks", preview
        ));
    }

    /**
     * Embed and store all chunks from a framework PDF into pgvector.
     * This is the one-time ingest step — run once per framework PDF.
     *
     * <p>Example:
     * <pre>
     *   POST /api/ingestion/ingest?filename=nist-800-53.pdf&framework=NIST-800-53
     *   POST /api/ingestion/ingest?filename=nist-800-53.pdf&framework=NIST-800-53&force=true
     * </pre>
     *
     * @param filename  PDF filename relative to ingestion.pdf-dir
     * @param framework NIST-800-53 | CIS-AWS | SOC2
     * @param force     if true, delete existing rows for this framework before re-ingesting
     */
    @PostMapping("/ingest")
    public ResponseEntity<?> ingest(
            @RequestParam String filename,
            @RequestParam String framework,
            @RequestParam(defaultValue = "false") boolean force) {

        Path pdfPath = Path.of(pdfDir, filename);
        if (!pdfPath.toFile().exists()) {
            return ResponseEntity.badRequest().body(Map.of(
                    "error", "File not found: " + pdfPath,
                    "hint", "Place PDF files in: " + pdfDir
            ));
        }

        EmbeddingIngestionService.IngestSummary result =
                embeddingIngestionService.ingestDocument(pdfPath, framework, force);

        int totalInDb = embeddingIngestionService.countAll();
        return ResponseEntity.ok(Map.of(
                "framework", framework,
                "filename", filename,
                "inserted", result.inserted(),
                "skipped", result.skipped(),
                "message", result.message(),
                "totalEmbeddingsInDb", totalInDb
        ));
    }

    /**
     * Row count in the embeddings table, broken down by framework.
     * Use after ingestion to confirm rows landed in pgvector.
     */
    @GetMapping("/count")
    public ResponseEntity<?> count() {
        int total = embeddingIngestionService.countAll();
        return ResponseEntity.ok(Map.of(
                "totalEmbeddings", total
        ));
    }

    /**
     * List PDF files available in the configured pdf-dir.
     * Useful for confirming the PDFs are in the right place before running ingest.
     */
    @GetMapping("/files")
    public ResponseEntity<?> listFiles() {
        File dir = new File(pdfDir);
        if (!dir.exists() || !dir.isDirectory()) {
            return ResponseEntity.ok(Map.of(
                    "pdfDir", pdfDir,
                    "exists", false,
                    "files", List.of(),
                    "hint", "Create the directory and place NIST/CIS PDF files in it"
            ));
        }
        String[] pdfs = dir.list((d, name) -> name.toLowerCase().endsWith(".pdf"));
        return ResponseEntity.ok(Map.of(
                "pdfDir", pdfDir,
                "exists", true,
                "files", pdfs == null ? List.of() : List.of(pdfs)
        ));
    }
}
