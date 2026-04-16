package com.compliance.platform.ingestion;

import com.compliance.platform.model.ControlChunk;
import org.apache.pdfbox.Loader;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.text.PDFTextStripper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Extracts text from compliance framework PDFs and splits into control-level chunks.
 *
 * <p><b>Key design decision:</b> Section-boundary-aware chunking keyed on control IDs
 * (AC-3, SC-8, 1.2) instead of naive character-count splitting. Each chunk is one
 * semantically complete control definition, which is critical for retrieval precision.
 * Naive splitting would break control text across chunk boundaries, corrupting citations.
 */
@Service
public class DocumentIngestionService {

    private static final Logger log = LoggerFactory.getLogger(DocumentIngestionService.class);

    /**
     * NIST 800-53 Rev 5 control header line.
     * Matches lines like:
     *   "AC-2 ACCOUNT MANAGEMENT"
     *   "AC-2(1) AUTOMATED SYSTEM ACCOUNT MANAGEMENT"
     *   "SC-8 TRANSMISSION CONFIDENTIALITY AND INTEGRITY"
     * Does NOT match inline references like "...as required by AC-2..."
     * Uses full-line match (matches()) so embedded references are ignored.
     */
    private static final Pattern NIST_HEADER = Pattern.compile(
            "^((?:AC|AT|AU|CA|CM|CP|IA|IR|MA|MP|PE|PL|PM|PS|RA|SA|SC|SI|SR)-\\d+(?:\\(\\d+\\))?)(?:\\s+[A-Z][A-Z0-9\\s/()/.,\\-]+)?$"
    );

    /**
     * CIS AWS Benchmark section header.
     * Matches lines like:
     *   "1.1 Maintain current contact details (Automated)"
     *   "2.1.1 Ensure S3 bucket access control is enabled"
     * Requires the title to start with an uppercase letter after the number.
     */
    private static final Pattern CIS_HEADER = Pattern.compile(
            "^(\\d+\\.\\d+(?:\\.\\d+)?)\\s+[A-Z]"
    );

    // NIST 800-53 Rev 5 High-baseline controls — used for severity assignment.
    // Source: https://csrc.nist.gov/projects/cprt/catalog#/cprt/framework/version/SP_800_53_5_1_0
    private static final Set<String> HIGH_IMPACT = Set.of(
            "AC-2", "AC-3", "AC-4", "AC-6", "AC-17", "AC-18", "AC-19",
            "AU-2", "AU-6", "AU-9", "AU-12",
            "CA-3", "CA-7", "CA-9",
            "CM-2", "CM-6", "CM-7", "CM-8",
            "IA-2", "IA-5", "IA-8",
            "IR-4", "IR-5", "IR-6",
            "SC-5", "SC-7", "SC-8", "SC-12", "SC-13", "SC-28",
            "SI-2", "SI-3", "SI-4", "SI-7", "SI-10"
    );

    private static final Set<String> LOW_IMPACT = Set.of(
            "AT-1", "AT-2", "AT-3",
            "PL-1", "PL-2", "PL-4",
            "PM-1", "PM-2", "PM-3", "PM-4"
    );

    /**
     * Entry point: extracts text from the PDF and splits into control-level chunks.
     *
     * @param pdfPath  path to the framework PDF
     * @param framework  one of NIST-800-53, CIS-AWS, SOC2
     * @return ordered list of control chunks; each chunk = one control definition
     */
    public List<ControlChunk> chunkDocument(Path pdfPath, String framework) {
        log.info("Chunking '{}' as framework={}", pdfPath.getFileName(), framework);
        String rawText = extractPdfText(pdfPath);
        log.info("Extracted {} characters from '{}'", rawText.length(), pdfPath.getFileName());
        List<ControlChunk> chunks = splitOnControlBoundaries(rawText, framework);
        log.info("Produced {} chunks from '{}'", chunks.size(), pdfPath.getFileName());
        return chunks;
    }

    // ── PDF text extraction ──────────────────────────────────────────────────

    private String extractPdfText(Path pdfPath) {
        try (PDDocument doc = Loader.loadPDF(pdfPath.toFile())) {
            PDFTextStripper stripper = new PDFTextStripper();
            return stripper.getText(doc);
        } catch (IOException e) {
            throw new RuntimeException("PDF extraction failed: " + pdfPath, e);
        }
    }

    // ── Section-boundary chunking ────────────────────────────────────────────

    /**
     * Splits raw PDF text into chunks by detecting control ID header lines.
     * Each new control ID header flushes the previous chunk and starts a new one.
     * Chunks shorter than 50 characters are discarded as noise (page headers, orphans).
     */
    private List<ControlChunk> splitOnControlBoundaries(String text, String framework) {
        String[] lines = text.split("\\r?\\n");
        List<ControlChunk> chunks = new ArrayList<>();

        String currentId = null;
        StringBuilder currentContent = new StringBuilder();

        for (String line : lines) {
            String trimmed = line.trim();
            Optional<String> detectedId = detectControlId(trimmed, framework);

            if (detectedId.isPresent()) {
                // Flush the previous chunk before starting the next control section
                flushChunk(currentId, framework, currentContent, chunks);
                currentId = detectedId.get();
                currentContent = new StringBuilder(line).append("\n");
            } else if (currentId != null) {
                currentContent.append(line).append("\n");
            }
            // Lines before the first control ID header are discarded (table of contents, etc.)
        }

        // Flush the final chunk
        flushChunk(currentId, framework, currentContent, chunks);
        return chunks;
    }

    private void flushChunk(String controlId, String framework,
                            StringBuilder content, List<ControlChunk> out) {
        if (controlId == null) return;
        String text = content.toString().trim();
        if (text.length() < 50) {
            log.debug("Discarding short chunk for {} ({} chars)", controlId, text.length());
            return;
        }
        out.add(new ControlChunk(controlId, framework, resolveSeverity(controlId, framework), text));
    }

    // ── Control ID detection ─────────────────────────────────────────────────

    private Optional<String> detectControlId(String trimmedLine, String framework) {
        return switch (framework) {
            case "NIST-800-53" -> {
                Matcher m = NIST_HEADER.matcher(trimmedLine);
                // matches() requires the entire line to match — prevents false positives
                // from inline references like "...based on AC-2 requirements..."
                yield m.matches() ? Optional.of(m.group(1)) : Optional.empty();
            }
            case "CIS-AWS" -> {
                Matcher m = CIS_HEADER.matcher(trimmedLine);
                yield m.find() ? Optional.of(m.group(1)) : Optional.empty();
            }
            default -> {
                log.warn("No control ID detection pattern for framework '{}' — chunks will be empty", framework);
                yield Optional.empty();
            }
        };
    }

    // ── Severity resolution ──────────────────────────────────────────────────

    private String resolveSeverity(String controlId, String framework) {
        if ("NIST-800-53".equals(framework)) {
            // Strip enhancement suffix: AC-2(1) → AC-2
            String baseId = controlId.replaceAll("\\(\\d+\\)$", "").trim();
            if (HIGH_IMPACT.contains(baseId)) return "HIGH";
            if (LOW_IMPACT.contains(baseId)) return "LOW";
            return "MEDIUM";
        }
        if ("CIS-AWS".equals(framework)) {
            // CIS section 1 = Identity, 4 = Monitoring, 5 = Networking → HIGH risk
            String major = controlId.split("\\.")[0];
            return switch (major) {
                case "1", "4", "5" -> "HIGH";
                case "2", "3" -> "MEDIUM";
                default -> "LOW";
            };
        }
        return "MEDIUM";
    }
}
