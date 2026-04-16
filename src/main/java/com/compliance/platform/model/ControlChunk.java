package com.compliance.platform.model;

/**
 * A single semantically complete control definition extracted from a compliance framework PDF.
 * Section-boundary-aware chunking ensures each chunk maps to exactly one control ID.
 */
public record ControlChunk(
        String controlId,   // e.g. AC-3, SC-8(1), 1.2
        String framework,   // NIST-800-53 | CIS-AWS | SOC2
        String severity,    // HIGH | MEDIUM | LOW
        String content      // full control definition text
) {}
