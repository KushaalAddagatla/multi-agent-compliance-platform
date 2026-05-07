package com.compliance.platform.api;

import com.compliance.platform.model.RetrievedChunk;
import com.compliance.platform.retrieval.RetrievalService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.ai.chat.client.ChatClient;
import org.springframework.ai.chat.memory.ChatMemory;
import org.springframework.ai.chat.messages.AssistantMessage;
import org.springframework.ai.chat.messages.Message;
import org.springframework.ai.chat.messages.UserMessage;
import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.*;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * Q&A chat endpoint grounded in the RAG knowledge base and live violation data.
 *
 * <p>Each request:
 * <ol>
 *   <li>Embeds the question and retrieves the top-5 semantically similar control chunks
 *       from pgvector — these are the framework sections most likely to answer the question.</li>
 *   <li>Loads the 10 most recent violations from the DB — gives Claude current environment
 *       state so it can answer "what are our biggest risks?" style questions accurately.</li>
 *   <li>Prepends prior conversation turns from {@link ChatMemory} so follow-up questions
 *       have context (e.g., "what about that control you mentioned?" works correctly).</li>
 *   <li>Calls Claude with a system prompt + history + current message.</li>
 *   <li>Stores only the compact question + answer in memory — NOT the full RAG context —
 *       so history stays small across turns.</li>
 * </ol>
 *
 * <p>Session ID is supplied by the client as the {@code X-Session-Id} header.
 * If absent, a new UUID is generated and returned — the client should persist it
 * for subsequent turns.
 */
@RestController
@RequestMapping("/api")
public class ChatController {

    private static final Logger log = LoggerFactory.getLogger(ChatController.class);

    private static final String SYSTEM_PROMPT = """
            You are a cloud security compliance expert assistant for an AWS environment.

            You will be given:
            1. RELEVANT FRAMEWORK CONTROLS — the most semantically similar sections from \
            NIST 800-53, CIS AWS Benchmark, and SOC2, retrieved from the compliance \
            knowledge base for this specific question.
            2. RECENT VIOLATIONS — compliance violations currently detected in the \
            environment, so you can answer questions about the actual compliance posture.

            Guidelines:
            - Base answers on the provided framework controls and violation data.
            - Always cite specific control IDs (e.g., AC-3, SC-7, CIS 1.4) when relevant.
            - If the provided context is insufficient to answer, say so — do not hallucinate.
            - Be concise but precise. One to three paragraphs is usually the right length.
            """;

    private final ChatClient chatClient;
    private final ChatMemory chatMemory;
    private final RetrievalService retrievalService;
    private final JdbcTemplate jdbcTemplate;

    public ChatController(ChatClient.Builder chatClientBuilder,
                          ChatMemory chatMemory,
                          RetrievalService retrievalService,
                          JdbcTemplate jdbcTemplate) {
        this.chatClient = chatClientBuilder.build();
        this.chatMemory = chatMemory;
        this.retrievalService = retrievalService;
        this.jdbcTemplate = jdbcTemplate;
    }

    // ── POST /api/chat ────────────────────────────────────────────────────────

    @PostMapping("/chat")
    public ResponseEntity<Map<String, Object>> chat(
            @RequestHeader(value = "X-Session-Id", required = false) String sessionId,
            @RequestBody Map<String, String> body) {

        String question = body.get("message");
        if (question == null || question.isBlank()) {
            return ResponseEntity.badRequest().build();
        }

        // Generate a session ID if the client didn't supply one
        if (sessionId == null || sessionId.isBlank()) {
            sessionId = UUID.randomUUID().toString();
        }
        final String sid = sessionId;

        log.debug("Chat request — sessionId={} question='{}'", sid, question);

        // 1. RAG: embed the question, retrieve top-5 most relevant control chunks.
        //    Wrapped in try-catch so a quota error or unavailable embedding API degrades
        //    gracefully — chat still works using violations context + Claude's training knowledge.
        List<RetrievedChunk> chunks;
        try {
            chunks = retrievalService.search(question, 5);
        } catch (Exception e) {
            log.warn("RAG retrieval failed (embeddings unavailable?) — proceeding without framework chunks: {}", e.getMessage());
            chunks = List.of();
        }
        List<String> citedControlIds = chunks.stream()
                .map(RetrievedChunk::controlId)
                .distinct()
                .toList();

        // 2. Load recent violations for current environment state context
        String violationsContext = loadRecentViolations();

        // 3. Load prior conversation turns from ChatMemory
        List<Message> history = chatMemory.get(sid);

        // 4. Build the full user message for this turn (question + RAG + violations)
        String userMessage = buildUserMessage(question, chunks, violationsContext);

        // 5. Call Claude: system + prior history + current message with full context
        String answer = chatClient.prompt()
                .system(SYSTEM_PROMPT)
                .messages(history)
                .user(userMessage)
                .call()
                .content();

        // 6. Store only the compact Q&A in memory — not the full RAG context —
        //    so history stays small and doesn't bloat subsequent calls.
        chatMemory.add(sid, List.of(
                new UserMessage(question),
                new AssistantMessage(answer)));

        Map<String, Object> response = new LinkedHashMap<>();
        response.put("answer", answer);
        response.put("citedControlIds", citedControlIds);
        response.put("sessionId", sid);

        return ResponseEntity.ok(response);
    }

    // ── Prompt assembly ───────────────────────────────────────────────────────

    private String buildUserMessage(String question,
                                    List<RetrievedChunk> chunks,
                                    String violationsContext) {
        StringBuilder sb = new StringBuilder();

        sb.append("RELEVANT FRAMEWORK CONTROLS:\n\n");
        if (chunks.isEmpty()) {
            sb.append("(No framework controls retrieved — embeddings may not be ingested yet.)\n");
        } else {
            for (int i = 0; i < chunks.size(); i++) {
                RetrievedChunk c = chunks.get(i);
                sb.append("[").append(i + 1).append("] ")
                  .append(c.framework()).append(" | ")
                  .append(c.controlId());
                if (c.severity() != null) sb.append(" | ").append(c.severity());
                sb.append("\n");
                // Cap each chunk to avoid overflowing Claude's context window
                String content = c.content().length() > 1200
                        ? c.content().substring(0, 1200) + "..."
                        : c.content();
                sb.append(content).append("\n\n");
            }
        }

        sb.append("RECENT VIOLATIONS:\n\n").append(violationsContext).append("\n\n");
        sb.append("QUESTION: ").append(question);

        return sb.toString();
    }

    // ── DB helpers ────────────────────────────────────────────────────────────

    /**
     * Returns a compact text summary of the 10 most recent violations.
     * Loaded fresh on every request so the chat always reflects current DB state.
     */
    private String loadRecentViolations() {
        List<Map<String, Object>> rows = jdbcTemplate.queryForList("""
                SELECT resource_id, resource_type, control_id, framework, severity, reasoning
                FROM violations
                ORDER BY first_seen_at DESC
                LIMIT 10
                """);

        if (rows.isEmpty()) {
            return "(No violations detected yet — run a scan first.)";
        }

        StringBuilder sb = new StringBuilder();
        for (Map<String, Object> row : rows) {
            sb.append("• [").append(row.get("severity")).append("] ")
              .append(row.get("resource_type")).append(" ").append(row.get("resource_id"))
              .append(" — ").append(row.get("framework")).append(" ").append(row.get("control_id"))
              .append(": ").append(row.get("reasoning")).append("\n");
        }
        return sb.toString();
    }
}
