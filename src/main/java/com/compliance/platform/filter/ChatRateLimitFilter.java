package com.compliance.platform.filter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Limits {@code POST /api/chat} to 20 requests per minute per session.
 *
 * <p><b>Keying strategy:</b> the {@code X-Session-Id} header is used as the rate-limit
 * key when present. If absent (e.g. a raw curl call), the client IP is used as a fallback.
 * This matches the ChatController session semantics exactly — the same session that builds
 * ChatMemory history is also the unit of rate limiting.
 *
 * <p><b>Reset:</b> counts are cleared every 60 seconds via {@code @Scheduled(fixedRate = 60_000)}.
 * This is a simple sliding-window approximation — not a strict per-minute token bucket —
 * which is sufficient for protecting against accidental client loops without requiring
 * Redis or a separate rate-limit library.
 *
 * <p><b>Response:</b> 429 Too Many Requests with a JSON body so the React chat UI can
 * display a user-friendly message rather than treating it as a generic error.
 */
@Component
public class ChatRateLimitFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger(ChatRateLimitFilter.class);
    private static final int MAX_REQUESTS_PER_WINDOW = 20;

    /** Count per session key; reset every 60s by {@link #resetCounts()}. */
    private final ConcurrentHashMap<String, AtomicInteger> counts = new ConcurrentHashMap<>();

    @Scheduled(fixedRate = 60_000)
    public void resetCounts() {
        int sessions = counts.size();
        counts.clear();
        if (sessions > 0) log.debug("Rate-limit window reset — cleared {} session counters", sessions);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain chain) throws ServletException, IOException {

        // Only applies to POST /api/chat
        if (!"POST".equalsIgnoreCase(request.getMethod())
                || !"/api/chat".equals(request.getRequestURI())) {
            chain.doFilter(request, response);
            return;
        }

        String sessionId = request.getHeader("X-Session-Id");
        String key = (sessionId != null && !sessionId.isBlank())
                ? sessionId
                : request.getRemoteAddr();

        int count = counts.computeIfAbsent(key, k -> new AtomicInteger(0)).incrementAndGet();

        if (count > MAX_REQUESTS_PER_WINDOW) {
            log.warn("Rate limit exceeded — key={} count={}", key.substring(0, Math.min(key.length(), 8)), count);
            response.setStatus(429);
            response.setContentType("application/json");
            response.getWriter().write(
                    "{\"error\":\"Rate limit exceeded — max 20 requests per minute per session.\"}");
            return;
        }

        chain.doFilter(request, response);
    }
}
