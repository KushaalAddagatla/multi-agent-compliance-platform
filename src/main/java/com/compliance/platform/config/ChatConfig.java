package com.compliance.platform.config;

import org.springframework.ai.anthropic.AnthropicChatModel;
import org.springframework.ai.chat.memory.ChatMemory;
import org.springframework.ai.chat.memory.InMemoryChatMemoryRepository;
import org.springframework.ai.chat.memory.MessageWindowChatMemory;
import org.springframework.ai.chat.model.ChatModel;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;

/**
 * Chat-layer Spring beans.
 *
 * <p><b>primaryChatModel</b> — disambiguates between Anthropic and OpenAI ChatModel beans.
 * Both starters register a ChatModel; @Primary makes Anthropic win wherever a single
 * ChatModel is injected (AnalyzerAgent, ChatController, etc.).
 *
 * <p><b>chatMemory</b> — session-keyed conversation history for the Q&A chat endpoint.
 * {@link MessageWindowChatMemory} keeps the last 20 messages per session ID, preventing
 * unbounded context growth while preserving enough history for coherent multi-turn Q&A.
 * {@link InMemoryChatMemoryRepository} is the backing store — appropriate for single-instance
 * dev/demo use; swap to a JDBC or Redis repository for multi-instance production deployments.
 */
@Configuration
public class ChatConfig {

    @Bean
    @Primary
    public ChatModel primaryChatModel(AnthropicChatModel anthropicChatModel) {
        return anthropicChatModel;
    }

    @Bean
    public ChatMemory chatMemory() {
        return MessageWindowChatMemory.builder()
                .chatMemoryRepository(new InMemoryChatMemoryRepository())
                .maxMessages(20)
                .build();
    }
}
