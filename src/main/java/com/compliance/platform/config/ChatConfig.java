package com.compliance.platform.config;

import org.springframework.ai.anthropic.AnthropicChatModel;
import org.springframework.ai.chat.model.ChatModel;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;

/**
 * Disambiguates the ChatModel bean.
 *
 * Both spring-ai-starter-model-anthropic and spring-ai-starter-model-openai register a
 * ChatModel bean. OpenAI chat is disabled in application.yml (used for embeddings only),
 * but its bean is still present on the context. @Primary ensures ChatClientAutoConfiguration
 * injects the Anthropic model everywhere a single ChatModel is expected.
 */
@Configuration
public class ChatConfig {

    @Bean
    @Primary
    public ChatModel primaryChatModel(AnthropicChatModel anthropicChatModel) {
        return anthropicChatModel;
    }
}
