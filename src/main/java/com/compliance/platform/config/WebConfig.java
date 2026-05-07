package com.compliance.platform.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

/**
 * Global CORS configuration.
 *
 * <p>Allows the React dev server (Vite on :5173, CRA on :3000) to call the Spring Boot
 * API during local development. In production, the React app is served from the same
 * origin (nginx reverse proxy), so this only matters for local dev — but it's safe to
 * leave in place since allowedOrigins is an explicit allow-list, not a wildcard.
 */
@Configuration
public class WebConfig implements WebMvcConfigurer {

    @Override
    public void addCorsMappings(CorsRegistry registry) {
        registry.addMapping("/api/**")
                .allowedOrigins(
                        "http://localhost:5173",   // Vite default
                        "http://localhost:3000"    // CRA / fallback
                )
                .allowedMethods("GET", "POST", "PATCH", "DELETE", "OPTIONS")
                .allowedHeaders("*")
                .allowCredentials(true)
                .maxAge(3600);
    }
}
