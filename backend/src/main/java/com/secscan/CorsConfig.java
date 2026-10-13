package com.secscan;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

/** Lets the front end (GitHub Pages) call this backend from another website address. */
@Configuration
public class CorsConfig implements WebMvcConfigurer {
    @Value("${app.frontend-origin}")
    private String origin;

    @Override
    public void addCorsMappings(CorsRegistry registry) {
        registry.addMapping("/api/**")
                .allowedOrigins(origin.split(","))
                .allowedMethods("GET", "POST");
    }
}
