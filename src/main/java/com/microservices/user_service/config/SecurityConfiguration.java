package com.microservices.user_service.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import lombok.RequiredArgsConstructor;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfiguration {

    private final JwtAuthenticationFilter jwtAuthFilter;

    private final AuthenticationProvider authenticationProvider;

    // 1. create filter chain
    // 2. register filters to the filter chain

    // filter chail
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                // jwt based apis dont use csrf ( csrf is used to prevent unauthorized form
                // submission )
                .csrf(csrf -> csrf.disable())
                .authorizeHttpRequests(auth -> auth
                        // allow access to selected paths without auth
                        .requestMatchers("/api/auth/**").permitAll()

                        // all other paths are available only with auth
                        .anyRequest().authenticated())
                .sessionManagement(session -> session
                        // No server-side session; JWT handles user info
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                // Checks user login details (e.g., email/password)
                .authenticationProvider(authenticationProvider)
                // Runs JWT filter to check tokens before default login filter
                .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }
}
