package com.api.gateway;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.server.SecurityWebFilterChain;
@Configuration
@EnableWebFluxSecurity
public class SecurityConfig {
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {
        return httpSecurity
                .csrf(csrf -> csrf.disable())
                .httpBasic(http -> http.disable())  // Deshabilitar httpBasic si no lo necesitas
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(auth -> {
                    // Configurar los endpoints públicos:
                    auth.requestMatchers("/api/auth/log-in", "/api/auth/sign-up").permitAll();
                    // Configurar los endpoints privados:
                    auth.requestMatchers(HttpMethod.GET, "/api/auth/get").hasAuthority("READ");
                    // O si estás usando roles:
                    // auth.requestMatchers(HttpMethod.GET, "/api/auth/get").hasRole("DEVELOPER");
                    // Configurar el resto de endpoints - NO ESPECIFICADOS:
                    auth.anyRequest().denyAll();
                })
                .addFilterBefore(new JwtTokenValidator(jwtUtils), BasicAuthenticationFilter.class)
                .build();
    }
}
