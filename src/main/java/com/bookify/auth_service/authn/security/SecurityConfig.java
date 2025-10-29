package com.bookify.auth_service.authn.security;


import jakarta.servlet.Filter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
public class SecurityConfig {
    private final JwtAuthenticationFilter jwtAuthenticationFilter;
    private final JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint;
    private final  GoogleOAuthFilter googleOAuthFilter;
    public SecurityConfig(JwtAuthenticationFilter jwtAuthenticationFilter,JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint,GoogleOAuthFilter googleOAuthFilter) {
        this.jwtAuthenticationFilter = jwtAuthenticationFilter;
        this.jwtAuthenticationEntryPoint = jwtAuthenticationEntryPoint;
        this.googleOAuthFilter = googleOAuthFilter;
    }


    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {
        return configuration.getAuthenticationManager();
    }

//    @Bean
//    @Order(0)
//    public SecurityFilterChain adminApiSecurity(HttpSecurity http) throws Exception {
//        return http
//                .securityMatcher("/admin/**")
//                .csrf(AbstractHttpConfigurer::disable)
//                .authorizeHttpRequests(auth -> auth.anyRequest().hasRole("ADMIN"))
//                .httpBasic(Customizer.withDefaults()) // simple for now
//                .build();
//    }


    @Bean
    @Order(1)
    public SecurityFilterChain jwtAuthFilterChain(HttpSecurity http) throws Exception {
        return http
                .securityMatcher("/api/auth/jwt/**","/admin/**")
                .csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/api/auth/jwt/register", "/api/auth/jwt/login", "/api/auth/jwt/refresh").permitAll()
                        .requestMatchers("/admin/**").hasRole("ADMIN")
                        .requestMatchers("/super-admin/**").hasRole("SUPER_ADMIN")// 👈 restrict to admin

                        .anyRequest().authenticated()
                )
                .exceptionHandling(ex -> ex
                        .authenticationEntryPoint(jwtAuthenticationEntryPoint)
                )
                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
                .build();
    }

    @Bean
    @Order(2)
    public SecurityFilterChain basicAuthFilterChain(HttpSecurity http) throws Exception {
        return http
                .securityMatcher("/api/auth/basic/**")
                .csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/api/auth/basic/register", "/api/auth/basic/login").permitAll()
                        .anyRequest().authenticated()
                )
                .httpBasic(Customizer.withDefaults())
                .build();
    }
    @Bean
    @Order(3)
    public SecurityFilterChain oauthFilterChain(HttpSecurity http) throws Exception {

        return http
                .securityMatcher("/api/auth/oauth/**")
                .csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/api/auth/oauth/login/google", "/api/auth/oauth/callback/google").permitAll()
                        .anyRequest().authenticated()
                )

                .addFilterBefore(googleOAuthFilter, UsernamePasswordAuthenticationFilter.class)
                .build();
    }


    @Bean
    @Order(4)
    public SecurityFilterChain defaultFilterChain(HttpSecurity http) throws Exception {
        return http
                .csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(auth -> auth.anyRequest().permitAll())
                .build();
    }



    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public JwtAuthenticationConverter jwtAuthenticationConverter() {
//        The JwtAuthenticationConverter bean is only needed when you use:
//Spring’s default OAuth2ResourceServer setup (http.oauth2ResourceServer(jwt -> …)),
        JwtGrantedAuthoritiesConverter grantedAuthoritiesConverter = new JwtGrantedAuthoritiesConverter();
        grantedAuthoritiesConverter.setAuthoritiesClaimName("roles");
        grantedAuthoritiesConverter.setAuthorityPrefix("ROLE_"); // adds ROLE_ prefix automatically

        JwtAuthenticationConverter converter = new JwtAuthenticationConverter();
        converter.setJwtGrantedAuthoritiesConverter(grantedAuthoritiesConverter);
        return converter;
    }

}
