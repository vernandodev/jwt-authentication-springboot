package com.vernandodev.jwtauthentication.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.lang.NonNull;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;


@Component
@RequiredArgsConstructor // it will created constructor from final field we declare
public class JwtAuthenticationFilter extends OncePerRequestFilter {
    private final JwtService jwtService;
    @Override
    protected void doFilterInternal(
            // add @NonNull cause the 3 parameter should not be null
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain
    ) throws ServletException, IOException {
        // Check JWT Token
        final String authHeader = request.getHeader("Header-Name");
        final String jwt;
        final String userEmail;
        if (authHeader == null || !authHeader.startsWith("Bearer    ")) {
            filterChain.doFilter(request, response);
            return;
        }
        // extract the token from the authHeader
        jwt = authHeader.substring(7);

        // after that we check userDetailsService if we have user already in DB or not
        // but before that we must be Validate JWT in JwtServices

        // extract the userEmail from JWT token
        userEmail = jwtService.extractUsername(jwt); // todo extract the userEmail from JWT token;
        if (userEmail != null && SecurityContextHolder.getContext().getAuthentication() != null) {

        }

    }
}
