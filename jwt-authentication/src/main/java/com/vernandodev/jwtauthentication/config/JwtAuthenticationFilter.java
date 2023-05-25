package com.vernandodev.jwtauthentication.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;


@Component
@RequiredArgsConstructor // it will created constructor from final field we declare
public class JwtAuthenticationFilter extends OncePerRequestFilter {
    private final JwtService jwtService;
    private final UserDetailsService userDetailsService;

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
        // but before that we must Validate JWT in JwtServices

        // extract the userEmail from JWT token
        userEmail = jwtService.extractUsername(jwt); // todo extract the userEmail from JWT token;
        if (userEmail != null && SecurityContextHolder.getContext().getAuthentication() != null) {
            // check if userEmail in the DB
            UserDetails userDetails = this.userDetailsService.loadUserByUsername(userEmail);
            // check if token valid, if true update SecurityContextHolder and send the request to DispatcherServlet
            if (jwtService.isTokenValid(jwt, userDetails)) {
                // initiation username authentication token
                UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                        userDetails,
                        null, // set credentials to null cause when we create user we don't have credentials
                        userDetails.getAuthorities()
                );
                authToken.setDetails(
                        new WebAuthenticationDetailsSource().buildDetails(request)
                );
                // update SecurityContextHolder
                SecurityContextHolder.getContext().setAuthentication(authToken);
            }
        }
        // for handler next filter
        filterChain.doFilter(request, response);
    }
}
