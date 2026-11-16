package com.auth.services.ecommerce.security;

import java.io.IOException;

import org.springframework.data.redis.RedisConnectionFailureException;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {
    private final JwtService jwtService;
    private final CustomUserDetailsService userDetailsService;
    private final StringRedisTemplate redisTemplate;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        String authHeader = request.getHeader("Authorization");
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }

        String token = authHeader.substring(7);
        DecodedJWT decodedJWT;

        // 1. Verify Jwt
        try {
            decodedJWT = jwtService.verifyAccessToken(token);
        } catch (JWTVerificationException e) {
            SecurityContextHolder.clearContext();

            writeError(
                    response,
                    HttpServletResponse.SC_UNAUTHORIZED,
                    "Invalid or expired access token");
            return;
        }

        String email = decodedJWT.getSubject();
        String sessionId = decodedJWT.getClaim("sid").asString();
        String accessJti = decodedJWT.getId();

        // 2. Check Redis Session
        try {
            if (sessionId == null || accessJti == null) {
                writeError(
                        response,
                        HttpServletResponse.SC_UNAUTHORIZED,
                        "Invalid access token");
                return;
            }

            String sessionKey = "session:" + sessionId;

            String storedAccessJti = (String) redisTemplate.opsForHash().get(sessionKey, "accessJti");
            if (storedAccessJti == null || !storedAccessJti.equals(accessJti)) {

                SecurityContextHolder.clearContext();

                writeError(
                        response,
                        HttpServletResponse.SC_UNAUTHORIZED,
                        "Access token revoked");
                return;
            }

        } catch (RedisConnectionFailureException e) {
            SecurityContextHolder.clearContext();
            writeError(
                    response,
                    HttpServletResponse.SC_SERVICE_UNAVAILABLE,
                    "Authentication service temporarily unavailable");

            return;
        }

        // 3. Load user details
        try {
            if (SecurityContextHolder.getContext().getAuthentication() == null) {
                UserDetails userDetails = userDetailsService.loadUserByUsername(email);

                UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                        userDetails, null, userDetails.getAuthorities());

                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                SecurityContextHolder.getContext().setAuthentication(authentication);
            }
        } catch (UsernameNotFoundException e) {
            SecurityContextHolder.clearContext();

            writeError(
                    response,
                    HttpServletResponse.SC_UNAUTHORIZED,
                    "User not found");

            return;
        }

        filterChain.doFilter(request, response);
    }

    private void writeError(
            HttpServletResponse response,
            int status,
            String message) throws IOException {

        response.setStatus(status);
        response.setContentType("application/json");
        response.setCharacterEncoding("UTF-8");

        response.getWriter().write(
                "{\"message\":\"" + message + "\"}");
    }

}
