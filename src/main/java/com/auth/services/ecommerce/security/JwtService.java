package com.auth.services.ecommerce.security;

import java.util.Date;
import java.util.UUID;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;

@Service
public class JwtService {
    private final Algorithm accessAlgorithm;
    private final Algorithm refreshAlgorithm;

    private final Long accessExpiration;
    private final Long refreshExpiration;

    private final String issuer;

    public JwtService(@Value("${jwt.secret.access}") String accessSecret,
            @Value("${jwt.secret.refresh}") String refreshSecret,
            @Value("${jwt.expiration.access}") Long accessExpiration,
            @Value("${jwt.expiration.refresh}") Long refreshExpiration,
            @Value("${jwt.issuer}") String issuer) {
        this.accessAlgorithm = Algorithm.HMAC256(accessSecret);
        this.refreshAlgorithm = Algorithm.HMAC256(refreshSecret);
        this.accessExpiration = accessExpiration;
        this.refreshExpiration = refreshExpiration;
        this.issuer = issuer;
    }

    public String generateAccessToken(String email, String sessionId) {
        return JWT.create()
                .withIssuer(issuer)
                .withSubject(email)
                .withJWTId(UUID.randomUUID().toString())
                .withClaim("type", "access")
                .withClaim("sid", sessionId)
                .withIssuedAt(new Date())
                .withExpiresAt(new Date(System.currentTimeMillis() + accessExpiration))
                .sign(accessAlgorithm);
    }

    public String generateRefreshToken(String email, String sessionId) {
        return JWT.create()
                .withIssuer(issuer)
                .withSubject(email)
                .withJWTId(UUID.randomUUID().toString())
                .withClaim("type", "refresh")
                .withClaim("sid", sessionId)
                .withIssuedAt(new Date())
                .withExpiresAt(new Date(System.currentTimeMillis() + refreshExpiration))
                .sign(refreshAlgorithm);
    }

    public DecodedJWT verifyAccessToken(String token) {
        JWTVerifier verifier = JWT.require(accessAlgorithm)
                .withIssuer(issuer)
                .withClaim("type", "access")
                .build();

        return verifier.verify(token);
    }

    public DecodedJWT verifyRefreshToken(String token) {
        JWTVerifier verifier = JWT.require(refreshAlgorithm)
                .withIssuer(issuer)
                .withClaim("type", "refresh")
                .build();

        return verifier.verify(token);
    }

    public Long getRefreshExpiration() {
        return refreshExpiration;
    }

}
