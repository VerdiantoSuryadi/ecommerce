package com.auth.services.ecommerce.services;

import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.script.DefaultRedisScript;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.auth.services.ecommerce.dto.request.LoginRequest;
import com.auth.services.ecommerce.dto.request.RefreshTokenRequest;
import com.auth.services.ecommerce.dto.request.RegisterRequest;
import com.auth.services.ecommerce.dto.response.TokenResponse;
import com.auth.services.ecommerce.entity.User;
import com.auth.services.ecommerce.enums.Role;
import com.auth.services.ecommerce.exception.EmailAlreadyExistsException;
import com.auth.services.ecommerce.exception.InvalidTokenException;
import com.auth.services.ecommerce.repository.UserRepository;
import com.auth.services.ecommerce.security.JwtService;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final AuthenticationManager authenticationManager;
    private final JwtService jwtService;
    private final StringRedisTemplate redisTemplate;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    @Value("${jwt.expiration.access}")
    private Long accessExpiration;

    private static final String SESSION_PREFIX = "session:";

    @Transactional
    public TokenResponse register(RegisterRequest request) {
        boolean existsByEmail = userRepository.existsByEmail(request.email());

        if (existsByEmail) {
            throw new EmailAlreadyExistsException("Email is already in use");
        }

        User user = User.builder()
                .email(request.email())
                .password(passwordEncoder.encode(request.password()))
                .role(Role.CUSTOMER)
                .isActive(true)
                .build();

        userRepository.save(user);

        String sessionId = UUID.randomUUID().toString();
        String accessToken = jwtService.generateAccessToken(request.email(), sessionId);
        String refreshToken = jwtService.generateRefreshToken(request.email(), sessionId);

        DecodedJWT accessJwt = jwtService.verifyAccessToken(accessToken);
        DecodedJWT refreshJwt = jwtService.verifyRefreshToken(refreshToken);

        String sessionKey = SESSION_PREFIX + sessionId;

        redisTemplate.opsForHash().putAll(sessionKey, Map.of(
                "email", user.getEmail(),
                "accessJti", accessJwt.getId(),
                "refreshJti", refreshJwt.getId()));
        redisTemplate.expire(sessionKey, Duration.ofMillis(jwtService.getRefreshExpiration()));

        return new TokenResponse(
                "Bearer",
                accessToken,
                refreshToken,
                accessExpiration / 1000);
    }

    public TokenResponse login(LoginRequest request) {
        // authenticate username and password
        authenticationManager
                .authenticate(new UsernamePasswordAuthenticationToken(request.email(), request.password()));
        // generate session id
        String sessionId = UUID.randomUUID().toString();
        // generate token
        String accessToken = jwtService.generateAccessToken(request.email(), sessionId);

        String refreshToken = jwtService.generateRefreshToken(request.email(), sessionId);

        // verify refresh token to get jwt id
        DecodedJWT accessJwt = jwtService.verifyAccessToken(accessToken);

        DecodedJWT refreshJwt = jwtService.verifyRefreshToken(refreshToken);
        String sessionKey = SESSION_PREFIX + sessionId;

        // Store refresh token in Redis
        redisTemplate.opsForHash().putAll(sessionKey, Map.of(
                "email", request.email(),
                "accessJti", accessJwt.getId(),
                "refreshJti", refreshJwt.getId()));
        redisTemplate.expire(sessionKey, Duration.ofMillis(jwtService.getRefreshExpiration()));

        // return tokens
        return new TokenResponse(
                "Bearer",
                accessToken,
                refreshToken,
                accessExpiration / 1000);
    }

    public TokenResponse refreshToken(RefreshTokenRequest request) {
        try {
            // Verify Refreh token signature and expiration
            DecodedJWT refreshJwt = jwtService.verifyRefreshToken(request.refreshToken());
            String email = refreshJwt.getSubject();
            String sessionId = refreshJwt.getClaim("sid").asString();
            String oldRefreshJti = refreshJwt.getId();

            String sessionKey = SESSION_PREFIX + sessionId;

            // generate new token pair
            String newAccessToken = jwtService.generateAccessToken(email, sessionId);

            String newRefreshToken = jwtService.generateRefreshToken(email, sessionId);

            // store new refresh token
            DecodedJWT newAccessJwt = jwtService.verifyAccessToken(newAccessToken);
            DecodedJWT newRefreshJwt = jwtService.verifyRefreshToken(newRefreshToken);

            // Atomic refresh token rotation
            String script = "if redis.call('HGET', KEYS[1], 'refreshJti') " +
                    "~= ARGV[1] then return 0 end; " +
                    "redis.call('HSET', KEYS[1], " +
                    "'accessJti', ARGV[2], " +
                    "'refreshJti', ARGV[3]); " +
                    "redis.call('PEXPIRE', KEYS[1], ARGV[4]); " +
                    "return 1;";

            DefaultRedisScript<Long> redisScript = new DefaultRedisScript<>();

            redisScript.setScriptText(script);
            redisScript.setResultType(Long.class);

            Long result = redisTemplate.execute(redisScript, List.of(sessionKey), oldRefreshJti, newAccessJwt.getId(),
                    newRefreshJwt.getId(), String.valueOf(jwtService.getRefreshExpiration()));

            if (!Long.valueOf(1).equals(result)) {
                throw new InvalidTokenException("Refresh token revoked or already used");
            }

            return new TokenResponse(
                    "Bearer",
                    newAccessToken,
                    newRefreshToken,
                    accessExpiration / 1000);

        } catch (JWTVerificationException e) {
            throw new InvalidTokenException("Invalid or expired refresh token");
        }

    }

    public void logout(RefreshTokenRequest request) {
        DecodedJWT refreshJwt = jwtService.verifyRefreshToken(request.refreshToken());
        String sessionId = refreshJwt.getClaim("sid").asString();
        String sessionKey = SESSION_PREFIX + sessionId;

        String storedRefreshJti = (String) redisTemplate.opsForHash().get(sessionKey, "refreshJti");

        if (storedRefreshJti == null || !storedRefreshJti.equals(refreshJwt.getId())) {
            throw new InvalidTokenException("Invalid or revoked refresh token");
        }

        // delete this entire session
        redisTemplate.delete(sessionKey);
    }

}
