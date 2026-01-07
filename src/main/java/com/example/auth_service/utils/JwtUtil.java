package com.example.auth_service.utils;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Base64;
import java.util.Date;
import java.util.Map;
import java.util.Optional;

@Component
public class JwtUtil {

    @Value("${jwt.secret}")
    private String secretKey;

    private static final String AUTH_COOKIE_NAME = "AUTH_TOKEN";

    /**
     * Generate JWT token với username và role.
     * Token có thời hạn 15 phút.
     */
    public String generateToken(String username, String role) {
        Key key = getSigningKey();
        return Jwts.builder()
                .setClaims(Map.of("role", role))
                .setSubject(username)
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 15 * 60)) // 15 minutes
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();
    }

    /**
     * Validate token - kiểm tra signature và expiration.
     */
    public boolean validateToken(String token) {
        try {
            Jwts.parserBuilder()
                    .setSigningKey(getSigningKey())
                    .build()
                    .parseClaimsJws(token);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Extract username từ token.
     */
    public String extractUsername(String token) {
        return extractAllClaims(token).getSubject();
    }

    /**
     * Extract role từ token.
     */
    public String extractRole(String token) {
        return extractAllClaims(token).get("role", String.class);
    }

    /**
     * Lấy token từ Cookie trong request.
     * @return Optional chứa token nếu tìm thấy, empty nếu không có.
     */
    public Optional<String> extractTokenFromRequest(HttpServletRequest request) {
        if (request.getCookies() == null) {
            return Optional.empty();
        }
        for (Cookie cookie : request.getCookies()) {
            if (AUTH_COOKIE_NAME.equals(cookie.getName())) {
                return Optional.of(cookie.getValue());
            }
        }
        return Optional.empty();
    }

    /**
     * Lấy username từ request (đọc token từ cookie).
     * @return Optional chứa username nếu token hợp lệ.
     */
    public Optional<String> getUsernameFromRequest(HttpServletRequest request) {
        return extractTokenFromRequest(request)
                .filter(this::validateToken)
                .map(this::extractUsername);
    }

    /**
     * Lấy role từ request (đọc token từ cookie).
     * @return Optional chứa role nếu token hợp lệ.
     */
    public Optional<String> getRoleFromRequest(HttpServletRequest request) {
        return extractTokenFromRequest(request)
                .filter(this::validateToken)
                .map(this::extractRole);
    }

    // ========== Private Methods ==========

    private Claims extractAllClaims(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(getSigningKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    private Key getSigningKey() {
        byte[] keyBytes = Base64.getDecoder().decode(secretKey);
        return Keys.hmacShaKeyFor(keyBytes);
    }

}
