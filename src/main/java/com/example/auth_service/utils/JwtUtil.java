package com.example.auth_service.utils;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
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
    
    @Autowired
    private RedisTemplate<String, String> redisTemplate;

    // ==================== TOKEN GENERATION ====================
    
    /**
     * Tạo JWT token với username và role.
     * Token có thời hạn 15 phút.
     * 
     * @param username Tên người dùng
     * @param role     Vai trò (ADMIN, CUSTOMER, ...)
     * @return JWT token string
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

    // ==================== TOKEN VALIDATION ====================
    
    /**
     * Xác thực token - kiểm tra signature và expiration.
     * 
     * @param token JWT token cần validate
     * @return true nếu token hợp lệ, false nếu không
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
     * Kiểm tra token có nằm trong blacklist (đã logout) hay không.
     * Token được lưu trong Redis với prefix "blacklist:"
     * 
     * @param token JWT token cần kiểm tra
     * @return true nếu token đã bị blacklist
     */
    public boolean isTokenBlacklisted(String token) {
        String value = redisTemplate.opsForValue().get("blacklist:" + token);
        return value != null;
    }

    // ==================== TOKEN EXTRACTION FROM REQUEST ====================
    
    /**
     * Lấy token từ Cookie trong request.
     * Cookie name: AUTH_TOKEN
     * 
     * @param req HttpServletRequest
     * @return Token string hoặc null nếu không tìm thấy
     */
    public String getAuthTokenFromCookie(HttpServletRequest req) {
        Cookie[] cookies = req.getCookies();
        if (cookies == null) {
            return null;
        }
        for (Cookie cookie : cookies) {
            if ("AUTH_TOKEN".equals(cookie.getName())) {
                return cookie.getValue();
            }
        }
        return null;
    }

    /**
     * Lấy token từ Authorization Header trong request.
     * Format: "Bearer {token}"
     * 
     * @param req HttpServletRequest
     * @return Token string hoặc null nếu không tìm thấy
     */
    public String getAuthTokenFromRequest(HttpServletRequest req) {
        String authHeader = req.getHeader("Authorization");
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            return authHeader.substring(7);
        }
        return null;
    }

    /**
     * Lấy token từ Cookie trong request (trả về Optional).
     * 
     * @param request HttpServletRequest
     * @return Optional chứa token nếu tìm thấy, empty nếu không có
     */
    public Optional<String> extractTokenFromRequest(HttpServletRequest request) {
        if (request.getCookies() == null) {
            return Optional.empty();
        }
        for (Cookie cookie : request.getCookies()) {
            if ("AUTH_TOKEN".equals(cookie.getName())) {
                return Optional.of(cookie.getValue());
            }
        }
        return Optional.empty();
    }

    // ==================== CLAIMS EXTRACTION ====================
    
    /**
     * Extract username từ token.
     * 
     * @param token JWT token
     * @return Username (subject của token)
     */
    public String extractUsername(String token) {
        return extractAllClaims(token).getSubject();
    }

    /**
     * Extract role từ token.
     * 
     * @param token JWT token
     * @return Role của user
     */
    public String extractRole(String token) {
        return extractAllClaims(token).get("role", String.class);
    }

    /**
     * Extract thời gian hết hạn của token (timestamp milliseconds).
     * 
     * @param token JWT token
     * @return Expiration time in milliseconds
     */
    public long extractExpiration(String token) {
        return extractAllClaims(token).getExpiration().getTime();
    }

    // ==================== HELPER METHODS FOR REQUEST ====================
    
    /**
     * Lấy username từ request (đọc token từ cookie, validate, extract).
     * 
     * @param request HttpServletRequest
     * @return Optional chứa username nếu token hợp lệ
     */
    public Optional<String> getUsernameFromRequest(HttpServletRequest request) {
        return extractTokenFromRequest(request)
                .filter(this::validateToken)
                .map(this::extractUsername);
    }

    /**
     * Lấy role từ request (đọc token từ cookie, validate, extract).
     * 
     * @param request HttpServletRequest
     * @return Optional chứa role nếu token hợp lệ
     */
    public Optional<String> getRoleFromRequest(HttpServletRequest request) {
        return extractTokenFromRequest(request)
                .filter(this::validateToken)
                .map(this::extractRole);
    }

    // ==================== PRIVATE METHODS ====================

    /**
     * Parse token và lấy tất cả claims.
     */
    private Claims extractAllClaims(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(getSigningKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    /**
     * Tạo signing key từ secret (Base64 decoded).
     */
    private Key getSigningKey() {
        byte[] keyBytes = Base64.getDecoder().decode(secretKey);
        return Keys.hmacShaKeyFor(keyBytes);
    }
}
