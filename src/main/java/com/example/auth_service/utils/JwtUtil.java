package com.example.auth_service.utils;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Base64;
import java.util.Date;
import java.util.Map;

@Component
public class JwtUtil {

    @Value("${jwt.secret}")
    private String secretKey;

    public String generateToken(String username, String role) {
        byte[] keyByte = Base64.getDecoder().decode(secretKey);
        Key key = Keys.hmacShaKeyFor(keyByte);
        return Jwts.builder()
                .setClaims(Map.of("role",role))
                .setSubject(username)
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 15 * 60))
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();
    }



}
