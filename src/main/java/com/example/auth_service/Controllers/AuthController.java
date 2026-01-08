package com.example.auth_service.Controllers;

import com.example.auth_service.Models.Dto.SignUpRequest;
import com.example.auth_service.Models.Entity.User;
import com.example.auth_service.Repository.UserRepository;
import com.example.auth_service.utils.JwtUtil;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

@RestController
public class AuthController {
    @Autowired
    private UserRepository userRepository;
    @Autowired
    private PasswordEncoder passwordEncoder;
    @Autowired
    private JwtUtil jwtUtil;

    //Tạo tài khoản
    @PostMapping("/api/auth/signup")
    public ResponseEntity<?> signUp(@RequestBody SignUpRequest req) {
        if (userRepository.findByUsername(req.getUsername()) != null) {
            return ResponseEntity.badRequest().body("Tên đăng nhập đã tồi tại");
        } else if (!req.getPassword().equals(req.getRepeatPassword())) {
            return ResponseEntity.badRequest().body("Mật khẩu không khớp");
        } else {
            User newUser = new User();
            newUser.setUsername(req.getUsername());
            newUser.setPassword(passwordEncoder.encode(req.getPassword()));
            newUser.setRole(req.getRole());
            userRepository.save(newUser);
        }
        return ResponseEntity.ok().body("Tạo tài khoản thành công");
    }
    @PostMapping("/api/auth/validate-token")
    public ResponseEntity<?> validateToken(HttpServletRequest req) {
        String token = jwtUtil.getAuthTokenFromRequest(req);
        Map<String, Object> response = new HashMap<>();
        if (token != null && !jwtUtil.isTokenBlacklisted(token) && jwtUtil.validateToken(token)) {
            response.put("valid", true);
            response.put("message", "Token is valid");
            return ResponseEntity.ok(response);
        }
        response.put("valid", false);
        response.put("message", "Token is invalid or blacklisted");
        return ResponseEntity.ok(response);
    }


}