package com.example.auth_service.Controllers;

import com.example.auth_service.Models.Dto.SignUpRequest;
import com.example.auth_service.Models.Entity.User;
import com.example.auth_service.Repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class AuthController {
    @Autowired
    private UserRepository userRepository;
    @Autowired
    private PasswordEncoder passwordEncoder;

    //Tạo tài khoản
    @PostMapping("/signup")
    public ResponseEntity<?> signUp(@RequestBody SignUpRequest req) {
        if (userRepository.findByUsername(req.getUsername()) != null) {
            return ResponseEntity.badRequest().body("Tên đăng nhập đã tồi tại");
        } else if (!req.getUsername().equals(req.getRepeatPassword())) {
            return ResponseEntity.badRequest().body("Mật khẩu không khớp");
        } else {
            User newUser = new User();
            newUser.setUsername(req.getUsername());
            newUser.setPassword(passwordEncoder.encode(req.getPassword()));
            userRepository.save(newUser);
        }
        return ResponseEntity.ok().body("Tạo tài khoản thành công");
    }


}