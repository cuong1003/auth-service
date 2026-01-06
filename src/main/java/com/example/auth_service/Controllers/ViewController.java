package com.example.auth_service.Controllers;

import com.example.auth_service.Models.Dto.LoginRequest;
import com.example.auth_service.Models.Entity.User;
import com.example.auth_service.Repository.UserRepository;
import com.example.auth_service.utils.JwtUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;

@Controller
public class ViewController {

    @Autowired
    private UserRepository userRepository;
    @Autowired
    private PasswordEncoder passwordEncoder;
    @Autowired
    private JwtUtil jwtUtil;

    @GetMapping("/login")
    public String loginPage() {
        return "login";
    }

    @GetMapping("/")
    public String index() {
        return "redirect:/login";
    }

    @GetMapping("/dashboard")
    public String dashboard() {
        return "dashboard";
    }

    @PostMapping("/login")
    public String login(@ModelAttribute LoginRequest req, Model model) {
        User user = userRepository.findByUsername(req.getUsername());
        if (user != null && passwordEncoder.matches(req.getPassword(), user.getPassword())) {
            String token = jwtUtil.generateToken(user.getUsername(), user.getRole());
            System.out.println(token);
            model.addAttribute("message", "Chào " + req.getUsername());
            return "dashboard";
        }
        model.addAttribute("message", "Sai tài khoản hoặc mật khẩu");
        return "login";
    }
}