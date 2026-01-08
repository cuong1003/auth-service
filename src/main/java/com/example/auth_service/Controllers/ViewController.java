package com.example.auth_service.Controllers;

import com.example.auth_service.Models.Dto.LoginRequest;
import com.example.auth_service.Models.Entity.User;
import com.example.auth_service.Repository.UserRepository;
import com.example.auth_service.utils.JwtUtil;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;

import java.util.concurrent.TimeUnit;

@Controller
public class ViewController {

    @Autowired
    private UserRepository userRepository;
    @Autowired
    private PasswordEncoder passwordEncoder;
    @Autowired
    private JwtUtil jwtUtil;
    @Autowired
    private RedisTemplate<String, String> redisTemplate;

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
    public String login(@ModelAttribute LoginRequest req,
                        Model model, HttpServletResponse res) {
        User user = userRepository.findByUsername(req.getUsername());
        if (user != null && passwordEncoder.matches(req.getPassword(), user.getPassword())) {
            String token = jwtUtil.generateToken(user.getUsername(), user.getRole());
            Cookie cookie = new Cookie("AUTH_TOKEN", token);
            cookie.setHttpOnly(true);
            cookie.setSecure(false);
            cookie.setPath("/");
            cookie.setMaxAge(60 * 60 * 24 * 7);
            res.addCookie(cookie);
            model.addAttribute("message", "Chào " + req.getUsername());
            return "redirect:/dashboard";
        }
        model.addAttribute("message", "Sai tài khoản hoặc mật khẩu");
        return "login";
    }

    @PostMapping("/do-logout")
    public String logout(HttpServletResponse res, HttpServletRequest req) {
        String token = jwtUtil.extractTokenFromRequest(req).orElse(null);
        
        if (token != null) {
            try {
                long tokenTimeRemainingMillis = jwtUtil.extractExpiration(token) - System.currentTimeMillis();
                long tokenTimeRemainingSeconds = tokenTimeRemainingMillis > 0 ? tokenTimeRemainingMillis / 1000 : 0;
                redisTemplate.opsForValue().set(
                        "blacklist:" + token, "logout", tokenTimeRemainingSeconds, TimeUnit.SECONDS
                );
            } catch (Exception ignored) {
            }
        }

        Cookie cookie = new Cookie("AUTH_TOKEN", "");
        cookie.setHttpOnly(true);
        cookie.setSecure(false);
        cookie.setPath("/");
        cookie.setMaxAge(0);
        res.addCookie(cookie);
        
        return "redirect:/login";
    }
}