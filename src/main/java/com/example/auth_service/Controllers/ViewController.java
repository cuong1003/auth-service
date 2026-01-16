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

import java.util.Enumeration;
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
    public String loginPage(HttpServletRequest req, Model model) {
        String prefix = getPrefix(req);
        // Debug: In ra tất cả headers để kiểm tra
        System.out.println("=== DEBUG HEADERS ===");
        Enumeration<String> headerNames = req.getHeaderNames();
        while (headerNames.hasMoreElements()) {
            String name = headerNames.nextElement();
            System.out.println(name + ": " + req.getHeader(name));
        }
        System.out.println("X-Forwarded-Prefix value: [" + prefix + "]");
        System.out.println("=== END DEBUG ===");
        
        model.addAttribute("prefix", prefix);
        return "login";
    }

    @GetMapping("/")
    public String index(HttpServletRequest req) {
        return "redirect:" + getPrefix(req) + "/login";
    }

    @GetMapping("/dashboard")
    public String dashboard(HttpServletRequest req, Model model) {
        String token = "";
        Cookie[] cookies = req.getCookies();
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if (cookie.getName().equals("AUTH_TOKEN")) {
                    token=cookie.getValue();
                }
            }
        }
        String role = jwtUtil.extractRole(token);
        model.addAttribute("role", role);
        model.addAttribute("prefix", getPrefix(req));
        return "dashboard";
    }

    @PostMapping("/login")
    public String login(@ModelAttribute LoginRequest loginRequest,
                        Model model, HttpServletResponse res, HttpServletRequest req) {
        User user = userRepository.findByUsername(loginRequest.getUsername());
        if (user != null && passwordEncoder.matches(loginRequest.getPassword(), user.getPassword())) {
            String token = jwtUtil.generateToken(user.getUsername(), user.getRole());
            Cookie cookie = new Cookie("AUTH_TOKEN", token);
            cookie.setHttpOnly(true);
            cookie.setSecure(false);
            cookie.setPath("/");
            cookie.setMaxAge(60 * 60 * 24 * 7);
            res.addCookie(cookie);
            model.addAttribute("message", "Chào " + loginRequest.getUsername());
            return "redirect:" + getPrefix(req) + "/dashboard";
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
        
        return "redirect:" + getPrefix(req) + "/login";
    }

    /**
     * Lấy prefix từ header X-Forwarded-Prefix (do Gateway gửi).
     * Nếu không có header (truy cập trực tiếp), trả về empty string.
     */
    private String getPrefix(HttpServletRequest req) {
        // Kiểm tra cả 2 trường hợp vì header có thể viết hoa hoặc thường
        String prefix = req.getHeader("X-Forwarded-Prefix");
        if (prefix == null) {
            prefix = req.getHeader("x-forwarded-prefix");
        }
        
        // Xử lý trường hợp có nhiều giá trị (ví dụ: /auth,/auth)
        if (prefix != null && prefix.contains(",")) {
            prefix = prefix.split(",")[0].trim();
        }
        
        return prefix != null ? prefix : "";
    }
}