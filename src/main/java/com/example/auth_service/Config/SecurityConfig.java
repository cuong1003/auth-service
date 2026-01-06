package com.example.auth_service.Config;

import com.example.auth_service.utils.JwtCookieFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Autowired
    private JwtCookieFilter jwtCookieFilter;

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain SecurityFilterChain(HttpSecurity httpSecurity) throws Exception {
        httpSecurity
                .authorizeHttpRequests(x -> x
                        .requestMatchers("/login", "/css/**", "/js/**", "/").permitAll()
                        .anyRequest().authenticated())
                .csrf(csrf -> csrf.disable());
        httpSecurity.addFilterBefore(jwtCookieFilter, UsernamePasswordAuthenticationFilter.class);
        return httpSecurity.build();
    }

}
