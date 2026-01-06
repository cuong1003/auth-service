package com.example.auth_service.Models.Dto;

import lombok.Data;

@Data
public class LoginRequest {
    private String username;
    private String password;
}
