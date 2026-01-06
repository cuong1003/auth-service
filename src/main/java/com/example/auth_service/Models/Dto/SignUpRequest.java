package com.example.auth_service.Models.Dto;

import lombok.Data;

@Data
public class SignUpRequest {
    private String username;
    private String password;
    private String repeatPassword;
    private String role;
}