package com.example.auth_service.Models.Dto;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class MenuItem {
    private String label;
    private String path;
}
