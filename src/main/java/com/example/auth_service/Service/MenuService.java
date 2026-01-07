package com.example.auth_service.Service;

import com.example.auth_service.Models.Dto.MenuItem;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

@Service
public class MenuService {
    public List<MenuItem> getMenuByRole(String role){
        List<MenuItem> menuItems = new ArrayList<>();
        menuItems.add(new MenuItem("Hồ sơ", "/profile"));
        if ("CUSTOMER".equals(role)) {
            menuItems.add(new MenuItem("Xem Phim", "/api/xemphim"));
        }
        if ("ADMIN".equals(role)) {
            menuItems.add(new MenuItem("Xem Phim", "/api/xemphim"));
            menuItems.add(new MenuItem("Cài đặt", "/api/setting"));
        }
        return menuItems;
    }
}
