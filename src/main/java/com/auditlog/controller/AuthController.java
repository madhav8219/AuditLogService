package com.auditlog.controller;

import com.auditlog.dto.TokenRequest;
import com.auditlog.entity.User;
import com.auditlog.security.JwtTokenProvider;
import com.auditlog.service.UserService;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequestMapping("/auth")
public class AuthController {

    private final UserService userService;
    private final JwtTokenProvider jwtTokenProvider;

    public AuthController(UserService userService, JwtTokenProvider jwtTokenProvider) {
        this.userService = userService;
        this.jwtTokenProvider = jwtTokenProvider;
    }

    @PostMapping("/token")
    public ResponseEntity<?> generateToken(@Valid @RequestBody TokenRequest request) {
        User user = userService.findByUsername(request.getUsername())
                .orElse(null);

        if (user == null || !userService.validateCredentials(request.getUsername(), request.getPassword())) {
            return ResponseEntity.status(401).body("Invalid username or password");
        }

        List<String> roles = user.getRoles().stream()
                .map(role -> role.getName())
                .toList();

        String token = jwtTokenProvider.generateToken(user.getUsername(), roles);
        return ResponseEntity.ok(new TokenResponse(token));
    }

    public record TokenResponse(String token) {
    }
}
