package com.jwt.jwt.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.jwt.jwt.model.User;
import com.jwt.jwt.security.JwtUtil;
import com.jwt.jwt.service.UserService;

@RestController
@RequestMapping("/auth")
@CrossOrigin
public class AuthController {

    @Autowired
    private UserService service;

    @Autowired
    private JwtUtil jwtUtil;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @PostMapping("/register")
    public User register(@RequestBody User user) {
        return service.save(user);
    }
    @GetMapping("/test")
    public String test() {
    return "JWT funcionando 🔥";
    }

@PostMapping("/login")
public String login(@RequestBody User user) {

    return service.findByUsername(user.getUsername())
        .map(dbUser -> {

            if (!passwordEncoder.matches(user.getPassword(), dbUser.getPassword())) {
                throw new RuntimeException("Contraseña incorrecta");
            }

            return jwtUtil.generateToken(dbUser.getUsername());
        })
        .orElseThrow(() -> new RuntimeException("Usuario no encontrado"));
}
}