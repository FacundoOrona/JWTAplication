package com.jwtapplication.jwt.auth.controller;

public record AuthRequest(
        String email,
        String password
) {
}
