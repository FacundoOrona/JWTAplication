package com.jwt.app.controller;

public record LoginRequest(
    String email,
    String password
) {
    
}
