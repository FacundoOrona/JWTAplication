package com.jwt.app.controller;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data // Genera getters, setters, toString, equals y hashCode
@AllArgsConstructor // Genera constructor con todos los campos
@NoArgsConstructor  // Genera constructor vacío
public class TokenResponse {
    private String jwtToken;
    private String refreshToken;
}

