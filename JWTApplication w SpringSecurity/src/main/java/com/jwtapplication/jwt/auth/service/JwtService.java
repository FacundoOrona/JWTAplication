package com.jwtapplication.jwt.auth.service;

import io.jsonwebtoken.Jwts; // Clase principal para construir y leer JWTs
import io.jsonwebtoken.io.Decoders; // Para decodificar claves base64
import io.jsonwebtoken.security.Keys; // Para crear claves HMAC seguras
import org.springframework.beans.factory.annotation.Value; // Para leer valores del application.properties
import org.springframework.stereotype.Service;

import com.jwtapplication.jwt.user.User;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.Map;

@Service // Declara que esta clase es un servicio Spring
public class JwtService {

    // Clave secreta (codificada en base64) que se define en application.properties
    @Value("${application.security.jwt.secret-key}")
    private String secretKey;

    // Tiempo de expiración del access token (en milisegundos)
    @Value("${application.security.jwt.expiration}")
    private long jwtExpiration;

    // Tiempo de expiración del refresh token (en milisegundos)
    @Value("${application.security.jwt.refresh-token.expiration}")
    private long refreshExpiration;

    // Extrae el email (username) desde el JWT
    public String extractUsername(String token) {
        return Jwts.parser() // Crea el parser
                .verifyWith(getSignInKey()) // Verifica usando la clave secreta
                .build()
                .parseSignedClaims(token) // Parsea y valida el JWT
                .getPayload()
                .getSubject(); // El "subject" es el email del usuario en este caso
    }

    // Genera un access token normal para el usuario
    public String generateToken(final User user) {
        return buildToken(user, jwtExpiration);
    }

    // Genera un refresh token con mayor duración
    public String generateRefreshToken(final User user) {
        return buildToken(user, refreshExpiration);
    }

    // Construye un token JWT con claims, tiempo de expiración y firma
    private String buildToken(final User user, final long expiration) {
        return Jwts
                .builder()
                .claims(Map.of("name", user.getName())) // Agrega un claim personalizado (opcional)
                .subject(user.getEmail()) // Usa el email como subject
                .issuedAt(new Date(System.currentTimeMillis())) // Fecha de emisión
                .expiration(new Date(System.currentTimeMillis() + expiration)) // Fecha de expiración
                .signWith(getSignInKey()) // Firma el token con la clave secreta
                .compact(); // Genera el JWT como String
    }

    // Verifica que el token pertenezca al usuario y que no esté expirado
    public boolean isTokenValid(String token, User user) {
        final String username = extractUsername(token);
        return (username.equals(user.getEmail())) && !isTokenExpired(token);
    }

    // Verifica si el token ya expiró
    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    // Extrae la fecha de expiración del JWT
    private Date extractExpiration(String token) {
        return Jwts.parser()
                .verifyWith(getSignInKey())
                .build()
                .parseSignedClaims(token)
                .getPayload()
                .getExpiration();
    }

    // Devuelve la clave HMAC decodificada desde base64 para firmar y verificar los tokens
    private SecretKey getSignInKey() {
        final byte[] keyBytes = Decoders.BASE64.decode(secretKey); // Decodifica el string base64
        return Keys.hmacShaKeyFor(keyBytes); // Genera la clave HMAC
    }
}
