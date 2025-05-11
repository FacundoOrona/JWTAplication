package com.jwt.app.service;

import java.util.Date;

import javax.crypto.SecretKey;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import com.jwt.app.usuario.User;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;

@Service
public class JwtService {

    @Value("${application.security.jwt.secret-key}")
    private String secretKey;
    @Value("${application.security.jwt.expiration}")
    private long jwtExpiration;
    @Value("${application.security.jwt.refresh-token.expiration}")
    private long refreshExpiration;

    public String generatedToken(final User user) {
        return buildToken(user, jwtExpiration);
    }

    public String generatedRefreshToken(final User user) {
        return buildToken(user, refreshExpiration);
    }

    private String buildToken(final User user, final long expiration) {
        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + expiration);

    return Jwts.builder()
        .setId(user.getId().toString())                    // jti
        .claim("name", user.getName())                // claim personalizado
        .setSubject(user.getEmail())                       // sub
        .setIssuedAt(now)                                  // iat
        .setExpiration(expiryDate)                         // exp
        .signWith(getSignInKey(), SignatureAlgorithm.HS256)
        .compact();
    }

    private SecretKey getSignInKey() {
        byte[] keyBytes = Decoders.BASE64.decode(secretKey);
        return Keys.hmacShaKeyFor(keyBytes);
    }
}
