package com.jwtapplication.jwt.auth.service;

import jakarta.validation.constraints.NotNull;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.jwtapplication.jwt.auth.controller.AuthRequest;
import com.jwtapplication.jwt.auth.controller.RegisterRequest;
import com.jwtapplication.jwt.auth.controller.TokenResponse;
import com.jwtapplication.jwt.auth.repository.Token;
import com.jwtapplication.jwt.auth.repository.TokenRepository;
import com.jwtapplication.jwt.user.User;
import com.jwtapplication.jwt.user.UserRepository;

import java.util.List;

@Service
@RequiredArgsConstructor // Genera constructor con todos los campos final (inyección automática)
public class AuthService {

    private final UserRepository repository; // Para acceder/guardar usuarios
    private final TokenRepository tokenRepository; // Para guardar/revocar tokens
    private final PasswordEncoder passwordEncoder; // Para encriptar contraseñas
    private final JwtService jwtService; // Para generar y validar JWT
    private final AuthenticationManager authenticationManager; // Para autenticar credenciales (email/pass)

    // Método para registrar un nuevo usuario
    public TokenResponse register(final RegisterRequest request) {
        // Se crea un nuevo usuario con los datos del request y se encripta la contraseña
        final User user = User.builder()
                .name(request.name())
                .email(request.email())
                .password(passwordEncoder.encode(request.password()))
                .build();

        // Se guarda el usuario en la base de datos
        final User savedUser = repository.save(user);

        // Se generan el token de acceso y el refresh token
        final String jwtToken = jwtService.generateToken(savedUser);
        final String refreshToken = jwtService.generateRefreshToken(savedUser);

        // Se guarda el token de acceso en la base de datos
        saveUserToken(savedUser, jwtToken);

        // Se devuelve la respuesta con ambos tokens
        return new TokenResponse(jwtToken, refreshToken);
    }

    // Método para autenticar un usuario existente
    public TokenResponse authenticate(final AuthRequest request) {
        // Autentica el email y la contraseña
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.email(),
                        request.password()
                )
        );

        // Busca el usuario por email (ya autenticado)
        final User user = repository.findByEmail(request.email())
                .orElseThrow();

        // Genera nuevos tokens
        final String accessToken = jwtService.generateToken(user);
        final String refreshToken = jwtService.generateRefreshToken(user);

        // Revoca todos los tokens previos válidos del usuario
        revokeAllUserTokens(user);

        // Guarda el nuevo token de acceso
        saveUserToken(user, accessToken);

        // Devuelve ambos tokens
        return new TokenResponse(accessToken, refreshToken);
    }

    // Método privado que guarda un nuevo token activo para un usuario
    private void saveUserToken(User user, String jwtToken) {
        final Token token = Token.builder()
                .user(user)
                .token(jwtToken)
                .tokenType(Token.TokenType.BEARER)
                .isExpired(false)
                .isRevoked(false)
                .build();
        tokenRepository.save(token);
    }

    // Método privado para revocar todos los tokens anteriores válidos de un usuario
    private void revokeAllUserTokens(final User user) {
        final List<Token> validUserTokens = tokenRepository.findAllValidTokenByUser(user.getId());
        if (!validUserTokens.isEmpty()) {
            // Marca cada token como expirado y revocado
            validUserTokens.forEach(token -> {
                token.setIsExpired(true);
                token.setIsRevoked(true);
            });
            tokenRepository.saveAll(validUserTokens); // Guarda los cambios
        }
    }

    // Método para refrescar el access token usando un refresh token válido
    public TokenResponse refreshToken(@NotNull final String authentication) {

        // Verifica que el header tenga formato válido: "Bearer <token>"
        if (authentication == null || !authentication.startsWith("Bearer ")) {
            throw new IllegalArgumentException("Invalid auth header");
        }

        // Extrae el token desde el header (sin "Bearer ")
        final String refreshToken = authentication.substring(7);

        // Extrae el email (username) desde el token
        final String userEmail = jwtService.extractUsername(refreshToken);
        if (userEmail == null) {
            return null;
        }

        // Busca el usuario en base al email
        final User user = this.repository.findByEmail(userEmail).orElseThrow();

        // Verifica que el token sea válido
        final boolean isTokenValid = jwtService.isTokenValid(refreshToken, user);
        if (!isTokenValid) {
            return null;
        }

        // Genera un nuevo token de acceso
        final String accessToken = jwtService.generateRefreshToken(user);

        // Revoca los tokens anteriores y guarda el nuevo
        revokeAllUserTokens(user);
        saveUserToken(user, accessToken);

        // Devuelve ambos tokens: el viejo refresh token y el nuevo access token
        return new TokenResponse(accessToken, refreshToken);
    }
}
