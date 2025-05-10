package com.jwt.app.service;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.jwt.app.controller.LoginRequest;
import com.jwt.app.controller.RegisterRequest;
import com.jwt.app.controller.TokenResponse;
import com.jwt.app.repository.TokenRepository;
import com.jwt.app.usuario.User;
import com.jwt.app.usuario.UserRepository;
import com.jwt.app.repository.Token;
import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class AuthService {
    private final UserRepository userRepository;
    private final TokenRepository tokenRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;

    public TokenResponse register(RegisterRequest request){
        var user = User.builder()
            .name(request.name())
            .email(request.email())
            .password(passwordEncoder.encode(request.password()))
            .build();
        var savedUser = userRepository.save(user);
        var jwtToken = jwtService.generatedToken(savedUser);
        var refreshToken = jwtService.generatedRefreshToken(savedUser);
        saveUserToken(savedUser, jwtToken);
        return new TokenResponse(jwtToken, refreshToken);
    }

    public TokenResponse login(LoginRequest request){
        return null;
    }

    private void saveUserToken(User user, String jwtToken){
        var token = Token.builder()
                    .user(user)
                    .token(jwtToken)
                    .tokenType(Token.TokenType.BEARER)
                    .expired(false)
                    .revoked(false)
                    .build();
        tokenRepository.save(token);
    }

    public void refreshToken(){
        
    }
}
