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

import java.util.List;

import org.springframework.security.authentication.AuthenticationManager;


@Service
@RequiredArgsConstructor
public class AuthService {
    private final UserRepository userRepository;
    private final TokenRepository tokenRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;

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
        authenticationManager.authenticate(
            new UsernamePasswordAuthenticationToken(
                request.email(),
                request.password()
            )
        );
        var user = userRepository.findByEmail(request.email())
                .orElseThrow();
        var jwtToken = jwtService.generatedToken(user);
        revokeAllUserTokens(user);   
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

    private void revokeAllUserTokens(final User user) {
        final List<Token> validUserTokens = tokenRepository
                .findAllByUserIdAndExpiredFalseAndRevokedFalse(user.getId());
        if (!validUserTokens.isEmpty()){
            for (final Token token : validUserTokens) {
                token.setExpired(true);
                token.setRevoked(true);
            }
            tokenRepository.saveAll(validUserTokens);
        }
    }

    public void refreshToken(){
        
    }
}
