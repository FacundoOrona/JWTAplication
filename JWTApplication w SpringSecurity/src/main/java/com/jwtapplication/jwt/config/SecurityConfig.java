package com.jwtapplication.jwt.config;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.jwtapplication.jwt.auth.repository.Token;
import com.jwtapplication.jwt.auth.repository.TokenRepository;

import static org.springframework.security.config.http.SessionCreationPolicy.STATELESS;

@Configuration // Marca esta clase como clase de configuración de Spring
@EnableWebSecurity // Habilita la seguridad web en la app
@RequiredArgsConstructor // Crea un constructor con los campos marcados como final
@EnableMethodSecurity // Habilita anotaciones como @PreAuthorize
public class SecurityConfig {

    private final JwtAuthenticationFilter jwtAuthFilter; // Filtro personalizado para JWT
    private final AuthenticationProvider authenticationProvider; // Provider para autenticación
    private final TokenRepository tokenRepository; // Repositorio para acceder a los tokens

    @Bean
    public SecurityFilterChain securityFilterChain(final HttpSecurity http) throws Exception {
        http
                // Desactiva CSRF (no se necesita en APIs REST stateless)
                .csrf(AbstractHttpConfigurer::disable)

                // Define las reglas de autorización para los endpoints
                .authorizeHttpRequests(req ->
                        req.requestMatchers("/auth/**") // Rutas públicas (login, register, refresh)
                                .permitAll()
                                .anyRequest() // Cualquier otra ruta
                                .authenticated() // Requiere autenticación
                )

                // Define que no se usará sesión (stateless)
                .sessionManagement(session -> session.sessionCreationPolicy(STATELESS))

                // Configura el proveedor de autenticación
                .authenticationProvider(authenticationProvider)

                // Agrega el filtro de JWT antes del filtro de autenticación por usuario/contraseña
                .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class)

                // Configura el logout
                .logout(logout ->
                        logout.logoutUrl("/auth/logout") // URL para hacer logout
                                .addLogoutHandler(this::logout) // Lógica personalizada para invalidar el token
                                .logoutSuccessHandler((request, response, authentication) -> 
                                        SecurityContextHolder.clearContext()) // Limpia el contexto de seguridad
                );

        // Devuelve la configuración construida
        return http.build();
    }

    // Método que se ejecuta al hacer logout
    private void logout(
            final HttpServletRequest request, final HttpServletResponse response,
            final Authentication authentication
    ) {
        // Obtiene el header de autorización
        final String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return; // Si no hay token válido, no hace nada
        }

        // Extrae el token JWT del header
        final String jwt = authHeader.substring(7);

        // Busca el token en la base de datos
        final Token storedToken = tokenRepository.findByToken(jwt).orElse(null);

        if (storedToken != null) {
            // Marca el token como expirado y revocado
            storedToken.setIsExpired(true);
            storedToken.setIsRevoked(true);
            tokenRepository.save(storedToken);

            // Limpia el contexto de seguridad
            SecurityContextHolder.clearContext();
        }
    }
}
