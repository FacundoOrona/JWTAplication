package com.jwtapplication.jwt.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.jwtapplication.jwt.auth.repository.TokenRepository;
import com.jwtapplication.jwt.auth.service.JwtService;
import com.jwtapplication.jwt.user.User;
import com.jwtapplication.jwt.user.UserRepository;

import java.io.IOException;
import java.util.Optional;

@Component // Marca esta clase como un componente gestionado por Spring
@RequiredArgsConstructor // Crea constructor para todos los campos final
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtService jwtService; // Servicio para manejar JWT
    private final UserDetailsService userDetailsService; // Servicio para cargar detalles del usuario
    private final TokenRepository tokenRepository; // Repositorio para buscar tokens en DB
    private final UserRepository userRepository; // Repositorio para buscar usuarios

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain
    ) throws ServletException, IOException {

        // Si la ruta es la de autenticación (login, register, etc) no validar JWT, solo sigue el filtro
        if (request.getServletPath().contains("/api/v1/auth")) {
            filterChain.doFilter(request, response);
            return; // Termina aquí para esas rutas
        }

        // Obtiene el header Authorization
        final String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);

        // Si no hay header o no empieza con Bearer (no es un token JWT válido) sigue el filtro sin autenticar
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }

        // Extrae el token JWT (elimina "Bearer " del inicio)
        final String jwt = authHeader.substring(7);

        // Extrae el email del usuario a partir del token (payload)
        final String userEmail = jwtService.extractUsername(jwt);

        // Obtiene la autenticación actual del contexto de seguridad (puede ser null si no está autenticado)
        final Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        // Si no se pudo extraer el email o ya hay una autenticación establecida, no hace nada más
        if (userEmail == null || authentication != null) {
            filterChain.doFilter(request, response);
            return;
        }

        // Carga los detalles del usuario con base en el email extraído del token
        final UserDetails userDetails = this.userDetailsService.loadUserByUsername(userEmail);

        // Consulta en la base de datos si el token no está expirado y no está revocado
        final boolean isTokenExpiredOrRevoked = tokenRepository.findByToken(jwt)
                .map(token -> !token.getIsExpired() && !token.getIsRevoked())
                .orElse(false);

        // Si el token está activo (no expirado ni revocado)
        if (isTokenExpiredOrRevoked) {

            // Busca el usuario en la base de datos
            final Optional<User> user = userRepository.findByEmail(userEmail);

            if (user.isPresent()) {

                // Verifica que el token JWT sea válido para ese usuario (firma, expiración, etc)
                final boolean isTokenValid = jwtService.isTokenValid(jwt, user.get());

                if (isTokenValid) {
                    // Crea un objeto Authentication válido con los detalles del usuario y sus permisos
                    UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                            userDetails,
                            null, // No se usa password acá
                            userDetails.getAuthorities() // Roles o permisos del usuario
                    );

                    // Establece detalles adicionales del request en el token (IP, sesión, etc)
                    authToken.setDetails(
                            new WebAuthenticationDetailsSource().buildDetails(request)
                    );

                    // Guarda la autenticación en el contexto de seguridad, así Spring sabe que el usuario está autenticado
                    SecurityContextHolder.getContext().setAuthentication(authToken);
                }
            }
        }

        // Continua con el resto de filtros en la cadena
        filterChain.doFilter(request, response);
    }
}
