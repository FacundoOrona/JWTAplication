package com.jwtapplication.jwt.config;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import com.jwtapplication.jwt.user.User;
import com.jwtapplication.jwt.user.UserRepository;

@Configuration // Marca esta clase como una clase de configuración de Spring
@RequiredArgsConstructor // Genera automáticamente el constructor para inyectar el UserRepository
public class AppConfig {

    private final UserRepository repository; // Repositorio para buscar usuarios por email

    @Bean
    public UserDetailsService userDetailsService() {
        // Retorna una implementación de UserDetailsService usando una expresión lambda
        return username -> {
            final User user = repository.findByEmail(username) // Busca el usuario por email
                    .orElseThrow(() -> new UsernameNotFoundException("User not found")); // Lanza excepción si no lo encuentra

            // Devuelve un objeto UserDetails básico (username y password, sin roles configurados)
            return org.springframework.security.core.userdetails.User
                    .builder()
                    .username(user.getEmail())
                    .password(user.getPassword())
                    .build();
        };
    }

    @Bean
    public AuthenticationProvider authenticationProvider() {
        // Crea un proveedor de autenticación basado en DAO (usuario/contraseña)
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();

        // Configura el servicio que se usa para cargar usuarios desde la base de datos
        authProvider.setUserDetailsService(userDetailsService());

        // Configura el codificador de contraseñas
        authProvider.setPasswordEncoder(passwordEncoder());

        return authProvider;
    }

    @Bean
    public AuthenticationManager authenticationManager(final AuthenticationConfiguration config) throws Exception {
        // Obtiene el AuthenticationManager desde la configuración global de Spring Security
        return config.getAuthenticationManager();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        // Define BCrypt como algoritmo para codificar y verificar contraseñas
        return new BCryptPasswordEncoder();
    }
}
