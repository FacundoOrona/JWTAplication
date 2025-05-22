package com.jwtapplication.jwt.auth.controller;

import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import com.jwtapplication.jwt.auth.service.AuthService;

@RestController //combinación de @Controller + @ResponseBody. Indica que esta clase expone endpoints REST y que las respuestas se serializan automáticamente a JSON.
@RequestMapping("/auth") //todos los endpoints definidos tendrán la ruta base /auth.
@RequiredArgsConstructor //de Lombok. Genera un constructor con todos los campos final, lo cual inyecta automáticamente el servicio AuthService.
public class AuthController {

    private final AuthService service; //El controlador delega la lógica a AuthService. Esto mantiene el código desacoplado y limpio.

    @PostMapping("/register")
    public ResponseEntity<TokenResponse> register(@RequestBody RegisterRequest request) { //Espera un RegisterRequest (nombre, email, password).
        final TokenResponse response = service.register(request); //Llama a service.register(...) que:
        return ResponseEntity.ok(response); //Devuelve una respuesta HTTP 200 con el token (envuelto en un TokenResponse). 
    }

    @PostMapping("/login")
    public ResponseEntity<TokenResponse> authenticate(@RequestBody AuthRequest request) { //Espera un AuthRequest (email y password).
        final TokenResponse response = service.authenticate(request); //El servicio valida las credenciales 
        return ResponseEntity.ok(response); // y devuelve un TokenResponse con un JWT si todo está bien.
    }

    @PostMapping("/refresh-token")
    public TokenResponse refreshToken(
            @RequestHeader(HttpHeaders.AUTHORIZATION) final String authentication //Recibe un token de acceso caducado o cerca de expirar en el encabezado Authorization.
    ) {
        return service.refreshToken(authentication); //Llama a service.refreshToken(...) para emitir uno nuevo y retorna un nuevo TokenResponse con un token JWT actualizado.
    }


}
