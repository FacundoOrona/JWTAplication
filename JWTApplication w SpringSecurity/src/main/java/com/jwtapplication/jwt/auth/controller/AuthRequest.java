package com.jwtapplication.jwt.auth.controller;

public record AuthRequest(
        String email,
        String password
) {
}

/*📘 ¿Qué es un record?
Un record en Java es una clase inmutable y transparente que:

Tiene todos los campos private final.

Genera automáticamente:

Un constructor con todos los campos.

Métodos getters (sin el prefijo get, es decir: email(), password()).

Métodos equals(), hashCode(), y toString(). */

/*¿Por qué usar record?
Es perfecto para clases DTO (Data Transfer Object) como AuthRequest, que simplemente trasladan datos entre capas (por ejemplo, desde el frontend hasta el backend).

Hace el código más limpio, corto y fácil de mantener.

Fomenta la inmutabilidad (algo positivo en muchos contextos como seguridad o concurrencia). */

/* Limitaciones
No se pueden extender otras clases (los record son final por defecto).

Todos los campos son final e inmutables.

No podés declarar constructores sin parámetros (si querés sobrecargar, tenés que usar un constructor compacto). */