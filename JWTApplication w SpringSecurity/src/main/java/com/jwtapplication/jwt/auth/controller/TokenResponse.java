package com.jwtapplication.jwt.auth.controller;

import com.fasterxml.jackson.annotation.JsonProperty;

/*sirve como DTO de salida para responder al cliente 
con los tokens generados durante el login o el registro. */
public record TokenResponse(
        @JsonProperty("access_token")
        String accessToken,
        @JsonProperty("refresh_token")
        String refreshToken
) {
}

/*Define un objeto inmutable con dos campos:

accessToken: el JWT que se utiliza para autenticar peticiones al backend.

refreshToken: un token de renovación que permite obtener un nuevo accessToken cuando este expira, sin tener que volver a hacer login. */

/*@JsonProperty("access_token")
@JsonProperty("refresh_token")
Estas anotaciones son de Jackson, y sirven para:

Cambiar el nombre de los campos al serializar/deserializar JSON.

En este caso, se transforma:

accessToken → "access_token"

refreshToken → "refresh_token"

Esto es útil porque:

En APIs REST modernas (por ejemplo, siguiendo estándares como OAuth2), se acostumbra usar snake_case en los nombres de campos JSON.

En cambio, en Java usamos camelCase.

Sin @JsonProperty, la respuesta JSON tendría los nombres accessToken y refreshToken, lo que no siempre es deseado en el contrato con el frontend. */
