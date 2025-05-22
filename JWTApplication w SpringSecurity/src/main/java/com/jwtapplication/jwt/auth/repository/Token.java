package com.jwtapplication.jwt.auth.repository;

import com.jwtapplication.jwt.user.User;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data //Genera automáticamente getters, setters, toString(), equals() y hashCode().
@Builder //Permite usar el patrón builder para crear instancias de Token.
@NoArgsConstructor
@AllArgsConstructor //Generan constructores sin argumentos y con todos los argumentos.
@Entity // Es una entidad de JPA, es decir, está mapeada a una tabla de base de datos.
public final class Token { //Declarada final para que no se herede.

    @Id
    @GeneratedValue //clave primaria generada automáticamente.
    private Integer id; 

    @Column(unique = true) //clave primaria generada automáticamente.
    private String token; 

    @Enumerated(EnumType.STRING) //Enumera el tipo de token (por ahora solo BEARER, típico en JWTs).
    @Builder.Default //Se le da un valor por defecto en el @Builder
    private TokenType tokenType = TokenType.BEARER; //Se guarda como string en la BD (EnumType.STRING).

    @Column(nullable = false)
    private Boolean isRevoked; // indica si el token fue revocado.

    @Column(nullable = false)
    private Boolean isExpired; //indica si el token ya expiró.

    @ManyToOne(fetch = FetchType.LAZY) //Cada token pertenece a un usuario. LAZY: se carga el usuario solo cuando se necesita (por eficiencia).
    @JoinColumn(name = "user_id") //define la columna que actúa como clave foránea en la tabla de tokens.
    private User user;

    public enum TokenType {
        BEARER //Enum sencillo para representar el tipo de token. Se puede extender si en el futuro se usan otros tipos (por ejemplo, REFRESH).
    }

}
