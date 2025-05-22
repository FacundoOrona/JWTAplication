package com.jwtapplication.jwt.auth.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.List;
import java.util.Optional;

/*JpaRepository<Token, Integer>: es una interfaz de Spring Data JPA que provee
 métodos CRUD automáticos para la entidad Token, usando como clave primaria un Integer. */

public interface TokenRepository extends JpaRepository<Token, Integer> {

  //Consulta personalizada
  /*Busca todos los tokens válidos (no expirados o no revocados) de un usuario específico. */
  @Query(value = """
      select t from Token t inner join User u\s
      on t.user.id = u.id\s
      where u.id = :id and (t.expired = false or t.revoked = false)\s
      """)
  List<Token> findAllValidTokenByUser(Integer id); 

  Optional<Token> findByToken(String token); //Sirve para buscar rápidamente un token JWT específico, por ejemplo, cuando se recibe en una request y se quiere validar.
}
