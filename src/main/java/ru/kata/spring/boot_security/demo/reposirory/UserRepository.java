package ru.kata.spring.boot_security.demo.reposirory;


import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import ru.kata.spring.boot_security.demo.model.User;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {
   User findByUsername(String username);
   User findByEmail(String email);
}
//Интерфейс JpaRepository предоставляет набор стандартных методов (findBy, save, deleteById и др.) для работы с БД.