package ru.kata.spring.boot_security.demo;


import org.springframework.stereotype.Component;
import ru.kata.spring.boot_security.demo.model.Role;
import ru.kata.spring.boot_security.demo.model.User;
import ru.kata.spring.boot_security.demo.reposirory.RoleRepository;
import ru.kata.spring.boot_security.demo.reposirory.UserRepository;

import javax.annotation.PostConstruct;
import java.util.ArrayList;
import java.util.List;


@Component
public class Init {

    private final RoleRepository roleRepository;

    private final UserRepository userRepository;

    public Init(RoleRepository roleRepository, UserRepository userRepository) {
        this.roleRepository = roleRepository;
        this.userRepository = userRepository;
    }

    @PostConstruct
    public void init() {

        User user = new User("User", "Userov", 18,  "user@mail.ru", "$2a$12$I2Jaja1tiG0OLLA8G9SrOO225e93KICb9qknGyO8Lgs5/CIMbxWV6"); //1234
        User admin = new User("Admin", "Adminov", 25,  "admin@mail.ru", "$2a$12$T69GNWh63fXfM7RuAcBZm.ZrZo9HjEJkf0cwpg8LWAc8XEM16Lg2e"); //4321

        Role roleUser = new Role("ROLE_USER");
        Role roleAdmin = new Role("ROLE_ADMIN");

        roleRepository.save(roleUser);
        roleRepository.save(roleAdmin);

        List<Role> userRoles = new ArrayList<>();
        List<Role> adminRoles = new ArrayList<>();

        userRoles.add(roleUser);
        adminRoles.add(roleAdmin);
        adminRoles.add(roleUser);

        user.setRoles(userRoles);
        admin.setRoles(adminRoles);

        userRepository.save(user);
        userRepository.save(admin);

    }

}
