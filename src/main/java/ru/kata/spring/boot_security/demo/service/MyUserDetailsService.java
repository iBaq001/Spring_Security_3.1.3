package ru.kata.spring.boot_security.demo.service;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import ru.kata.spring.boot_security.demo.model.User;

@Service
@Transactional
public class MyUserDetailsService implements UserDetailsService {

    private final AppService appService;

    public MyUserDetailsService(AppService appService) {
        this.appService = appService;
    }

    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        User user = appService.getUserByEmail(email);
        if (user == null) {
            throw new UsernameNotFoundException(String.format("User with email '%s' not found!", email));
        }
        return new org.springframework.security.core.userdetails.User(
                user.getEmail(), user.getPassword(), user.getAuthorities());
    }
}