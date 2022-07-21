package ru.kata.spring.boot_security.demo.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import ru.kata.spring.boot_security.demo.model.User;
import ru.kata.spring.boot_security.demo.service.AppService;

import java.security.Principal;


@Controller
@RequestMapping("/user")
public class UserController {
    private final AppService appService;

    @Autowired
    public UserController(AppService appService) {
        this.appService = appService;
    }

    @GetMapping
    public String userInfoPage(Principal principal, Model model) {
        User user = appService.getUserByEmail(principal.getName());
        model.addAttribute("user", user);
        return "user";
    }

}
