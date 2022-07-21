package ru.kata.spring.boot_security.demo.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import ru.kata.spring.boot_security.demo.model.Role;
import ru.kata.spring.boot_security.demo.model.User;
import ru.kata.spring.boot_security.demo.service.AppService;

import java.security.Principal;
import java.util.List;

@Controller
@RequestMapping("/admin")
public class AdminController {
    private final AppService appService;
    @Autowired
    public AdminController(AppService userService) {
        this.appService = userService;
    }

    @GetMapping()
    public String findAll(Principal principal, Model model) {
        User newuser = new User();
        User loguser = appService.getUserByEmail(principal.getName());
        List<User> users = appService.getAllUsers();
        List<Role> roles = appService.listRoles();
        model.addAttribute("users", users);
        model.addAttribute("loguser", loguser);
        model.addAttribute("newuser", newuser);
        model.addAttribute("roles", roles);
        return "admin";
    }

    @GetMapping("/user-create")
    public String createUserForm(User user, Model model) {
        model.addAttribute(user);
        return "user-create";
    }

    @PostMapping("/user-create")
    public String createUser(@ModelAttribute("newuser") User user) {
        appService.saveUser(user);
        return "redirect:/admin";
    }

    @DeleteMapping("/user-delete/{id}")
    public String deleteUser(@PathVariable("id") Long id) {
        appService.removeUser(id);
        return "redirect:/admin";
    }

    @PutMapping("/user-update/{id}")
    public String update(@ModelAttribute("user") User user, @PathVariable("id") Long id) {
        appService.saveUser(user);
        return "redirect:/admin";
    }


}
