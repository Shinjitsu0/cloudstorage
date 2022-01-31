package ru.netology.demo.controller;


import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;
import ru.netology.demo.service.UserService;

import javax.servlet.http.HttpServletRequest;

@RestController
public class LogoutController {

    private final UserService userService;

    private static final Logger log = LoggerFactory.getLogger(LogoutController.class);

    public LogoutController(UserService userService) {
        this.userService = userService;
    }

    @GetMapping(value = "/login")
    public ResponseEntity<?> logout(@RequestHeader("User-Agent") String useragent, HttpServletRequest request) {
        var login = SecurityContextHolder.getContext().getAuthentication().getName();
        var ip = request.getRemoteAddr();
        var hostname = request.getRemoteHost();
        log.info("Exit attempt. ip:" + ip + " hostname:" + hostname + " User-Agent:" + useragent);
        var userDetails = userService.getUserByLogin(login);
        if (userDetails != null) {
            userService.deleteTokenByUsername(login);
            log.info("Successful logout. User " + login + " has logged out");
            return ResponseEntity.status(HttpStatus.OK).body("user quit");
        }

        log.info("Failed exit attempt. ip:" + ip + " hostname:" + hostname + " User-Agent:" + useragent);
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("cant find such token");

    }
}
