package ru.netology.demo.controller;


import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import ru.netology.demo.configJwt.JwtTokenUtil;
import ru.netology.demo.service.UserService;

import javax.servlet.http.HttpServletRequest;

@RestController
public class LogoutController {

    final UserService userService;
    final JwtTokenUtil jwtTokenUtil;
    private static final Logger log = LoggerFactory.getLogger(LogoutController.class);

    public LogoutController(UserService userService, JwtTokenUtil jwtTokenUtil) {
        this.userService = userService;
        this.jwtTokenUtil = jwtTokenUtil;
    }

    @GetMapping(value = "/login")
    public ResponseEntity<?> logout(HttpServletRequest request) {
        var ip = request.getRemoteAddr();
        var hostname = request.getRemoteHost();
        var useragent = request.getHeader("User-Agent");
        log.info("Exit attempt. ip:" + ip + " hostname:" + hostname + " User-Agent:" + useragent);

        String tokenRaw = request.getHeader("auth-token");
        String usernameFromToken;
        try {
            usernameFromToken = jwtTokenUtil.getUserNameFromTokenRaw(tokenRaw);
        } catch (NullPointerException npe) {
            log.info("Failure exit attempt. Wrong token. ip:" + ip + " hostname:" + hostname + " User-Agent:" + useragent);
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("unreadable token");
        }

        var userDetails = userService.getUserByLogin(usernameFromToken);
        if (userDetails != null) {
            userService.deleteTokenByUsername(usernameFromToken);
            log.info("Successful logout. User " + usernameFromToken + " has logged out");
            return ResponseEntity.status(HttpStatus.OK).body("user quit");
        }

        log.info("Failed exit attempt. ip:" + ip + " hostname:" + hostname + " User-Agent:" + useragent);
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("cant find such token");

    }
}
