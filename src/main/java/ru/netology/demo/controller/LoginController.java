package ru.netology.demo.controller;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;
import ru.netology.demo.security.JwtTokenUtil;
import ru.netology.demo.model.UserDB;
import ru.netology.demo.service.UserService;
import javax.servlet.http.HttpServletRequest;
import java.util.HashMap;


@RestController
public class LoginController {

    private final JwtTokenUtil jwtTokenUtil;

    private final UserService userService;

    private static final Logger log = LoggerFactory.getLogger(LoginController.class);

    public LoginController(JwtTokenUtil jwtTokenUtil, UserService userService) {
        this.jwtTokenUtil = jwtTokenUtil;
        this.userService = userService;
    }

    @PostMapping(value = "/login")
    public ResponseEntity<?> createAuthenticationToken(@RequestBody UserDB userDB,
                                                       @RequestHeader("User-Agent") String useragent, HttpServletRequest request) {
        var ip = request.getRemoteAddr();
        var hostname = request.getRemoteHost();
        log.info("Login attempt. ip:" + ip + " hostname:" + hostname + " User-Agent:" + useragent);
        final UserDetails userDetails = userService.getUserByLogin(userDB.getLogin());
        if (userDetails != null) {
            var name = userDetails.getUsername();
            var pass = userDetails.getPassword();
            if (name.equals(userDB.getLogin()) && pass.equals(userDB.getPassword())) {
                final String token = jwtTokenUtil.generateToken(userDetails);
                userService.addTokenToUser(userDB.getLogin(), token);
                log.info("Successful login. Access granted for user: " + userDB.getLogin() + ". token: " + token);
                HashMap<String, String> map = new HashMap<>();
                map.put("auth-token", token);
                return ResponseEntity.status(200).body(map);
            }

        }
        log.info("Failure login attempt. Access denied for: ip:" + ip + " hostname:" + hostname + " User-Agent:" + useragent);
        return ResponseEntity.status(HttpStatus.FORBIDDEN).body("such user not found");

    }

}
