package ru.netology.demo.service;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import ru.netology.demo.model.UserDB;
import ru.netology.demo.repository.UserRepository;
import org.springframework.security.core.userdetails.User;

import java.util.ArrayList;

@Service
public class UserService {

    private final UserRepository userRepository;

    public UserService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    public UserDetails getUserByLogin(String login) {
        UserDB userDB = userRepository.findByLoginReturnUserDB(login);
        return new User(userDB.getLogin(), userDB.getPassword(), new ArrayList<>());
    }

    public UserDB getUserByLoginReturnUser(String login) {
        return userRepository.findByLoginReturnUserDB(login);
    }

    public void addTokenToUser(String login, String token) {
        userRepository.addTokenToUser(login, token);
    }

    public void deleteTokenByUsername(String username) {
        userRepository.deleteTokenByUsername(username);
    }
}
