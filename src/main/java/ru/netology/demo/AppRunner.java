package ru.netology.demo;

import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;
import ru.netology.demo.model.UserDB;
import ru.netology.demo.repository.UserRepository;

@Component
public class AppRunner implements CommandLineRunner {

    private final UserRepository userRepository;

    public AppRunner(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    @Transactional
    public void run(String... args) {
        UserDB u1 = UserDB.builder().login("admin").password("admin").username("admin").build();
        UserDB u2 = UserDB.builder().login("user").password("user").username("user").build();
        userRepository.save(u1);
        userRepository.save(u2);
    }

}
