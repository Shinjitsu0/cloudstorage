package ru.netology.demo;

import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;
import ru.netology.demo.model.User;
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
        User u1 = User.builder().login("admin").password("admin").username("admin").build();
        User u2 = User.builder().login("user").password("user").username("user").build();
        userRepository.save(u1);
        userRepository.save(u2);
    }

}
