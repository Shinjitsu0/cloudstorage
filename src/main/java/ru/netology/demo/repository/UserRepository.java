package ru.netology.demo.repository;


import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;
import ru.netology.demo.model.User;

@Repository
@Transactional
public interface UserRepository extends JpaRepository<User, Long> {

    User save(User user);

    UserDetails findByLogin(String login);

    @Query("select u from User u where u.login = :login")
    User findByLoginReturnUser(String login);

    @Modifying
    @Query("update User u set u.token = :token where u.login = :login")
    void addTokenToUser(String login, String token);

    @Modifying
    @Query("update User u set u.token = null where u.login=:username")
    void deleteTokenByUsername(String username);
}
