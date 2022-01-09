package ru.netology.demo.controller;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.testcontainers.containers.GenericContainer;

import java.util.HashMap;
import java.util.Objects;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
public class LoginControllerTest {
    @Autowired
    TestRestTemplate restTemplate;
    public static GenericContainer<?> app = new GenericContainer("app").withExposedPorts(8085);

    @BeforeAll
    public static void setUp() {
        app.start();
    }

    @ParameterizedTest
    @ValueSource(strings = {"qwerty", "asdfg", "zxcvb", "andreq", "ivon"})
    void testLoggingWithWrongUsername_POST(String args) {
        HashMap<String, Object> map = new HashMap<>();
        map.put("login", args);
        map.put("password", "111111");

        ResponseEntity<String> response = restTemplate.postForEntity("/login", map, String.class);
        Assertions.assertEquals(response.getStatusCodeValue(), HttpStatus.FORBIDDEN.value());
    }





    @ParameterizedTest
    @ValueSource(strings = {"qwerty", "asdfg", "zxcvb", "andreq", "ivon"})
    void testLoggingWithNullKey1_POST(String args) {
        HashMap<Object, Object> map = new HashMap<>();
        map.put(null, args);
        map.put(null, "12345");

        try {
            ResponseEntity<String> response = restTemplate.postForEntity("/login", map, String.class);
        } catch (Exception ex) {
            Assertions.assertTrue(ex.getMessage().contains("Could not write JSON"));
        }
    }


    @ParameterizedTest
    @ValueSource(strings = {"11223344", "123", "1234", "/*-+--/*-00-", "--**/1*4-255*/", "", "  ", ""})
    void testLoggingWithWrongPassword_POST(String args) {
        HashMap<String, Object> map = new HashMap<>();
        map.put("login", "admin");
        map.put("password", args);

        ResponseEntity<String> response = restTemplate.postForEntity("/login", map, String.class);
        Assertions.assertEquals(HttpStatus.FORBIDDEN.value(), response.getStatusCodeValue());
    }

    @Test
    void successLogging_POST_expect200() {
        HashMap<String, String> map = new HashMap<>();
        map.put("login", "admin");
        map.put("password", "admin");

        ResponseEntity<String> response = restTemplate.postForEntity("/login", map, String.class);
        Assertions.assertEquals(response.getStatusCodeValue(), HttpStatus.OK.value());
    }

    @Test
    void successLogging_POST_expectNotEmptyToken() {
        HashMap<String, String> map = new HashMap<>();
        map.put("login", "admin");
        map.put("password", "admin");

        ResponseEntity<String> response = restTemplate.postForEntity("/login", map, String.class);
        Assertions.assertTrue(Objects.requireNonNull(response.getBody()).contains("auth-token"));
    }
}