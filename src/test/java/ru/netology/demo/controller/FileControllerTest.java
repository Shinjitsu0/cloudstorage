package ru.netology.demo.controller;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.testcontainers.containers.GenericContainer;


@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
public class FileControllerTest {

    @Autowired
    TestRestTemplate template1;
    public static GenericContainer<?> app = new GenericContainer("app").withExposedPorts(8085);

    @BeforeAll
    public static void setUp() {
        app.start();
    }

    @Test
    void doEmptyGET_expect400() {
        ResponseEntity<String> response = template1.getForEntity("/list", String.class);
        var expected = HttpStatus.BAD_REQUEST.value();
        var actual = response.getStatusCodeValue();
        Assertions.assertEquals(expected, actual);
    }
}