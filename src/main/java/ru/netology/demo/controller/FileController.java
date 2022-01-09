package ru.netology.demo.controller;


import org.json.JSONException;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.io.InputStreamResource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import ru.netology.demo.configJwt.JwtTokenUtil;
import ru.netology.demo.model.IncomingFile;
import ru.netology.demo.service.FileService;
import ru.netology.demo.service.UserService;

import javax.servlet.http.HttpServletRequest;
import java.io.ByteArrayInputStream;
import java.io.IOException;

@RestController
public class FileController {

    final FileService fileService;

    final UserService userService;

    final JwtTokenUtil jwtTokenUtil;

    private static final Logger log = LoggerFactory.getLogger(FileController.class);

    public FileController(FileService fileService, UserService userService, JwtTokenUtil jwtTokenUtil) {
        this.fileService = fileService;
        this.userService = userService;
        this.jwtTokenUtil = jwtTokenUtil;
    }

    @GetMapping(value = "/list")
    public Object showSavedFiles(HttpServletRequest request) {
        var ip = request.getRemoteAddr();
        var hostname = request.getRemoteHost();
        var useragent = request.getHeader("User-Agent");
        log.info("Viewing files attempt. ip:" + ip + " hostname:" + hostname + " User-Agent:" + useragent);

        var tokenRaw = request.getHeader("auth-token");
        String usernameFromToken;
        try {
            usernameFromToken = jwtTokenUtil.getUserNameFromTokenRaw(tokenRaw);
        } catch (NullPointerException npe) {
            log.info("Failure viewing attempt. Wrong token. ip:" + ip + " hostname:" + hostname + " User-Agent:" + useragent);
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("unreadable token");
        }

        var userDetails = userService.getUserByLogin(usernameFromToken);
        if (userDetails != null) {
            log.info("Successful viewing attempt. Access granted for user: " + userDetails.getUsername());
            return fileService.show(usernameFromToken);
        }
        log.info("Failure viewing attempt. Wrong token. ip:" + ip + " hostname:" + hostname + " User-Agent:" + useragent);
        return ResponseEntity.status(HttpStatus.FORBIDDEN).body("unauthorized attempt to access files");

    }

    @PostMapping(value = "/file")
    public ResponseEntity<?> saveFile(@RequestParam("filename") String filename, MultipartFile file, HttpServletRequest request) throws IOException {
        var ip = request.getRemoteAddr();
        var hostname = request.getRemoteHost();
        var useragent = request.getHeader("User-Agent");
        log.info("Upload attempt. ip" + ip + " hostname:" + hostname + " User-Agent:" + useragent);

        var tokenRaw = request.getHeader("auth-token");
        String usernameFromToken;
        try {
            usernameFromToken = jwtTokenUtil.getUserNameFromTokenRaw(tokenRaw);
        } catch (NullPointerException npe) {
            log.info("Failed upload attempt. ip:" + ip + " hostname:" + hostname + " User-Agent:" + useragent);
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("cant find such token");
        }
        var userDetails = userService.getUserByLogin(usernameFromToken);
        if (userDetails != null) {
            fileService.upload(file, request);
            log.info("Success upload attempt. User " + usernameFromToken + " uploaded file " + file.getOriginalFilename());
            return ResponseEntity.status(200).build();
        }
        log.info("Failed upload attempt. ip:" + ip + " hostname:" + hostname + " User-Agent:" + useragent);
        return ResponseEntity.status(HttpStatus.FORBIDDEN).body("cant find such token");
    }

    @GetMapping(value = "/file")
    public ResponseEntity<Object> downloadFile(@RequestParam("filename") String filename, HttpServletRequest request) {
        var ip = request.getRemoteAddr();
        var hostname = request.getRemoteHost();
        var useragent = request.getHeader("User-Agent");
        log.info("Download attempt. ip" + ip + " hostname:" + hostname + " User-Agent:" + useragent);

        var tokenRaw = request.getHeader("auth-token");
        String usernameFromToken;
        try {
            usernameFromToken = jwtTokenUtil.getUserNameFromTokenRaw(tokenRaw);
        } catch (NullPointerException npe) {
            log.info("Failure downloading attempt. Wrong token. ip:" + ip + " hostname:" + hostname + " User-Agent:" + useragent);
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("unreadable token");
        }

        var userDetails = userService.getUserByLogin(usernameFromToken);
        if (userDetails != null) {
            IncomingFile file = fileService.download(filename);
            InputStreamResource resource = new InputStreamResource(new ByteArrayInputStream(file.getFileContent()));
            HttpHeaders headers = new HttpHeaders();

            headers.add("Content-Disposition", String.format("attachment; filename=\"%s\"", file.getFilename()));
            headers.add("Cache-Control", "no-cache, no-store, must-revalidate");
            headers.add("Pragma", "no-cache");
            headers.add("Expires", "0");

            return ResponseEntity.ok().headers(headers).contentLength(
                    file.getFileContent().length).contentType(MediaType.parseMediaType(file.getFileType())).body(resource);
        }

        log.info("Failed download attempt. ip:" + ip + " hostname:" + hostname + " User-Agent:" + useragent);
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("cant find such token");
    }

    @DeleteMapping(value = "/file")
    public ResponseEntity<?> deleteFile(@RequestParam("filename") String filename, HttpServletRequest request) {
        var ip = request.getRemoteAddr();
        var hostname = request.getRemoteHost();
        var useragent = request.getHeader("User-Agent");
        log.info("Delete attempt. ip" + ip + " hostname:" + hostname + " User-Agent:" + useragent);

        var tokenRaw = request.getHeader("auth-token");
        String usernameFromToken;
        try {
            usernameFromToken = jwtTokenUtil.getUserNameFromTokenRaw(tokenRaw);
        } catch (NullPointerException npe) {
            log.info("Failed delete attempt. ip:" + ip + " hostname:" + hostname + " User-Agent:" + useragent);
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("cant find such token");
        }

        var userDetails = userService.getUserByLogin(usernameFromToken);
        if (userDetails != null) {
            fileService.delete(filename, userDetails.getUsername());
            log.info("User " + usernameFromToken + " successfully deleted file " + filename);
            return ResponseEntity.ok("successfully deleted");
        }
        log.info("Failed delete attempt. Wrong token. ip:" + ip + " hostname:" + hostname + " User-Agent:" + useragent);
        return ResponseEntity.status(HttpStatus.FORBIDDEN).body("unauthorized attempt delete files");
    }

    @PutMapping(value = "/file")
    public ResponseEntity<?> renameFile(@RequestParam("filename") String filename, @RequestBody String json, HttpServletRequest request) throws JSONException {
        var ip = request.getRemoteAddr();
        var hostname = request.getRemoteHost();
        var useragent = request.getHeader("User-Agent");
        log.info("Renaming attempt. ip" + ip + " hostname:" + hostname + " User-Agent:" + useragent);

        String tokenRaw = request.getHeader("auth-token");
        String usernameFromToken;
        try {
            usernameFromToken = jwtTokenUtil.getUserNameFromTokenRaw(tokenRaw);
        } catch (NullPointerException npe) {
            log.info("Failure renaming attempt. Wrong token. ip:" + ip + " hostname:" + hostname + " User-Agent:" + useragent);
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("unreadable token");
        }

        var userDetails = userService.getUserByLogin(usernameFromToken);
        if (userDetails != null) {
            JSONObject jsonObject = new JSONObject(json);
            fileService.rename(filename, jsonObject.get("filename").toString());
            log.info("User " + usernameFromToken + " renamed file " + filename);
            return ResponseEntity.status(200).body("successfully renamed");
        }

        log.info("Failed rename attempt. ip:" + ip + " hostname:" + hostname + " User-Agent:" + useragent);
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("cant find such token");
    }

}