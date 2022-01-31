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
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import ru.netology.demo.security.JwtTokenUtil;
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
    public Object showSavedFiles(@RequestHeader("User-Agent") String useragent, HttpServletRequest request) {
        var login = SecurityContextHolder.getContext().getAuthentication().getName();
        var ip = request.getRemoteAddr();
        var hostname = request.getRemoteHost();
        log.info("Viewing files attempt. ip:" + ip + " hostname:" + hostname + " User-Agent:" + useragent);
        var userDetails = userService.getUserByLogin(login);
        if (userDetails != null) {
            log.info("Successful viewing attempt. Access granted for user: " + userDetails.getUsername());
            return fileService.show(login);
        }
        log.info("Failure viewing attempt. Wrong token. ip:" + ip + " hostname:" + hostname + " User-Agent:" + useragent);
        return ResponseEntity.status(HttpStatus.FORBIDDEN).body("unauthorized attempt to access files");

    }
    @PostMapping(value = "/file")
    public ResponseEntity<?> saveFile(@RequestHeader("User-Agent") String useragent,
                                      MultipartFile file, HttpServletRequest request) throws IOException {
        var login = SecurityContextHolder.getContext().getAuthentication().getName();
        var ip = request.getRemoteAddr();
        var hostname = request.getRemoteHost();
        log.info("Upload attempt. ip" + ip + " hostname:" + hostname + " User-Agent:" + useragent);
        var userDetails = userService.getUserByLogin(login);
        if (userDetails != null) {
            fileService.upload(file);
            log.info("Success upload attempt. User " + login + " uploaded file " + file.getOriginalFilename());
            return ResponseEntity.status(200).build();
        }
        log.info("Failed upload attempt. ip:" + ip + " hostname:" + hostname + " User-Agent:" + useragent);
        return ResponseEntity.status(HttpStatus.FORBIDDEN).body("cant find such token");
    }

    @GetMapping(value = "/file")
    public ResponseEntity<Object> downloadFile(@RequestParam("filename") String filename,
                                               @RequestHeader("User-Agent") String useragent,
                                               HttpServletRequest request) {
        var login = SecurityContextHolder.getContext().getAuthentication().getName();
        var ip = request.getRemoteAddr();
        var hostname = request.getRemoteHost();
        log.info("Download attempt. ip" + ip + " hostname:" + hostname + " User-Agent:" + useragent);
        var userDetails = userService.getUserByLogin(login);
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
    public ResponseEntity<?> deleteFile(@RequestParam("filename") String filename,
                                        @RequestHeader("User-Agent") String useragent,
                                        HttpServletRequest request) {
        var login = SecurityContextHolder.getContext().getAuthentication().getName();
        var ip = request.getRemoteAddr();
        var hostname = request.getRemoteHost();
        log.info("Delete attempt. ip" + ip + " hostname:" + hostname + " User-Agent:" + useragent);
        var userDetails = userService.getUserByLogin(login);
        if (userDetails != null) {
            fileService.delete(filename, userDetails.getUsername());
            log.info("User " + login + " successfully deleted file " + filename);
            return ResponseEntity.ok("successfully deleted");
        }
        log.info("Failed delete attempt. Wrong token. ip:" + ip + " hostname:" + hostname + " User-Agent:" + useragent);
        return ResponseEntity.status(HttpStatus.FORBIDDEN).body("unauthorized attempt delete files");
    }

    @PutMapping(value = "/file")
    public ResponseEntity<?> renameFile(@RequestParam("filename") String filename, @RequestBody String json,
                                        @RequestHeader("User-Agent") String useragent, HttpServletRequest request) throws JSONException {
        var login = SecurityContextHolder.getContext().getAuthentication().getName();
        var ip = request.getRemoteAddr();
        var hostname = request.getRemoteHost();
        log.info("Renaming attempt. ip" + ip + " hostname:" + hostname + " User-Agent:" + useragent);
        var userDetails = userService.getUserByLogin(login);
        if (userDetails != null) {
            JSONObject jsonObject = new JSONObject(json);
            fileService.rename(filename, jsonObject.get("filename").toString());
            log.info("User " + login + " renamed file " + filename);
            return ResponseEntity.status(200).body("successfully renamed");
        }
        log.info("Failed rename attempt. ip:" + ip + " hostname:" + hostname + " User-Agent:" + useragent);
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("cant find such token");
    }

}