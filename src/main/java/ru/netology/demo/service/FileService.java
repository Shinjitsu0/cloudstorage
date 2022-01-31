package ru.netology.demo.service;


import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;
import ru.netology.demo.model.IncomingFile;
import ru.netology.demo.repository.FileRepository;
import java.io.IOException;
import java.time.LocalDate;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Service
public class FileService {

    private final FileRepository fileRepository;
    private final UserService userService;

    public FileService(FileRepository fileRepository, UserService userService) {
        this.fileRepository = fileRepository;
        this.userService = userService;
    }

    public void upload(MultipartFile resource) throws IOException {
        var login = SecurityContextHolder.getContext().getAuthentication().getName();
        var user = userService.getUserByLoginReturnUser(login);
        IncomingFile file = IncomingFile.builder()
                .filename(resource.getOriginalFilename())
                .key(UUID.randomUUID().toString())
                .size(resource.getSize())
                .uploadDate(LocalDate.now())
                .fileType(resource.getContentType())
                .fileContent(resource.getInputStream().readAllBytes())
                .userDB(user)
                .build();
        fileRepository.save(file);
    }

    public IncomingFile download(String filename) {
        Optional<IncomingFile> file = fileRepository.findByFilename(filename);
        return file.orElse(null);
    }

    public void delete(String filename, String username) {
        fileRepository.deleteByFilename(filename, username);
    }


    public List<IncomingFile> show(String username) {
        return fileRepository.findAllFilesByUsername(username);
    }

    public void rename(String originalFilename, String targetFileName) {
        fileRepository.rename(originalFilename, targetFileName);
    }
}