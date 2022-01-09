package ru.netology.demo.repository;


import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;
import ru.netology.demo.model.IncomingFile;

import java.util.List;
import java.util.Optional;

@Repository
@Transactional
public interface FileRepository extends JpaRepository<IncomingFile, Long> {
    IncomingFile save(IncomingFile file);

    Optional<IncomingFile> findByFilename(String filename);

    @Query("select files from IncomingFile files where files.user.login = :username")
    List<IncomingFile> findAllFilesByUsername(String username);

    @Modifying
    @Query("delete from IncomingFile file where file.filename = :filename and file.user.login = :username")
    void deleteByFilename(String filename, String username);

    @Modifying
    @Query("update IncomingFile file set file.filename = :targetFileName where file.filename=:originalFilename")
    void rename(@Param("originalFilename") String originalFilename, @Param("targetFileName") String targetFileName);
}
