package ru.netology.demo.model;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import javax.persistence.*;
import java.io.Serializable;
import java.util.List;

@Data
@Builder
@Entity
@NoArgsConstructor
@AllArgsConstructor
public class User implements Serializable {
    @Id
    private String login;
    @Column
    private String username;
    @Column
    private String token;
    @Column
    private String password;
    @OneToMany(cascade = CascadeType.ALL)
    private List<IncomingFile> files;
}
