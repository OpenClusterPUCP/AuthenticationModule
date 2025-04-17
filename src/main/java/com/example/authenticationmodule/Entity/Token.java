package com.example.authenticationmodule.Entity;

import jakarta.persistence.*;

@Entity
@Table(name = "token", schema = "cloud")
public class Token {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id", nullable = false)
    private Integer id;

    @Column(name = "token", nullable = false, length = 200)
    private String token;

    @Column(name = "type", nullable = false, length = 45)
    private String type;

    @Column(name = "expiration", nullable = false)
    private Integer expiration;

    @Column(name = "revokate", nullable = false)
    private Integer revokate;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "user", nullable = false)
    private User user;

    public Integer getId() {
        return id;
    }

    public void setId(Integer id) {
        this.id = id;
    }

    public String getToken() {
        return token;
    }

    public void setToken(String token) {
        this.token = token;
    }

    public String getType() {
        return type;
    }

    public void setType(String type) {
        this.type = type;
    }

    public Integer getExpiration() {
        return expiration;
    }

    public void setExpiration(Integer expiration) {
        this.expiration = expiration;
    }

    public Integer getRevokate() {
        return revokate;
    }

    public void setRevokate(Integer revokate) {
        this.revokate = revokate;
    }

    public User getUser() {
        return user;
    }

    public void setUser(User user) {
        this.user = user;
    }

}