package com.example.authenticationmodule.DTO;

import java.io.Serializable;

public class JwtResponse implements Serializable {
        private String token;
        private String type = "Bearer";

        public JwtResponse(String token) {
            this.token = token;
        }

        // Getters y setters


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
}