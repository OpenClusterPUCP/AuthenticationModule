package com.example.authenticationmodule.RestTemplate;

import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;

@FeignClient(name="UserServiceModule")
public interface UserServiceFeign {
    @GetMapping("/users")
    ResponseEntity<?> listarUsers();
}