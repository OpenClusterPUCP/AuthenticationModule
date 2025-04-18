package com.example.authenticationmodule.Controller;

import com.example.authenticationmodule.DTO.JwtResponse;
import com.example.authenticationmodule.Util.JwtTokenUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.stream.Collectors;

@RestController
public class AuthController {
    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private JwtTokenUtil jwtTokenUtil;

    @PostMapping("/login")
    public ResponseEntity<?> authenticateUser(@RequestBody LinkedHashMap<String, Object> loginRequest) {

        // Autenticar al usuario
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        loginRequest.get("username"),
                        loginRequest.get("password")
                )
        );

        // Establecer la autenticación en el contexto
        SecurityContextHolder.getContext().setAuthentication(authentication);

        // Extraer los roles/autoridades del objeto Authentication
        Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
        List<String> roles = authorities.stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toList());

        // Generar el token JWT incluyendo los roles
        // Modificar tu método generateToken para aceptar los roles
        String jwt = jwtTokenUtil.generateToken(authentication.getName(), roles);

        // Devolver el token en la respuesta
        return ResponseEntity.ok(new JwtResponse(jwt));
    }
    @GetMapping("/Admin/test")
    public Object testResource(){
        return "HolaAdmin";
    }
    @GetMapping("/User/test")
    public Object testResourceUser(){
        return "HolaUser";

    }


}
