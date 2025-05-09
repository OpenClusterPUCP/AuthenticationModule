package com.example.authenticationmodule.Controller;

import com.example.authenticationmodule.Entity.User;
import com.example.authenticationmodule.Repository.UserRepository;
import com.example.authenticationmodule.Util.JwtTokenUtil;
import jakarta.servlet.http.HttpSession;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.*;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDateTime;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.stream.Collectors;

@RestController
@Slf4j
public class AuthController {
    @Autowired
    private AuthenticationManager authenticationManager;
    @Autowired
    private JwtTokenUtil jwtTokenUtil;
    @Autowired
    private UserRepository userRepository;
    @PostMapping("/login")
    public ResponseEntity<?> authenticateUser(@RequestBody LinkedHashMap<String, Object> loginRequest) {
        log.info("Recibida solicitud de login para usuario: {}", loginRequest.get("username"));

        try {
            // Validar que los campos requeridos estén presentes
            if (loginRequest.get("username") == null || loginRequest.get("password") == null) {
                log.warn("Intento de login con campos vacíos: username o password no proporcionados");

                LinkedHashMap<String, Object> response = new LinkedHashMap<>();
                response.put("success", false);
                response.put("message", "Username or password cannot be empty");

                return ResponseEntity
                        .status(HttpStatus.BAD_REQUEST)
                        .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
                        .body(response);
            }

            log.debug("Iniciando proceso de autenticación para el usuario: {}", loginRequest.get("username"));

            // Intentar autenticar al usuario
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            loginRequest.get("username"),
                            loginRequest.get("password")
                    )
            );

            log.info("Usuario autenticado correctamente: {}", authentication.getName());

            // Si la autenticación es exitosa, establecer el contexto de seguridad
            SecurityContextHolder.getContext().setAuthentication(authentication);
            Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
            List<String> roles = authorities.stream()
                    .map(GrantedAuthority::getAuthority)
                    .collect(Collectors.toList());

            log.debug("Roles del usuario {}: {}", authentication.getName(), roles);

            // Generar token JWT
            log.debug("Generando token JWT para el usuario: {}", authentication.getName());
            String jwt = jwtTokenUtil.generateToken(authentication.getName(), roles.get(0));
            log.debug("Token JWT generado exitosamente");

            // Crear respuesta exitosa usando LinkedHashMap
            LinkedHashMap<String, Object> response = new LinkedHashMap<>();

            log.debug("Recuperando información de usuario de la base de datos");
            User user = userRepository.findUsersByUsername(authentication.getName()).get();

            // Establecer el tiempo del login
            log.debug("Actualizando última fecha de login para el usuario: {}", user.getUsername());
            user.setLastLogin(LocalDateTime.now());
            userRepository.save(user);
            log.debug("Última fecha de login actualizada correctamente");

            response.put("jwt", jwt);
            response.put("name", user.getName());
            response.put("lastname", user.getLastName());
            response.put("username", user.getUsername());
            response.put("code", user.getCode());
            response.put("role", roles.get(0));
            response.put("id", user.getId());

            log.info("Login exitoso completado para el usuario: {}, ID: {}", user.getUsername(), user.getId());

            return ResponseEntity.ok()
                    .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
                    .body(response);

        } catch (BadCredentialsException e) {
            // Credenciales inválidas
            log.warn("Intento de login fallido: Credenciales inválidas para usuario: {}", loginRequest.get("username"));

            LinkedHashMap<String, Object> response = new LinkedHashMap<>();
            response.put("success", false);
            response.put("message", "Invalid username or password");

            return ResponseEntity
                    .status(HttpStatus.UNAUTHORIZED)
                    .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
                    .body(response);

        } catch (DisabledException e) {
            // Cuenta deshabilitada
            log.warn("Intento de login fallido: Cuenta deshabilitada para usuario: {}", loginRequest.get("username"));

            LinkedHashMap<String, Object> response = new LinkedHashMap<>();
            response.put("success", false);
            response.put("message", "Account is disabled");

            return ResponseEntity
                    .status(HttpStatus.FORBIDDEN)
                    .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
                    .body(response);

        } catch (LockedException e) {
            // Cuenta bloqueada
            log.warn("Intento de login fallido: Cuenta bloqueada para usuario: {}", loginRequest.get("username"));

            LinkedHashMap<String, Object> response = new LinkedHashMap<>();
            response.put("success", false);
            response.put("message", "Account is locked");

            return ResponseEntity
                    .status(HttpStatus.FORBIDDEN)
                    .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
                    .body(response);

        } catch (Exception e) {
            // Otros errores inesperados
            log.error("Error inesperado durante la autenticación: {} - Mensaje: {}", loginRequest.get("username"), e.getMessage(), e);

            LinkedHashMap<String, Object> response = new LinkedHashMap<>();
            response.put("success", false);
            response.put("message", "Authentication error: " + e.getMessage());

            return ResponseEntity
                    .status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
                    .body(response);
        }
    }
}