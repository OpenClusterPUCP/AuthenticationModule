package com.example.authenticationmodule.Controller;

import com.example.authenticationmodule.Entity.User;
import com.example.authenticationmodule.Repository.UserRepository;
import com.example.authenticationmodule.Util.JwtTokenUtil;
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
import lombok.extern.slf4j.Slf4j;
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
        log.info("Intento de login recibido para usuario: {}", loginRequest.get("username"));

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

            // Intentar autenticar al usuario
            log.debug("Intentando autenticar usuario: {}", loginRequest.get("username"));
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            loginRequest.get("username"),
                            loginRequest.get("password")
                    )
            );

            // Si la autenticación es exitosa, establecer el contexto de seguridad
            log.info("Autenticación exitosa para usuario: {}", authentication.getName());
            SecurityContextHolder.getContext().setAuthentication(authentication);
            Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
            List<String> roles = authorities.stream()
                    .map(GrantedAuthority::getAuthority)
                    .collect(Collectors.toList());

            log.debug("Roles del usuario {}: {}", authentication.getName(), roles);


            // Generar token JWT
            log.debug("Generando token JWT para usuario: {}", authentication.getName());

            String jwt = jwtTokenUtil.generateToken(authentication.getName(), roles.get(0));
            log.debug("Token JWT generado exitosamente");
            // Crear respuesta exitosa usando LinkedHashMap
            LinkedHashMap<String, Object> response = new LinkedHashMap<>();
            log.debug("Buscando información adicional del usuario en la base de datos");
            User user = userRepository.findUsersByUsername(authentication.getName()).get();
            log.debug("Usuario encontrado en la base de datos, ID: {}", user.getId());
            response.put("jwt", jwt);
            response.put("name", user.getUsername() );
            response.put("lastname", user.getUsername() );
            response.put("username", user.getUsername() );
            response.put("role", roles.get(0));
            response.put("id" , user.getId());

            log.info("Login exitoso para usuario: {}, role: {}", user.getUsername(), roles.get(0));

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
            System.out.println("Disabled");
            return ResponseEntity
                    .status(HttpStatus.FORBIDDEN)
                    .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
                    .body(response);

        } catch (LockedException e) {
            System.out.println("Locked");
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
            LinkedHashMap<String, Object> response = new LinkedHashMap<>();
            log.error("Error inesperado durante la autenticación del usuario: {}", loginRequest.get("username"), e);
            response.put("success", false);
            response.put("message", "Authentication error: " + e.getMessage());
            return ResponseEntity
                    .status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
                    .body(response);
        }
    }
}
