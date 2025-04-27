package com.example.authenticationmodule.Util;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.Resource;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;

@Component
public class JwtTokenUtil {
    private static final long EXPIRATION_TIME = 864_000_000; // 10 días
    private PrivateKey privateKey;
    private PublicKey publicKey;

    // Inyectar las rutas de los archivos de claves
    @Value("${jwt.private-key-path:classpath:private_key.pem}")
    private Resource privateKeyResource;

    @Value("${jwt.public-key-path:classpath:public_key.pem}")
    private Resource publicKeyResource;

    @PostConstruct
    public void init() {
        try {
            // Cargar clave privada desde archivo PEM
            loadPrivateKey();

            // Cargar clave pública desde archivo PEM
            loadPublicKey();

            // Verificar que ambas claves se hayan cargado correctamente
            if (privateKey == null || publicKey == null) {
                throw new RuntimeException("Error al cargar las claves RSA desde archivos");
            }

            System.out.println("✅ Claves RSA cargadas exitosamente desde archivos PEM");
        } catch (Exception e) {
            throw new RuntimeException("Error al inicializar las claves RSA", e);
        }
    }

    private void loadPrivateKey() throws Exception {
        try {
            // Leer el contenido del archivo PEM
            String pemContent = new String(privateKeyResource.getInputStream().readAllBytes(), StandardCharsets.UTF_8);

            // Extraer la clave privada (quitar cabeceras y pies PEM)
            String privateKeyPEM = pemContent
                    .replace("-----BEGIN PRIVATE KEY-----", "")
                    .replace("-----END PRIVATE KEY-----", "")
                    .replace("-----BEGIN RSA PRIVATE KEY-----", "")
                    .replace("-----END RSA PRIVATE KEY-----", "")
                    .replaceAll("\\s", "");

            // Decodificar Base64
            byte[] encoded = Base64.getDecoder().decode(privateKeyPEM);

            // Crear la clave privada
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encoded);
            this.privateKey = keyFactory.generatePrivate(keySpec);
        } catch (Exception e) {
            System.err.println("Error al cargar la clave privada: " + e.getMessage());
            throw e;
        }
    }

    private void loadPublicKey() throws Exception {
        try {
            // Leer el contenido del archivo PEM
            String pemContent = new String(publicKeyResource.getInputStream().readAllBytes(), StandardCharsets.UTF_8);

            // Extraer la clave pública (quitar cabeceras y pies PEM)
            String publicKeyPEM = pemContent
                    .replace("-----BEGIN PUBLIC KEY-----", "")
                    .replace("-----END PUBLIC KEY-----", "")
                    .replaceAll("\\s", "");

            // Decodificar Base64
            byte[] encoded = Base64.getDecoder().decode(publicKeyPEM);

            // Crear la clave pública
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(encoded);
            this.publicKey = keyFactory.generatePublic(keySpec);
        } catch (Exception e) {
            System.err.println("Error al cargar la clave pública: " + e.getMessage());
            throw e;
        }
    }

    public String generateToken(String username, String roles) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("roles", roles);

        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + EXPIRATION_TIME);

        return Jwts.builder()
                .setClaims(claims)
                .setSubject(username)
                .setIssuedAt(now)
                .setExpiration(expiryDate)
                .signWith(privateKey, SignatureAlgorithm.RS256)
                .compact();
    }

    public boolean validateToken(String token) {
        try {
            Jwts.parserBuilder()
                    .setSigningKey(publicKey)
                    .build()
                    .parseClaimsJws(token);
            return true;
        } catch (Exception ex) {
            return false;
        }
    }

    public String getUsernameFromToken(String token) {
        Claims claims = Jwts.parserBuilder()
                .setSigningKey(publicKey)
                .build()
                .parseClaimsJws(token)
                .getBody();

        return claims.getSubject();
    }

    // Método auxiliar para exportar la clave pública (útil para configurar otros servicios)
    public String getPublicKeyBase64() {
        return Base64.getEncoder().encodeToString(publicKey.getEncoded());
    }
}