package com.example.authenticationmodule.Util;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.annotation.GetMapping;

import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;
import java.util.stream.Collectors;

@Component
public class JwtTokenUtil {

    private static final long EXPIRATION_TIME = 864_000_000; // 10 días

    private PrivateKey privateKey;
    private PublicKey publicKey;

    // Opción 1: Para desarrollo/pruebas, genera automáticamente las claves
    public JwtTokenUtil() {
        try {
            // Genera un par de claves para desarrollo (no recomendado para producción)
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();

            this.privateKey = keyPair.getPrivate();
            this.publicKey = keyPair.getPublic();

            // Imprime las claves para configuración futura
            System.out.println("⚠️ USANDO CLAVES GENERADAS AUTOMÁTICAMENTE - NO PARA PRODUCCIÓN ⚠️");
            System.out.println("Clave privada Base64: " +
                    Base64.getEncoder().encodeToString(privateKey.getEncoded()));
            System.out.println("Clave pública Base64: " +
                    Base64.getEncoder().encodeToString(publicKey.getEncoded()));
        } catch (Exception e) {
            throw new RuntimeException("Error al generar las claves RSA", e);
        }
    }

    /*
    // Opción 2: Para producción, usa claves desde properties
    // Descomenta esto y comenta el constructor de arriba cuando tengas tus claves listas

    @Value("${jwt.private.key:}")
    private String privateKeyString;

    @Value("${jwt.public.key:}")
    private String publicKeyString;

    @PostConstruct
    public void init() {
        try {
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");

            // Inicializar con claves de configuración si están disponibles
            if (privateKeyString != null && !privateKeyString.isEmpty()) {
                try {
                    // Intenta decodificar como PKCS8 directo
                    byte[] privateKeyBytes = Base64.getDecoder().decode(privateKeyString);
                    PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
                    this.privateKey = keyFactory.generatePrivate(privateKeySpec);
                } catch (Exception e) {
                    // Si falla, puede ser que la clave esté en formato PEM, intenta limpiar
                    String cleanedKey = privateKeyString
                            .replace("-----BEGIN PRIVATE KEY-----", "")
                            .replace("-----END PRIVATE KEY-----", "")
                            .replace("-----BEGIN RSA PRIVATE KEY-----", "")
                            .replace("-----END RSA PRIVATE KEY-----", "")
                            .replaceAll("\\s+", "");

                    byte[] privateKeyBytes = Base64.getDecoder().decode(cleanedKey);
                    PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
                    this.privateKey = keyFactory.generatePrivate(privateKeySpec);
                }
            }

            if (publicKeyString != null && !publicKeyString.isEmpty()) {
                try {
                    // Intenta decodificar como X509 directo
                    byte[] publicKeyBytes = Base64.getDecoder().decode(publicKeyString);
                    X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyBytes);
                    this.publicKey = keyFactory.generatePublic(publicKeySpec);
                } catch (Exception e) {
                    // Si falla, puede ser que la clave esté en formato PEM, intenta limpiar
                    String cleanedKey = publicKeyString
                            .replace("-----BEGIN PUBLIC KEY-----", "")
                            .replace("-----END PUBLIC KEY-----", "")
                            .replaceAll("\\s+", "");

                    byte[] publicKeyBytes = Base64.getDecoder().decode(cleanedKey);
                    X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyBytes);
                    this.publicKey = keyFactory.generatePublic(publicKeySpec);
                }
            }

            // Genera claves si no se proporcionaron en la configuración
            if (privateKey == null || publicKey == null) {
                System.out.println("⚠️ Claves no configuradas, generando automáticamente ⚠️");
                KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
                keyPairGenerator.initialize(2048);
                KeyPair keyPair = keyPairGenerator.generateKeyPair();

                if (privateKey == null) {
                    this.privateKey = keyPair.getPrivate();
                    System.out.println("Clave privada generada: " +
                        Base64.getEncoder().encodeToString(privateKey.getEncoded()));
                }

                if (publicKey == null) {
                    this.publicKey = keyPair.getPublic();
                    System.out.println("Clave pública generada: " +
                        Base64.getEncoder().encodeToString(publicKey.getEncoded()));
                }
            }
        } catch (Exception e) {
            throw new RuntimeException("Error al inicializar las claves RSA", e);
        }
    }
    */

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

    // Métodos auxiliares para exportar las claves (útil para configurar otros servicios)
    public String getPublicKeyBase64() {
        return Base64.getEncoder().encodeToString(publicKey.getEncoded());
    }


}