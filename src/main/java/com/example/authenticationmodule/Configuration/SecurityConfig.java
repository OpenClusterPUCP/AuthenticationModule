package com.example.authenticationmodule.Configuration;

import com.example.authenticationmodule.Util.JwtAuthenticationFilter;
import com.example.authenticationmodule.Util.JwtTokenUtil;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.sql.DataSource;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {

    private final DataSource dataSource;
    private final JwtTokenUtil jwtService;

    public SecurityConfig(DataSource dataSource, JwtTokenUtil jwtService) {
        this.dataSource = dataSource;
        this.jwtService = jwtService;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    // Configuración de UserDetailsService (con Jdbc)
    @Bean
    public UserDetailsManager userDetailsService() {
        JdbcUserDetailsManager users = new JdbcUserDetailsManager(dataSource);

        String sql1 = "SELECT username, password, state FROM user WHERE username = ?";
        String sql2 = "SELECT u.username, r.name FROM user u " +
                "INNER JOIN role r ON (u.role = r.id) " +
                "WHERE u.username = ?";
        users.setUsersByUsernameQuery(sql1);
        users.setAuthoritiesByUsernameQuery(sql2);

        return users;
    }

    // Bean para el filtro JWT, evitando @Autowired y ciclos
    @Bean
    public JwtAuthenticationFilter jwtAuthenticationFilter(UserDetailsManager userDetailsService) {
        return new JwtAuthenticationFilter();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authConfig) throws Exception {
        return authConfig.getAuthenticationManager();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http,
                                           JwtAuthenticationFilter jwtAuthenticationFilter) throws Exception {
        http
                .csrf(csrf -> csrf.disable())
                .exceptionHandling(exception -> exception
                        .authenticationEntryPoint((request, response, authException) ->
                                response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "No autorizado")
                        )
                )
                .sessionManagement(session -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                )
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/Admin/**", "/Admin").hasAuthority("Admin")
                        .requestMatchers("/User/**", "/User").hasAuthority("User")
                        .anyRequest().permitAll()
                )
                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }
}