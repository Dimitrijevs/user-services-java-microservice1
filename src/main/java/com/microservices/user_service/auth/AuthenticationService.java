package com.microservices.user_service.auth;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.microservices.user_service.config.JwtService;
import com.microservices.user_service.user.Role;
import com.microservices.user_service.user.User;
import com.microservices.user_service.user.UserRepository;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class AuthenticationService {

    // created
    private final UserRepository repository;

    // created
    private final JwtService jwtService;

    // build in
    private final PasswordEncoder passwordEncoder;

    // build in 
    private final AuthenticationManager authenticationManager;

    // return token to a user after registration
        public AuthenticationResponse register(RegisterRequest request) {
                User user = User.builder()
                                .first_name(request.getFirstname())
                                .last_name(request.getLastname())
                                .email(request.getEmail())
                                .password(passwordEncoder.encode(request.getPassword()))
                                .role(Role.USER)
                                .build();

                repository.save(user);

                String jwtToken = jwtService.generateToken(user);

                return generateResponseWithToken(jwtToken);
        }

        // return token to a user after login
        public AuthenticationResponse authenticate(AuthenticationRequest request) {
                authenticationManager.authenticate(
                                new UsernamePasswordAuthenticationToken(
                                                request.getEmail(),
                                                request.getPassword()));

                User user = repository.findByEmail(request.getEmail()).orElseThrow();

                String jwtToken = jwtService.generateToken(user);

                return generateResponseWithToken(jwtToken);
        }

        // generate token
        private AuthenticationResponse generateResponseWithToken(String jwtToken) {
                return AuthenticationResponse.builder()
                                .token(jwtToken)
                                .build();
        }
}
