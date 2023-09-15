package com.testingground.springsecurity.security.authentication;

import com.testingground.springsecurity.security.JWTService;
import com.testingground.springsecurity.security.authentication.model.AuthenticationRequest;
import com.testingground.springsecurity.security.authentication.model.AuthenticationResponse;
import com.testingground.springsecurity.security.authentication.model.RegisterRequest;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthenticationService {

  private final UserDetailsManager userDetailsManager;
  private final JWTService jWTService;
  private final AuthenticationManager authenticationManager;

  // TODO Distinguish between roles
  public AuthenticationResponse register(RegisterRequest registerRequest) {
    var user = User.builder() // TODO Use custom user with more information later
        .username(registerRequest.username())
        .password(registerRequest.password())
        .build(); // TODO Add roles, password encoder. possibly authorities and ...

    userDetailsManager.createUser(user);
    // TODO Refresh? Save Token?
    return AuthenticationResponse.of(jWTService.generateToken(user));
  }

  public AuthenticationResponse authenticate(AuthenticationRequest authenticationRequest) {
    final var username = authenticationRequest.username();
    authenticationManager.authenticate(
        new UsernamePasswordAuthenticationToken(username, authenticationRequest.password()));

    // Authentication was successful
    var userDetails = userDetailsManager.loadUserByUsername(username);
    // TODO Refresh? Revoke Tokens? Save Token?
    return AuthenticationResponse.of(jWTService.generateToken(userDetails));
  }

  public void refreshToken(HttpServletRequest request, HttpServletResponse response) {
    //TODO
  }

}
