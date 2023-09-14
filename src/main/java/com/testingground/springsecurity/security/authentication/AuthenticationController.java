package com.testingground.springsecurity.security.authentication;

import com.testingground.springsecurity.security.authentication.model.AuthenticationRequest;
import com.testingground.springsecurity.security.authentication.model.AuthenticationResponse;
import com.testingground.springsecurity.security.authentication.model.RegisterRequest;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController("api/v1/auth")
@RequiredArgsConstructor
public class AuthenticationController {

  private final AuthenticationService service;

  @PostMapping("/register")
  public ResponseEntity<AuthenticationResponse> register(@RequestBody RegisterRequest registerRequest) {
    return ResponseEntity.ok(service.register(registerRequest));
  }

  @PostMapping("/authenticate")
  public ResponseEntity<AuthenticationResponse> authenticate(@RequestBody AuthenticationRequest authenticationRequest) {
    return ResponseEntity.ok(service.authenticate(authenticationRequest));
  }

  @GetMapping("/refresh-token")
  public void refreshToken(HttpServletRequest request, HttpServletResponse response) {
    service.refreshToken(request, response);
  }

}
