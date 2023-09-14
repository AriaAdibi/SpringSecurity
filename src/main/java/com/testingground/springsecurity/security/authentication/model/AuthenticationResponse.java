package com.testingground.springsecurity.security.authentication.model;

import java.util.Objects;

public record AuthenticationResponse(String jWT) {
  public AuthenticationResponse {
    Objects.requireNonNull(jWT);
  }
}
