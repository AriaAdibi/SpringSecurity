package com.testingground.springsecurity.security.authentication.model;

import java.util.Objects;

public record AuthenticationResponse(String jWT) {
  public AuthenticationResponse {
    Objects.requireNonNull(jWT);
  }

  public static AuthenticationResponse of(String jWT) {
    return new AuthenticationResponse(jWT);
  }

}
