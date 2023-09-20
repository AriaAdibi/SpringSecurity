package com.testingground.springsecurity.demo;

import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("api/v1/demo")
public class DemoController {

  @GetMapping("welcome-commoner")
  public ResponseEntity<String> welcomeCommoner() {
    return ResponseEntity.ok("Welcome!");
  }

  @GetMapping("welcome-king")
  @PreAuthorize("hasAuthority('KingOfKings')")
  public ResponseEntity<String> welcomeKing() {
    return ResponseEntity.ok("All hail the king!");
  }

}
