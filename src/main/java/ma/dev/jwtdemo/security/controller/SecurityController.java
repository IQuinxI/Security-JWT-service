package ma.dev.jwtdemo.security.controller;

import java.util.Map;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import org.springframework.security.core.Authentication;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import lombok.RequiredArgsConstructor;
import ma.dev.jwtdemo.security.service.AuthService;

/**
 * SecurityController
 */
@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class SecurityController {

	private final AuthService authService;

	@GetMapping("/profile")
	public Authentication authentication(Authentication authentication) {
		return authentication;
	}

	@PostMapping("/login")
	public ResponseEntity<Map<String, String>> login(String username, String password) {
		Map<String, String> jwt = authService.authenticate(username, password);
		return new ResponseEntity<Map<String, String>>(jwt, HttpStatus.OK);
	}
}