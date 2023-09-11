package ma.dev.jwtdemo.controller;

import java.util.List;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

import lombok.RequiredArgsConstructor;
import ma.dev.jwtdemo.security.models.AppUser;
import ma.dev.jwtdemo.security.repository.AppUserRepository;
import ma.dev.jwtdemo.security.service.AccountService;

/**
 * UserController
 */
@RestController
@RequiredArgsConstructor
public class UserController {

    private final AccountService accountService;
    // TODO: delete after testing 
    private final AppUserRepository appUserRepository;

    @GetMapping("/users")
    @PreAuthorize("hasAuthority('SCOPE_USER')")
    public List<AppUser> getAllUsers() {
        return accountService.listUsers();
    }

    // TODO: delete after testing
    @GetMapping("/users/{id}")
    @PreAuthorize("hasAuthority('SCOPE_ADMIN')")
    public AppUser getUser(@PathVariable("id") Long id) {
        return appUserRepository.findById(id).get();
    }

}