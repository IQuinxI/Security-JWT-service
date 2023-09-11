package ma.dev.jwtdemo.security.service;

import java.util.List;

import ma.dev.jwtdemo.security.models.AppRole;
import ma.dev.jwtdemo.security.models.AppUser;

/**
 * AccountService
 */
public interface AccountService {
    AppUser addNewUser(AppUser appUser);
    AppRole addNewRole(AppRole appRole);
    void addRoleToUser(String username, String roleName);
    AppUser loadUserByUsername(String username);
    List<AppUser> listUsers();
}