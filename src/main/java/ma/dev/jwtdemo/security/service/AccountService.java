package ma.dev.jwtdemo.security.service;

import java.util.List;

import ma.dev.jwtdemo.security.models.AppRole;
import ma.dev.jwtdemo.security.models.AppUser;

/**
 * AccountService
 */
public interface AccountService {
    AppUser addNewUser(String username, String password, String confirmPassword);

    AppRole addNewRole(String roleName);

    void addRoleToUser(String username, String roleName);

    void removeRoleToUser(String username, String roleName);

    AppUser loadUserByUsername(String username);

    List<AppUser> listUsers();

}