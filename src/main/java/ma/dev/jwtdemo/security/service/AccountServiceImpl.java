package ma.dev.jwtdemo.security.service;

import java.util.List;


import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import lombok.RequiredArgsConstructor;
import ma.dev.jwtdemo.security.models.AppRole;
import ma.dev.jwtdemo.security.models.AppUser;
import ma.dev.jwtdemo.security.repository.AppRoleRepository;
import ma.dev.jwtdemo.security.repository.AppUserRepository;

/**
 * AccountServiceImpl
 */
@Service
@Transactional
@RequiredArgsConstructor
public class AccountServiceImpl implements AccountService {

    private final AppUserRepository appUserRepository;
    private final AppRoleRepository appRoleRepository;
    private final PasswordEncoder passwordEncoder;
    @Override
    public AppUser addNewUser(String username, String password, String confirmPassword) {
        AppUser user = appUserRepository.findByUsername(username);
        if(user != null) throw new RuntimeException("The user already exists");
        if(!password.equals(confirmPassword)) throw new RuntimeException("The Passwords do not match");
        user = AppUser.builder()
                .username(username)
                .password(passwordEncoder.encode(password))
                .build();
        return appUserRepository.save(user);
    }

    @Override
    public AppRole addNewRole(String roleName) {
        AppRole role = appRoleRepository.findByRoleName(roleName);
        if(role != null) throw new RuntimeException("The role already exists");
        role = AppRole.builder()
            .roleName(roleName)
            .build();
        return appRoleRepository.save(role);
    }

    @Override
    public void addRoleToUser(String username, String roleName) {
        AppUser appUser = appUserRepository.findByUsername(username);
        AppRole appRole = appRoleRepository.findByRoleName(roleName);

        if(appUser == null || appRole == null) throw new RuntimeException("user or role don't exist");
        appUser.getAppRoles().add(appRole);
    }

    @Override
    public AppUser loadUserByUsername(String username) {
        return appUserRepository.findByUsername(username);
    }

    @Override
    public List<AppUser> listUsers() {
        return appUserRepository.findAll();
    }

    @Override
    public void removeRoleToUser(String username, String roleName) {
        
    }

}