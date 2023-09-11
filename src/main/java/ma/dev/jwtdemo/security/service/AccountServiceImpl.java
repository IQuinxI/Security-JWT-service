package ma.dev.jwtdemo.security.service;

import java.util.List;

import org.springframework.stereotype.Service;

import jakarta.transaction.Transactional;
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
public class AccountServiceImpl implements AccountService{

    private final AppUserRepository appUserRepository;
    private final AppRoleRepository appRoleRepository;

    @Override
    public AppUser addNewUser(AppUser appUser) {
        return appUserRepository.save(appUser);
    }

    @Override
    public AppRole addNewRole(AppRole appRole) {
        return appRoleRepository.save(appRole);
    }

    @Override
    public void addRoleToUser(String username, String roleName) {
        AppUser appUser = appUserRepository.findByUsername(username);
        AppRole appRole = appRoleRepository.findByRoleName(roleName);

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

    
}