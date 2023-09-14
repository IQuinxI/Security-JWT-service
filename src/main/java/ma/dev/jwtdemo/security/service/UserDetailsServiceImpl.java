package ma.dev.jwtdemo.security.service;

import java.util.stream.Collectors;

import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import lombok.RequiredArgsConstructor;
import ma.dev.jwtdemo.security.models.AppUser;
import ma.dev.jwtdemo.security.repository.AppUserRepository;

/**
 * UserDetailsServiceImpl
 */
@Service
public class UserDetailsServiceImpl implements UserDetailsService{
    private AppUserRepository appUserRepository;
    // private  AccountService accountService;

    public UserDetailsServiceImpl(AppUserRepository appUserRepository) {
        this.appUserRepository = appUserRepository;
    }

    
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        // AppUser appUser = accountService.loadUserByUsername(username);
        AppUser appUser = appUserRepository.findByUsername(username);

        if(appUser == null) throw new UsernameNotFoundException("The username couldn't be found");
        
        UserDetails userDetails = User
            .withUsername(username)
            .password(appUser.getPassword())
            .roles(appUser.getAppRoles().stream().map(au -> au.getRoleName()).toArray(String[]::new))
            .build();

        return userDetails;
    }

    
}