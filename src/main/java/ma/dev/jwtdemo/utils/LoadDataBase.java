package ma.dev.jwtdemo.utils;

import java.util.ArrayList;

import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import ma.dev.jwtdemo.security.models.AppRole;
import ma.dev.jwtdemo.security.models.AppUser;
import ma.dev.jwtdemo.security.repository.AppRoleRepository;
import ma.dev.jwtdemo.security.repository.AppUserRepository;
import ma.dev.jwtdemo.security.service.AccountService;

/**
 * LoadDataBase
 */
@Configuration
public class LoadDataBase {

    @Bean
    CommandLineRunner load(AccountService accountService) {
        return args -> {
            accountService.addNewRole(new AppRole(null, "MANAGER"));
            accountService.addNewRole(new AppRole(null, "CASHIER"));

            accountService.addNewUser(new AppUser(null, "manager", "1234", new ArrayList<>()));
            accountService.addNewUser(new AppUser(null, "user1", "1234", new ArrayList<>()));
            accountService.addNewUser(new AppUser(null, "user2", "1234", new ArrayList<>()));
            accountService.addNewUser(new AppUser(null, "user3", "1234", new ArrayList<>()));
            
            accountService.addRoleToUser("manager", "MANAGER");
            accountService.addRoleToUser("manager", "CASHIER");
            accountService.addRoleToUser("user1", "CASHIER");
            accountService.addRoleToUser("user2", "CASHIER");
            accountService.addRoleToUser("user3", "CASHIER");
            
        };
    }
    
}