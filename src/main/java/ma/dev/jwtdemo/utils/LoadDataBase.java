package ma.dev.jwtdemo.utils;


import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;


import ma.dev.jwtdemo.security.service.AccountService;

/**
 * LoadDataBase
 */
@Configuration
public class LoadDataBase {

    @Bean
    CommandLineRunner load(AccountService accountService) {
        return args -> {
            accountService.addNewRole("ADMIN");
            accountService.addNewRole("USER");

            accountService.addNewUser("manager", "1234", "1234");
            accountService.addNewUser("user1", "1234", "1234");
            accountService.addNewUser("user2", "1234", "1234");
            accountService.addNewUser("user3", "1234", "1234");
            
            accountService.addRoleToUser("manager", "ADMIN");
            accountService.addRoleToUser("manager", "USER");
            accountService.addRoleToUser("user1", "USER");
            accountService.addRoleToUser("user2", "USER");
            accountService.addRoleToUser("user3", "USER");
            
        };
    }
    
}