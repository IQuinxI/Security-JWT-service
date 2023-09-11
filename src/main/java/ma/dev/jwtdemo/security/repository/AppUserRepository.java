package ma.dev.jwtdemo.security.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import ma.dev.jwtdemo.security.models.AppUser;

/**
 * AppUserRepository
 */
public interface AppUserRepository extends JpaRepository<AppUser, Long> {
    AppUser findByUsername(String username);
}