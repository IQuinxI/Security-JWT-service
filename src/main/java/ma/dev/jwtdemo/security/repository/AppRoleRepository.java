package ma.dev.jwtdemo.security.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import ma.dev.jwtdemo.security.models.AppRole;

/**
 * AppRoleRepository
 */
public interface AppRoleRepository extends JpaRepository<AppRole, Long> {
    AppRole findByRoleName(String roleName);
}