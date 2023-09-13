package ma.dev.jwtdemo.security.service;

import java.util.Map;

/**
 * AuthService
 */
public interface AuthService {

    public Map<String, String> authenticate(String username, String password);
    
}