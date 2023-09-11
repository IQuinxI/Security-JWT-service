package ma.dev.jwtdemo;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

import ma.dev.jwtdemo.security.RsaKeyConfig;


@SpringBootApplication
@EnableConfigurationProperties(RsaKeyConfig.class)
public class JwtDemoApplication {

	public static void main(String[] args) {
		SpringApplication.run(JwtDemoApplication.class, args);
	}

}
