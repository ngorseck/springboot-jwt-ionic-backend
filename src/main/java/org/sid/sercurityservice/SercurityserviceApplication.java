package org.sid.sercurityservice;

import org.sid.sercurityservice.entities.AppRoles;
import org.sid.sercurityservice.entities.AppUser;
import org.sid.sercurityservice.service.AccountService;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import java.util.ArrayList;

@SpringBootApplication
//Methode 2 pour la gestion des authorisations
@EnableGlobalMethodSecurity(prePostEnabled = true, securedEnabled = false)
public class SercurityserviceApplication {

	public static void main(String[] args) {
		SpringApplication.run(SercurityserviceApplication.class, args);
	}

	@Bean
	PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}

	//Pour debut angular
		/*@Bean
		public WebMvcConfigurer corsConfigurer() {

			return new WebMvcConfigurer() {
				@Override
				public void addCorsMappings(CorsRegistry registry) {
					registry.addMapping("/*")
							.allowedHeaders("*").allowedOrigins("http://localhost:4200/")
							.allowedMethods("*").allowCredentials(true);
				}
			};
		}*/
	//fin angular
	@Bean
	CommandLineRunner start (AccountService accountService) {
		return args -> {
			accountService.addNewRole(new AppRoles(null, "USER"));
			accountService.addNewRole(new AppRoles(null, "ADMIN"));
			accountService.addNewRole(new AppRoles(null, "CUSTOMER_MANAGER"));
			accountService.addNewRole(new AppRoles(null, "PRODUCT_MANAGER"));
			accountService.addNewRole(new AppRoles(null, "BILLS_MANAGER"));

			accountService.addNewUser(new AppUser(null, "user1", "1234", new ArrayList<>()));
			accountService.addNewUser(new AppUser(null, "admin", "1234", new ArrayList<>()));
			accountService.addNewUser(new AppUser(null, "user2", "1234", new ArrayList<>()));
			accountService.addNewUser(new AppUser(null, "user3", "1234", new ArrayList<>()));
			accountService.addNewUser(new AppUser(null, "user4", "1234", new ArrayList<>()));

			accountService.addRoleToUser("user1","USER");
			accountService.addRoleToUser("admin","USER");
			accountService.addRoleToUser("admin","ADMIN");
			accountService.addRoleToUser("user2","USER");
			accountService.addRoleToUser("user2","CUSTOMER_MANAGER");
			accountService.addRoleToUser("user3","USER");
			accountService.addRoleToUser("user3","PRODUCT_MANAGER");
			accountService.addRoleToUser("user4","USER");
			accountService.addRoleToUser("user4","BILLS_MANAGER");
		};



	}
}
