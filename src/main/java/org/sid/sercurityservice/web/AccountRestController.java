package org.sid.sercurityservice.web;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.Data;
import org.sid.sercurityservice.entities.AppRoles;
import org.sid.sercurityservice.entities.AppUser;
import org.sid.sercurityservice.service.AccountService;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.security.Principal;
import java.util.*;
import java.util.stream.Collectors;

@RestController
public class AccountRestController {

    private AccountService accountService;

    public AccountRestController(AccountService accountService) {
        this.accountService = accountService;
    }

    //Methode 2 pour la gestion des authorisations
    @PostAuthorize("hasAuthority('USER')")
    //@CrossOrigin(origins = "*", allowedHeaders = "*")
    //@CrossOrigin(origins = "http://localhost:4200")
    @GetMapping(path = "/users")
    public List<AppUser> appUsers() {
        //System.out.println("yes");
        return accountService.listUsers();
    }

    @PostMapping(path = "/users")
    @PostAuthorize("hasAuthority('ADMIN')")
    public AppUser savwUser(@RequestBody AppUser appUser) {

        return accountService.addNewUser(appUser);
    }
    @PostMapping(path = "/roles")
    @PostAuthorize("hasAuthority('ADMIN')")
    public AppRoles saveRole (@RequestBody AppRoles appRoles) {
        return accountService.addNewRole(appRoles);
    }

    @PostMapping(path = "/addRoleToUser")
    @PostAuthorize("hasAuthority('ADMIN')")
    public void addRoleToUser(@RequestBody RoleUserForm roleUserForm) {
        accountService.addRoleToUser(roleUserForm.getUsername(), roleUserForm.getRoleName());
    }

    @GetMapping(path = "/refreshToken")
    public void refreshToken(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String authToken = request.getHeader("Authorization");
        if (authToken != null && authToken.startsWith("Bearer ")) {
            try {
                String jwt = authToken.substring(7);
                Algorithm algorithm = Algorithm.HMAC256("mySecret1234");//cle privee pour la decryto
                JWTVerifier jwtVerifier = JWT.require(algorithm).build();
                DecodedJWT decodedJWT = jwtVerifier.verify(jwt);
                String username = decodedJWT.getSubject();

                AppUser appUser = accountService.loadUserByUsername(username);

                //On genere un nouveau Token
                String jwtAccessToken = JWT.create()
                        .withSubject(appUser.getUsername())
                        .withExpiresAt(new Date(System.currentTimeMillis() + 5*60*1000))//en milisecond dans 5mn
                        .withIssuer(request.getRequestURI().toString())//Nom de l'application qui a genere le tocken
                        .withClaim("roles", appUser.getAppRoles().stream().map(r->r.getRoleName()).collect(Collectors.toList()))//les roles
                        .sign(algorithm);//signature
                //On retourne le token
                Map<String, String> idToken = new HashMap<>();
                idToken.put("access-token", jwtAccessToken);
                idToken.put("refresh-token", jwt);

                response.setContentType("application/json");

                new ObjectMapper().writeValue(response.getOutputStream(), idToken);

            }catch (Exception ex) {
                throw ex;
            }
        } else {
            throw new RuntimeException("Refresh token required !!!");
        }
    }

    //Comment recupere l'utilisateur qui est connecte
    @GetMapping(path = "/profile")
    @PostAuthorize("hasAuthority('USER')")
    public AppUser profile(Principal principal) {
        return accountService.loadUserByUsername(principal.getName());
    }
}

@Data
class RoleUserForm {
    private String username;
    private String roleName;
}