package org.sid.sercurityservice.security.filters;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.sid.sercurityservice.security.util.JwtUtils;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private AuthenticationManager authenticationManager;

    public JwtAuthenticationFilter(AuthenticationManager authenticationManager) {

        this.authenticationManager = authenticationManager;
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        System.out.println("attemptAuthentication");
        String username = request.getParameter("username");
        String password = request.getParameter("password");
        System.out.println(username + "   " + password);
        UsernamePasswordAuthenticationToken authenticationToken =
                new UsernamePasswordAuthenticationToken(username, password);

        return authenticationManager.authenticate(authenticationToken);
    }



    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
        System.out.println("successfulAuthentication");
        User user = (User)authResult.getPrincipal();

        //On genere le JWT
        Algorithm algorithm = Algorithm.HMAC256(JwtUtils.SECRET);//("mySecret1234"); //cle privee pour la crypto pour le header du token
        String jwtAccessToken = JWT.create()//pour le payload
                .withSubject(user.getUsername())
                .withExpiresAt(new Date(System.currentTimeMillis() + 1*60*1000))//en milisecond dans 1mn
                .withIssuer(request.getRequestURI().toString())//Nom de l'application qui a genere le tocken
                .withClaim("roles", user.getAuthorities().stream().map(ga->ga.getAuthority()).collect(Collectors.toList()))//les roles
                .sign(algorithm);//signature du token
        //
        String jwtRefreshToken = JWT.create()
                .withSubject(user.getUsername())
                .withExpiresAt(new Date(System.currentTimeMillis() + 15*60*1000))//en milisecond dans 15mn en general pour une longue duree
                .withIssuer(request.getRequestURI().toString())//Nom de l'application qui a genere le tocken
                .sign(algorithm);//signature
        //On retourne le token
        Map<String, String> idToken = new HashMap<>();
        idToken.put("accessToken", jwtAccessToken);
        idToken.put("refreshToken", jwtRefreshToken);

        response.setContentType("application/json");

        new ObjectMapper().writeValue(response.getOutputStream(), idToken);
    }



}
