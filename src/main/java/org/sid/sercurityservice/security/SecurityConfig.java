package org.sid.sercurityservice.security;

import org.sid.sercurityservice.entities.AppUser;
import org.sid.sercurityservice.security.filters.JwtAuthenticationFilter;
import org.sid.sercurityservice.security.filters.JwtAuthorizationFilter;
import org.sid.sercurityservice.service.UserDetailsServiceImpl;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.util.ArrayList;
import java.util.Collection;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private UserDetailsServiceImpl userDetailsService;

    public SecurityConfig(UserDetailsServiceImpl userDetailsService) {
        this.userDetailsService = userDetailsService;
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userDetailsService);
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        /*http.csrf().disable();//pour les faille csrf
        http.headers().frameOptions().disable();//pour h2
        http.authorizeRequests().anyRequest().permitAll();*/

        http.csrf().disable();//pour les faille csrf
        //pour angular
        http.cors().disable();

        //Pour la securite front
        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);

        //Pour la consultation de h2
        http.headers().frameOptions().disable();//pour h2


        http.authorizeRequests()
                .antMatchers("/h2-console/**", "/refreshToken/**", "/login/**")
                .permitAll()
                .antMatchers(HttpMethod.OPTIONS, "/**");//pour angular
        http.authorizeRequests().antMatchers(HttpMethod.POST, "/login").permitAll();//pour angular
        //http.authorizeRequests().antMatchers(HttpMethod.POST, "/users/**").hasAnyAuthority("ADMIN");
        //Methode 1 pour la gestion des autorisations
        /*http.authorizeRequests().antMatchers(HttpMethod.POST, "/users/**").hasAnyAuthority("ADMIN");
        http.authorizeRequests().antMatchers(HttpMethod.GET, "/users/**").hasAnyAuthority("USER");*/
        //Pour la securite backend
        //http.formLogin();

        http.authorizeRequests().anyRequest().authenticated();

        //Gestion des filters
        http.addFilter(new JwtAuthenticationFilter(authenticationManagerBean()));
        http.addFilterBefore(new JwtAuthorizationFilter(), UsernamePasswordAuthenticationFilter.class);
    }

    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }
}
