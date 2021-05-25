package com.jwt.jwt.security;

import com.jwt.jwt.auth.ApplicationUserService;
import com.jwt.jwt.jwt.JwtUsernameAndPasswordAuthenticationFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import java.util.concurrent.TimeUnit;

import static com.jwt.jwt.security.ApplicationUserRole.*;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class ApplicationSecurityConfig extends WebSecurityConfigurerAdapter {

    private final PasswordEncoder passwordEncoder;
    private final ApplicationUserService applicationUserService;

    @Autowired
    public ApplicationSecurityConfig(PasswordEncoder passwordEncoder, ApplicationUserService applicationUserService) {
        this.passwordEncoder = passwordEncoder;
        this.applicationUserService = applicationUserService;
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
         http
//                 .csrf().csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
//                 .and()
                 .csrf().disable()
                 .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                 .and()
                 .addFilter(new JwtUsernameAndPasswordAuthenticationFilter(authenticationManager()))
                 .authorizeRequests()
                 .antMatchers("/","index","/css/*", "/js/*").permitAll()
                 .antMatchers("/api/**").hasRole(STUDENT.name())
//                  .antMatchers(HttpMethod.DELETE,"/management/api/**").hasAuthority(COURSE_WRITE.getPermission())
//                  .antMatchers(HttpMethod.POST,"/management/api/**").hasAuthority(COURSE_WRITE.getPermission())
//                  .antMatchers(HttpMethod.PUT,"/management/api/**").hasAuthority(COURSE_WRITE.getPermission())
//                  .antMatchers(HttpMethod.GET,"/management/api/**").hasAnyRole(ADMIN.name(), ADMINTRAINEE.name())
                 .anyRequest()
                 .authenticated();
//                 .and()
//                 .formLogin()
//                 .loginPage("/login").permitAll()
//                 .defaultSuccessUrl("/courses", true)
//                 .and()
//                 .rememberMe()
//                 .tokenValiditySeconds((int) TimeUnit.DAYS.toSeconds(21))
//                 .key("somethingverysecured")
//                 .and()
//                 .logout()
//                  .logoutUrl("/logout")
//                 .logoutRequestMatcher(new AntPathRequestMatcher("/logout", "GET"))
//                   .clearAuthentication(true)
//                    .invalidateHttpSession(true)
//                   .deleteCookies("JSESSIONID", "remember-me")
//                 .logoutSuccessUrl("/login");
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.authenticationProvider(daoAuthenticationProvider());
    }

    @Bean
    public DaoAuthenticationProvider daoAuthenticationProvider(){
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setPasswordEncoder(passwordEncoder);
        provider.setUserDetailsService(applicationUserService);
        return provider;
    }



}
