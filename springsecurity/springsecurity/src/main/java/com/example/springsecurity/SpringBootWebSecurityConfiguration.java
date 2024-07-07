package com.example.springsecurity;

import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication.Type;
import org.springframework.boot.autoconfigure.security.ConditionalOnDefaultWebSecurity;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AuthorizeHttpRequestsConfigurer;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@Configuration(proxyBeanMethods = false)
@ConditionalOnWebApplication(type = Type.SERVLET)
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class SpringBootWebSecurityConfiguration {

    @Configuration(proxyBeanMethods = false)
    @ConditionalOnMissingBean(name = {"springSecurityFilterChain"})
    @ConditionalOnClass({EnableWebSecurity.class})
    static class WebSecurityEnablerConfiguration {
        WebSecurityEnablerConfiguration() {
        }
    }

    @Configuration(proxyBeanMethods = false)
    @ConditionalOnDefaultWebSecurity
    static class SecurityFilterChainConfiguration {
        SecurityFilterChainConfiguration() {
        }

        @Bean
        @Order(2147483642)
        SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
            http.authorizeHttpRequests((requests) -> {
                ((AuthorizeHttpRequestsConfigurer.AuthorizedUrl)requests.anyRequest()).authenticated();
            });
            http.formLogin(Customizer.withDefaults());
            http.httpBasic(Customizer.withDefaults());
            return http.build();
        }

        @Bean
        public UserDetailsService userDetailsService() {
            UserDetails user1 = User.withUsername("user1")
                    .password("{bcrypt}$2a$10$W6L2LJzLO71kZc1sJ1MnRuyVRBj8BLy3jM/qdLdzeAGZaEHq6kk1W") // bcrypt("userpassword")
                    .roles("USER")
                    .build();

            UserDetails admin = User.withUsername("admin")
                    .password("{bcrypt}$2a$10$W6L2LJzLO71kZc1sJ1MnRuyVRBj8BLy3jM/qdLdzeAGZaEHq6kk1W") // bcrypt("adminpassword")
                    .roles("ADMIN")
                    .build();

            return new InMemoryUserDetailsManager(user1, admin);
        }
    }
}
