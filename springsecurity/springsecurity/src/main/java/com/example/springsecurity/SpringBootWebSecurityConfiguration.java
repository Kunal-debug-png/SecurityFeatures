package com.example.springsecurity;

import org.springframework.beans.factory.annotation.Autowired;
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
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.config.annotation.web.configurers.PasswordManagementConfigurer;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import javax.sql.DataSource;

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
                ((AuthorizeHttpRequestsConfigurer.AuthorizedUrl)requests.requestMatchers("/h2-console/**").permitAll().anyRequest()).authenticated();
            });
            //http.formLogin(Customizer.withDefaults());
            http.httpBasic(Customizer.withDefaults());
            http.headers(headers->
                    headers.frameOptions(frameOptions -> frameOptions.sameOrigin()));
            http.csrf(csrf->csrf.disable());
            return http.build();
        }
        @Autowired
        DataSource dataSource;
        @Bean
        public UserDetailsService userDetailsService() {
            UserDetails user1 = User.withUsername("user1")
                    .password(passwordEncoder().encode("userpassword"))
                    .roles("USER")
                    .build();

            UserDetails admin = User.withUsername("admin")
                    .password(passwordEncoder().encode("adminpassword"))
                    .roles("ADMIN")
                    .build();
            JdbcUserDetailsManager userDetailsManager=new JdbcUserDetailsManager(dataSource);
            userDetailsManager.createUser(user1);
            userDetailsManager.createUser(admin);
           return userDetailsManager;
        }
        @Bean
        public PasswordEncoder passwordEncoder(){
            return new BCryptPasswordEncoder();
        }
    }
}
