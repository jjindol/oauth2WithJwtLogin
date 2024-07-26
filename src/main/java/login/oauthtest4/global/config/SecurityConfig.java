package login.oauthtest4.global.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import login.oauthtest4.domain.user.repository.UserRepository;
import login.oauthtest4.global.jwt.filter.JwtAuthenticationProcessingFilter;
import login.oauthtest4.global.jwt.service.JwtService;
import login.oauthtest4.global.login.filter.CustomJsonUsernamePasswordAuthenticationFilter;
import login.oauthtest4.global.login.handler.LoginFailureHandler;
import login.oauthtest4.global.login.handler.LoginSuccessHandler;
import login.oauthtest4.global.login.service.LoginService;
import login.oauthtest4.global.oauth2.handler.OAuth2LoginFailureHandler;
import login.oauthtest4.global.oauth2.handler.OAuth2LoginSuccessHandler;
import login.oauthtest4.global.oauth2.service.CustomOAuth2UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.logout.LogoutFilter;


@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Autowired
    private final LoginService loginService;
    @Autowired
    private final JwtService jwtService;
    @Autowired
    private final UserRepository userRepository;
    @Autowired
    private final ObjectMapper objectMapper;
    @Autowired
    private final OAuth2LoginSuccessHandler oAuth2LoginSuccessHandler;
    @Autowired
    private final OAuth2LoginFailureHandler oAuth2LoginFailureHandler;
    @Autowired
    private final CustomOAuth2UserService customOAuth2UserService;

    public SecurityConfig(LoginService loginService, JwtService jwtService, UserRepository userRepository, ObjectMapper objectMapper, OAuth2LoginSuccessHandler oAuth2LoginSuccessHandler, OAuth2LoginFailureHandler oAuth2LoginFailureHandler, CustomOAuth2UserService customOAuth2UserService) {
        this.loginService = loginService;
        this.jwtService = jwtService;
        this.userRepository = userRepository;
        this.objectMapper = objectMapper;
        this.oAuth2LoginSuccessHandler = oAuth2LoginSuccessHandler;
        this.oAuth2LoginFailureHandler = oAuth2LoginFailureHandler;
        this.customOAuth2UserService = customOAuth2UserService;
    }


    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .formLogin().disable()
                .httpBasic().disable()
                .csrf().disable()
                .headers().frameOptions().disable()
                .and()

                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()

                .authorizeRequests()

                .antMatchers("/", "/css/**", "/images/**", "/js/**", "/favicon.ico", "/h2-console/**").permitAll()
                .antMatchers("/sign-up").permitAll()
                .anyRequest().authenticated()
                .and()

                //== 소셜 로그인 설정 ==//
                .oauth2Login()
                .successHandler(oAuth2LoginSuccessHandler)
                .failureHandler(oAuth2LoginFailureHandler)
                .userInfoEndpoint().userService(customOAuth2UserService);


        http.addFilterAfter(customJsonUsernamePasswordAuthenticationFilter(), LogoutFilter.class);
        http.addFilterBefore(jwtAuthenticationProcessingFilter(), CustomJsonUsernamePasswordAuthenticationFilter.class);

        return http.build();
    }


    @Bean
    public PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }


    @Bean
    public AuthenticationManager authenticationManager() {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setPasswordEncoder(passwordEncoder());
        provider.setUserDetailsService(loginService);
        return new ProviderManager(provider);
    }


    @Bean
    public LoginSuccessHandler loginSuccessHandler() {
        return new LoginSuccessHandler(jwtService, userRepository);
    }

    @Bean
    public LoginFailureHandler loginFailureHandler() {
        return new LoginFailureHandler();
    }

    @Bean
    public CustomJsonUsernamePasswordAuthenticationFilter customJsonUsernamePasswordAuthenticationFilter() {
        CustomJsonUsernamePasswordAuthenticationFilter customJsonUsernamePasswordLoginFilter
                = new CustomJsonUsernamePasswordAuthenticationFilter(objectMapper);
        customJsonUsernamePasswordLoginFilter.setAuthenticationManager(authenticationManager());
        customJsonUsernamePasswordLoginFilter.setAuthenticationSuccessHandler(loginSuccessHandler());
        customJsonUsernamePasswordLoginFilter.setAuthenticationFailureHandler(loginFailureHandler());
        return customJsonUsernamePasswordLoginFilter;
    }

    @Bean
    public JwtAuthenticationProcessingFilter jwtAuthenticationProcessingFilter() {
        JwtAuthenticationProcessingFilter jwtAuthenticationFilter = new JwtAuthenticationProcessingFilter(jwtService, userRepository);
        return jwtAuthenticationFilter;
    }


}
