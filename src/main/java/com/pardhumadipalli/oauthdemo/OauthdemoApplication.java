package com.pardhumadipalli.oauthdemo;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import javax.servlet.http.HttpServletRequest;
import java.util.Map;

@SpringBootApplication
@RestController
public class OauthdemoApplication extends WebSecurityConfigurerAdapter {

	Logger log = LoggerFactory.getLogger(OauthdemoApplication.class);

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http
				.authorizeRequests(a -> a
						.antMatchers("/", "/error", "/webjars/**").permitAll()
						.anyRequest().authenticated()
				)
				.exceptionHandling(e -> e
						.authenticationEntryPoint(new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED))
				)
				.oauth2Login(o -> o.failureHandler((request, response, exception) -> {
					log.error("OAuth2 failure.", exception);
					request.getSession().setAttribute("error.message", exception.getMessage());
					response.sendRedirect("/");
				}));
		http.logout(l -> l.logoutSuccessUrl("/").permitAll());
		http.csrf(c -> c.csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse()));
	}

	@GetMapping("/user")
	public Map<String, Object> user(@AuthenticationPrincipal OAuth2User principal) {
		return principal.getAttributes();
	}

	@GetMapping("/error")
	public String error(HttpServletRequest request) {
		String message = (String) request.getSession().getAttribute("error.message");
		request.getSession().removeAttribute("error.message");
		return message;
	}

	public static void main(String[] args) {
		SpringApplication.run(OauthdemoApplication.class, args);
	}

}
