package br.com.avelar.client.security;

import java.util.Arrays;
import java.util.List;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.oauth2.client.InMemoryOAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
             .authorizeRequests()
             .antMatchers("/logout.xhtml").permitAll()
             .anyRequest().authenticated()
         .and()
         .oauth2Login()
             .loginPage("http://vigilante.vm/oauth-client/oauth2/authorization/self")
             .clientRegistrationRepository(clientRegistrationRepository())
             .authorizedClientService(authorizedClientService())
         .and()
             .logout()
             .logoutSuccessHandler(
                     new RedirectLogoutSuccessHandler("http://vigilante.vm/provider/logout"));
    }

    @Bean
    public OAuth2AuthorizedClientService authorizedClientService() {
        return new InMemoryOAuth2AuthorizedClientService(clientRegistrationRepository());
    }

    @Bean
    public ClientRegistrationRepository clientRegistrationRepository() {
        List<ClientRegistration> registrations = Arrays.asList(getRegistration());
        return new InMemoryClientRegistrationRepository(registrations);
    }

    private ClientRegistration getRegistration() {
        ClientRegistration.Builder builder = ClientRegistration.withRegistrationId("self");
        builder.clientAuthenticationMethod(ClientAuthenticationMethod.BASIC);
        builder.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE);
        builder.authorizationUri("http://127.0.0.1:8080/provider/oauth/authorize");
        builder.tokenUri("http://127.0.0.1:8080/provider/oauth/token");
        builder.clientId("trusted");
        builder.clientSecret("secret");
        builder.redirectUriTemplate("{baseUrl}/login/oauth2/code/{registrationId}");
        builder.scope("read", "write");
        builder.userInfoUri("http://127.0.0.1:8080/provider/oauth/user");
        builder.userNameAttributeName("username");
        builder.clientName("self");

        return builder.build();
    }

}
