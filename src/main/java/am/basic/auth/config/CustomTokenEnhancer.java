package am.basic.auth.config;


import am.basic.auth.model.Role;
import am.basic.auth.repsoitory.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.TokenEnhancer;
import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

@Component
public class CustomTokenEnhancer implements TokenEnhancer {

    @Autowired
    private UserRepository userRepository;

    @Override
    public OAuth2AccessToken enhance(OAuth2AccessToken accessToken, OAuth2Authentication authentication) {

        User oauthUser = (User) authentication.getPrincipal();
        final Map<String, Object> additionalInfo = new HashMap<>();


        Optional<am.basic.auth.model.User> userOptional = userRepository.getByUsername(oauthUser.getUsername());

        if (userOptional.isPresent()) {
            am.basic.auth.model.User user = userOptional.get();
            additionalInfo.put("userId", user.getId());
            additionalInfo.put("username", user.getUsername());
            additionalInfo.put("name", user.getName());
            additionalInfo.put("surname", user.getSurname());
            additionalInfo.put("roles", user.getRoles().stream().map(Role::getName).collect(Collectors.toSet()));

            ((DefaultOAuth2AccessToken) accessToken).setAdditionalInformation(additionalInfo);
        }


        return accessToken;
    }

}
