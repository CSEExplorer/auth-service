package com.bookify.auth_service.authn.admin.oauth.service;

import com.bookify.auth_service.authn.admin.oauth.dto.ClientRegistrationRequest;
import com.bookify.auth_service.authn.user.oauth.Internal.config.RegisteredClientAdapter;
import com.bookify.auth_service.authn.user.oauth.Internal.entity.OAuth2Client;
import com.bookify.auth_service.authn.user.oauth.Internal.repository.OAuth2ClientRepository;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Map;

@Service
@Transactional
public class ClientAdminService {

    private final OAuth2ClientRepository clientRepository;

    ClientAdminService(OAuth2ClientRepository clientRepository){
         this.clientRepository = clientRepository;

    }
    public List<OAuth2Client> listClients() {
        return clientRepository.findAll();
    }

    public OAuth2Client createClient(ClientRegistrationRequest request) throws JsonProcessingException {
        // Here also add the token setting

        OAuth2Client client = new OAuth2Client();
        client.setClientId(request.getClientId());
        client.setClientSecret(request.getClientSecret());
        client.setClientName(request.getClientName());
        //request.getRedirectUris().toString()  here not secure to save to string ->
        // since it may break if null comes so chekc for the null entry if null then keep ""

        if (request.getGrantTypes().contains("authorization_code")) {
            if (request.getRedirectUris() == null || request.getRedirectUris().isEmpty()) {
                throw new IllegalArgumentException("Redirect URIs are required for authorization_code grant type");
            }
            client.setRedirectUris(String.join(",", request.getRedirectUris()));
        } else {
            // not needed for client_credentials or password grant
            client.setRedirectUris(null);
        }
//        client.setRedirectUris(request.getRedirectUris().toString());
        client.setGrantTypes(String.join(",", request.getGrantTypes()));
        client.setScopes(String.join(",", request.getScopes()));
        client.setClientAuthMethod(request.getClientAuthMethod());
        client.setActive(true);

        ObjectMapper mapper = new ObjectMapper();

        if (request.getTokenSettings() != null) {
            // Convert the object to JSON string
            String tokenSettingsJson = mapper.writeValueAsString(request.getTokenSettings());
            client.setTokenSettings(tokenSettingsJson);
        } else {
            // Save default settings as JSON
            Map<String, Object> defaultSettings = Map.of(
                    "accessTokenTimeToLive", 3600L,
                    "refreshTokenTimeToLive", 2592000L,
                    "reuseRefreshTokens", true
            );
            client.setTokenSettings(mapper.writeValueAsString(defaultSettings));
        }



        return clientRepository.save(client);
    }

    public void deleteClient(String clientId) {
        clientRepository.deleteByClientId(clientId);
    }

    // If you ever need to expose a RegisteredClient for testing:
    public RegisteredClient getRegisteredClient(String clientId) {
        return clientRepository.findByClientId(clientId)
                .map(client -> RegisteredClientAdapter.toRegisteredClient(client, null))
                .orElse(null);
    }
}

