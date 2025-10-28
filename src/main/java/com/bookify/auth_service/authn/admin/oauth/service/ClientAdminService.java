package com.bookify.auth_service.authn.admin.oauth.service;

import com.bookify.auth_service.authn.admin.oauth.dto.ClientRegistrationRequest;
import com.bookify.auth_service.authn.user.oauth.Internal.config.RegisteredClientAdapter;
import com.bookify.auth_service.authn.user.oauth.Internal.entity.OAuth2Client;
import com.bookify.auth_service.authn.user.oauth.Internal.repository.OAuth2ClientRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
@RequiredArgsConstructor
public class ClientAdminService {

    private final OAuth2ClientRepository clientRepository;
    private final RegisteredClientAdapter adapter;

    public List<OAuth2Client> listClients() {
        return clientRepository.findAll();
    }

    public OAuth2Client createClient(ClientRegistrationRequest request) {
        OAuth2Client client = new OAuth2Client();
        client.setClientId(request.getClientId());
        client.setClientSecret(request.getClientSecret());
        client.setClientName(request.getClientName());
        client.setRedirectUris(request.getRedirectUris().toString());
        client.setGrantTypes(String.join(",", request.getGrantTypes()));
        client.setScopes(String.join(",", request.getScopes()));
        client.setClientAuthMethod(request.getClientAuthMethod());
        client.setActive(true);
        return clientRepository.save(client);
    }

    public void deleteClient(String clientId) {
        clientRepository.deleteByClientId(clientId);
    }

    // If you ever need to expose a RegisteredClient for testing:
    public RegisteredClient getRegisteredClient(String clientId) {
        return clientRepository.findByClientId(clientId)
                .map(client -> adapter.toRegisteredClient(client, null))
                .orElse(null);
    }
}

