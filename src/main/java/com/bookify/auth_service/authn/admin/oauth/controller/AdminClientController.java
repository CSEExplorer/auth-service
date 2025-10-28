package com.bookify.auth_service.authn.admin.oauth.controller;


import com.bookify.auth_service.authn.admin.oauth.dto.ClientRegistrationRequest;
import com.bookify.auth_service.authn.admin.oauth.service.ClientAdminService;
import com.bookify.auth_service.authn.user.oauth.Internal.entity.OAuth2Client;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/admin/clients")
public class AdminClientController {
    private final ClientAdminService clientAdminService;

    public AdminClientController(ClientAdminService clientAdminService) {
        this.clientAdminService = clientAdminService;
    }

    @PostMapping
    public ResponseEntity<OAuth2Client> registerClient(@RequestBody ClientRegistrationRequest request) {
        return ResponseEntity.ok(clientAdminService.createClient(request));
    }

    @GetMapping
    public ResponseEntity<Iterable<OAuth2Client>> listClients() {
        return ResponseEntity.ok(clientAdminService.listClients());
    }
    @DeleteMapping("/{clientId}")
    public ResponseEntity<Void> deleteClient(@PathVariable String clientId) {
        clientAdminService.deleteClient(clientId);
        return ResponseEntity.noContent().build();
    }
}
