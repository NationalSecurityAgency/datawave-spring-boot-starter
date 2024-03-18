package datawave.microservice.authorization.federation;

import static datawave.microservice.authorization.preauth.ProxiedEntityX509Filter.ENTITIES_HEADER;
import static datawave.microservice.authorization.preauth.ProxiedEntityX509Filter.ISSUERS_HEADER;

import java.time.Duration;

import org.apache.http.HttpHeaders;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.reactive.function.client.ExchangeStrategies;
import org.springframework.web.reactive.function.client.WebClient;

import datawave.microservice.authorization.config.AuthorizationsListSupplier;
import datawave.microservice.authorization.federation.config.FederatedAuthorizationProperties;
import datawave.security.authorization.AuthorizationException;
import datawave.security.authorization.DatawaveUser;
import datawave.security.authorization.ProxiedUserDetails;
import datawave.security.authorization.UserOperations;
import datawave.user.AuthorizationsListBase;
import datawave.webservice.result.GenericResponse;

public class FederatedAuthorizationService implements UserOperations {
    private static final Logger log = LoggerFactory.getLogger(FederatedAuthorizationService.class);
    
    private FederatedAuthorizationProperties federatedAuthorizationProperties;
    private final WebClient webClient;
    private AuthorizationsListSupplier authorizationsListSupplier;
    
    public FederatedAuthorizationService(FederatedAuthorizationProperties federatedAuthorizationProperties, WebClient.Builder webClientBuilder,
                    AuthorizationsListSupplier authorizationsListSupplier) {
        this.federatedAuthorizationProperties = federatedAuthorizationProperties;
        // @formatter:off
        this.webClient = webClientBuilder
                .baseUrl(federatedAuthorizationProperties.getFederatedAuthorizationUri())
                .exchangeStrategies(ExchangeStrategies.builder()
                        .codecs(clientCodecConfigurer -> clientCodecConfigurer
                                .defaultCodecs()
                                .maxInMemorySize(federatedAuthorizationProperties.getMaxBytesToBuffer()))
                        .build())
                .build();
        // @formatter:on
        this.authorizationsListSupplier = authorizationsListSupplier;
    }
    
    private String getProxiedEntities(ProxiedUserDetails currentUser) {
        StringBuilder builder = new StringBuilder();
        for (DatawaveUser user : currentUser.getProxiedUsers()) {
            builder.append('<').append(user.getDn().subjectDN()).append('>');
        }
        return builder.toString();
    }
    
    private String getProxiedIssuers(ProxiedUserDetails currentUser) {
        StringBuilder builder = new StringBuilder();
        for (DatawaveUser user : currentUser.getProxiedUsers()) {
            builder.append('<').append(user.getDn().issuerDN()).append('>');
        }
        return builder.toString();
    }
    
    @Override
    @Cacheable(value = "getRemoteUser", key = "{#currentUser}", cacheManager = "remoteOperationsCacheManager")
    public <T extends ProxiedUserDetails> T getRemoteUser(T currentUser) throws AuthorizationException {
        return UserOperations.super.getRemoteUser(currentUser);
    }
    
    @Override
    @Cacheable(value = "listEffectiveAuthorizations", key = "{#currentUser}", cacheManager = "remoteOperationsCacheManager")
    public AuthorizationsListBase listEffectiveAuthorizations(ProxiedUserDetails currentUser) throws AuthorizationException {
        return listEffectiveAuthorizations(currentUser, true);
    }
    
    public AuthorizationsListBase listEffectiveAuthorizations(ProxiedUserDetails currentUser, boolean federate) throws AuthorizationException {
        log.info("FederatedAuthorizationService listEffectiveAuthorizations for {}", currentUser.getPrimaryUser());
        
        try {
            // @formatter:off
            ResponseEntity<AuthorizationsListBase> authorizationsListBaseResponseEntity = (ResponseEntity<AuthorizationsListBase>) webClient.get()
                    .uri(uriBuilder -> uriBuilder
                            .path("listEffectiveAuthorizations")
                            .queryParam("includeRemoteServices", federate)
                            .build())
                    .header(ENTITIES_HEADER, getProxiedEntities(currentUser))
                    .header(ISSUERS_HEADER, getProxiedIssuers(currentUser))
                    .header(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON_VALUE)
                    .retrieve()
                    .toEntity(authorizationsListSupplier.get().getClass())
                    .block(Duration.ofMillis(federatedAuthorizationProperties.getListEffectiveAuthorizationsTimeoutMillis()));
            // @formatter:on
            
            AuthorizationException authorizationException;
            if (authorizationsListBaseResponseEntity != null) {
                AuthorizationsListBase authorizationsListBase = authorizationsListBaseResponseEntity.getBody();
                
                if (authorizationsListBaseResponseEntity.getStatusCode() == HttpStatus.OK) {
                    return authorizationsListBase;
                } else {
                    authorizationException = new AuthorizationException("Unknown error occurred while calling listEffectiveAuthorizations for "
                                    + currentUser.getPrimaryUser() + ", Status Code: " + authorizationsListBaseResponseEntity.getStatusCodeValue());
                }
            } else {
                authorizationException = new AuthorizationException(
                                "Unknown error occurred while calling listEffectiveAuthorizations for " + currentUser.getPrimaryUser());
            }
            throw authorizationException;
        } catch (RuntimeException e) {
            log.error("Timed out waiting for federated listEffectiveAuthorizations response");
            throw new AuthorizationException("Timed out waiting for federated listEffectiveAuthorizations response", e);
        }
    }
    
    @Override
    public GenericResponse<String> flushCachedCredentials(ProxiedUserDetails currentUser) throws AuthorizationException {
        return flushCachedCredentials(currentUser, true);
    }
    
    public GenericResponse<String> flushCachedCredentials(ProxiedUserDetails currentUser, boolean federate) throws AuthorizationException {
        try {
            // @formatter:off
            ResponseEntity<GenericResponse> genericResponseEntity = webClient.get()
                    .uri(uriBuilder -> uriBuilder
                            .path("flushCachedCredentials")
                            .queryParam("includeRemoteServices", federate)
                            .build())
                    .header(ENTITIES_HEADER, getProxiedEntities(currentUser))
                    .header(ISSUERS_HEADER, getProxiedIssuers(currentUser))
                    .header(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON_VALUE)
                    .retrieve()
                    .toEntity(GenericResponse.class)
                    .block(Duration.ofMillis(federatedAuthorizationProperties.getFlushCachedCredentialsTimeoutMillis()));
            // @formatter:on
            
            AuthorizationException authorizationException;
            if (genericResponseEntity != null) {
                GenericResponse genericResponse = genericResponseEntity.getBody();
                
                if (genericResponseEntity.getStatusCode() == HttpStatus.OK) {
                    return genericResponse;
                } else {
                    authorizationException = new AuthorizationException("Unknown error occurred while calling flushCachedCredentials for "
                                    + currentUser.getPrimaryUser() + ", Status Code: " + genericResponseEntity.getStatusCodeValue());
                }
            } else {
                authorizationException = new AuthorizationException(
                                "Unknown error occurred while calling flushCachedCredentials for " + currentUser.getPrimaryUser());
            }
            throw authorizationException;
        } catch (RuntimeException e) {
            log.error("Timed out waiting for federated flushCachedCredentials response");
            throw new AuthorizationException("Timed out waiting for federated flushCachedCredentials response", e);
        }
    }
}
