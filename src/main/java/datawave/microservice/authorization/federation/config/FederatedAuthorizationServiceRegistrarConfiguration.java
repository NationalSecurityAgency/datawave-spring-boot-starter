package datawave.microservice.authorization.federation.config;

import org.springframework.cache.CacheManager;
import org.springframework.cache.annotation.EnableCaching;
import org.springframework.cache.caffeine.CaffeineCacheManager;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;

import datawave.microservice.authorization.federation.DynamicFederatedAuthorizationServiceBeanDefinitionRegistrar;

@EnableCaching
@Configuration
public class FederatedAuthorizationServiceRegistrarConfiguration {
    @Bean
    public static DynamicFederatedAuthorizationServiceBeanDefinitionRegistrar federatedAuthorizationServiceBeanDefinitionRegistrar(Environment environment) {
        return new DynamicFederatedAuthorizationServiceBeanDefinitionRegistrar(environment);
    }
    
    @Bean
    public CacheManager remoteOperationsCacheManager() {
        return new CaffeineCacheManager("getRemoteUser", "listEffectiveAuthorizations");
    }
}
