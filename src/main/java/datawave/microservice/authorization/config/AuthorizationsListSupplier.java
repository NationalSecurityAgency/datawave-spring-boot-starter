package datawave.microservice.authorization.config;

import java.util.function.Supplier;

import org.springframework.stereotype.Component;

import datawave.user.AuthorizationsListBase;
import datawave.user.DefaultAuthorizationsList;

@Component
public class AuthorizationsListSupplier implements Supplier<AuthorizationsListBase<?>> {
    @Override
    public AuthorizationsListBase<?> get() {
        return new DefaultAuthorizationsList();
    }
}
