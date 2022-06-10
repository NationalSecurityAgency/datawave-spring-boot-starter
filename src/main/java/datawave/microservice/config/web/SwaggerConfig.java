package datawave.microservice.config.web;

import io.swagger.v3.oas.models.ExternalDocumentation;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.info.License;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Configuration to generate Swagger documentation for REST endpoints.
 */
@Configuration
public class SwaggerConfig {
    @Bean
    public OpenAPI springDocsOpenAPI(@Value("${spring.application.name}") String appName) {
        return new OpenAPI()
                        .info(new Info().title(appName + " API").description("REST operations provided by the " + appName + " API")
                                        .version(SwaggerConfig.class.getPackage().getImplementationVersion())
                                        .license(new License().name("Apache License 2.0").url("https://www.apache.org/licenses/LICENSE-2.0")))
                        .externalDocs(new ExternalDocumentation().description("Additional documentation available on GitHub")
                                        .url("https://github.com/NationalSecurityAgency/datawave"));
    }
}
