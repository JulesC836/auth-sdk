package io.github.photondev.authsdk.config;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;

@Configuration
@ComponentScan(basePackages = {"io.github.photondev.authsdk.service", "io.github.photondev.authsdk.config.utils"})
@EnableJpaRepositories(basePackages = "io.github.photondev.authsdk.repository")
@EnableConfigurationProperties(SecurityProperties.class)
public class SdkConfig {

}
