/*
 * Copyright 2002-2018 the original author or authors.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * https://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.saml.provider.identity.config;

import static org.springframework.security.saml.util.StringUtils.stripSlashes;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.saml.provider.config.AbstractProviderSecurityConfiguration;
import org.springframework.security.web.SecurityFilterChain;


public abstract class SamlIdentityProviderSecurityConfiguration extends AbstractProviderSecurityConfiguration
{

  private static final Log log = LogFactory.getLog(SamlIdentityProviderSecurityConfiguration.class);

  private final SamlIdentityProviderServerBeanConfiguration configuration;

  protected SamlIdentityProviderSecurityConfiguration(SamlIdentityProviderServerBeanConfiguration configuration)
  {
    this("saml/idp/", configuration);
  }

  protected SamlIdentityProviderSecurityConfiguration(String prefix,
                                                      SamlIdentityProviderServerBeanConfiguration configuration)
  {
    super(stripSlashes(prefix + "/"));
    this.configuration = configuration;
  }

  @Bean
  public SecurityFilterChain filterChain(HttpSecurity http) throws Exception
  {
    String filterChainPattern = "/" + stripSlashes(getPrefix()) + "/**";
    log.info("Configuring SAML IDP on pattern:" + filterChainPattern);
    http.securityMatcher(filterChainPattern)
        .csrf()
        .disable()
        .authorizeRequests()
        .requestMatchers("/metadata")
        .permitAll()
        .requestMatchers("/**")
        .authenticated();
    return http.build();
  }

  public SamlIdentityProviderServerBeanConfiguration getConfiguration()
  {
    return configuration;
  }
}
