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
package org.springframework.security.saml.provider.service.config;

import static org.springframework.security.saml.util.StringUtils.stripSlashes;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.saml.provider.config.AbstractProviderSecurityConfiguration;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;


public abstract class SamlServiceProviderSecurityConfiguration extends AbstractProviderSecurityConfiguration
{

  private static final Log log = LogFactory.getLog(SamlServiceProviderSecurityConfiguration.class);

  private SamlServiceProviderServerBeanConfiguration configuration;

  protected SamlServiceProviderSecurityConfiguration(SamlServiceProviderServerBeanConfiguration configuration)
  {
    this("saml/sp/", configuration);
  }

  protected SamlServiceProviderSecurityConfiguration(String prefix,
                                                     SamlServiceProviderServerBeanConfiguration configuration)
  {
    super(stripSlashes(prefix + "/"));
    this.configuration = configuration;
  }

  @Bean
  public SecurityFilterChain filterChain(HttpSecurity http) throws Exception
  {
    String prefix = getPrefix();

    String filterChainPattern = "/" + stripSlashes(prefix) + "/**";
    http.securityMatcher(filterChainPattern)
        .csrf()
        .disable()
        .authorizeRequests()
        .requestMatchers(filterChainPattern)
        .permitAll();

    http.addFilterAfter(getConfiguration().samlConfigurationFilter(), BasicAuthenticationFilter.class)
        .addFilterAfter(getConfiguration().spExceptionHandlerFilter(),
                        getConfiguration().samlConfigurationFilter().getClass())
        .addFilterAfter(getConfiguration().spMetadataFilter(), getConfiguration().spExceptionHandlerFilter().getClass())
        .addFilterAfter(getConfiguration().spAuthenticationRequestFilter(),
                        getConfiguration().spMetadataFilter().getClass())
        .addFilterAfter(getConfiguration().spAuthenticationResponseFilter(),
                        getConfiguration().spAuthenticationRequestFilter().getClass())
        .addFilterAfter(getConfiguration().spSamlLogoutFilter(),
                        getConfiguration().spAuthenticationResponseFilter().getClass())
        .addFilterAfter(getConfiguration().spSelectIdentityProviderFilter(),
                        getConfiguration().spSamlLogoutFilter().getClass());
    return http.build();
  }

  public SamlServiceProviderServerBeanConfiguration getConfiguration()
  {
    return configuration;
  }


}
