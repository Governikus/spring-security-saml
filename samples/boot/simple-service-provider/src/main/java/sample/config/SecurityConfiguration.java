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

package sample.config;

import static org.springframework.security.saml.provider.service.config.SamlServiceProviderSecurityDsl.serviceProvider;

import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.saml.provider.service.config.SamlServiceProviderSecurityConfiguration;
import org.springframework.security.web.SecurityFilterChain;


@EnableWebSecurity
public class SecurityConfiguration
{

  @Configuration
  @Order(1)
  public static class SamlSecurity extends SamlServiceProviderSecurityConfiguration
  {

    private AppConfig appConfig;

    public SamlSecurity(BeanConfig beanConfig, @Qualifier("appConfig") AppConfig appConfig)
    {
      super("/saml/sp/", beanConfig);
      this.appConfig = appConfig;
    }

    @Override
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception
    {
      http.apply(serviceProvider()).configure(appConfig);
      return super.filterChain(http);
    }
  }

}
