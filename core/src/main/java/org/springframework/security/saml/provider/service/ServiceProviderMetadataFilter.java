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

package org.springframework.security.saml.provider.service;

import org.springframework.security.saml.provider.SamlMetadataFilter;
import org.springframework.security.saml.provider.provisioning.SamlProviderProvisioning;
import org.springframework.security.saml.provider.service.config.ExternalIdentityProviderConfiguration;
import org.springframework.security.saml.provider.service.config.LocalServiceProviderConfiguration;
import org.springframework.security.saml.saml2.metadata.IdentityProviderMetadata;
import org.springframework.security.saml.saml2.metadata.ServiceProviderMetadata;
import org.springframework.security.web.util.matcher.RequestMatcher;


public class ServiceProviderMetadataFilter extends
  SamlMetadataFilter<HostedServiceProviderService, LocalServiceProviderConfiguration, ServiceProviderMetadata, IdentityProviderMetadata, ExternalIdentityProviderConfiguration>
{

  public ServiceProviderMetadataFilter(SamlProviderProvisioning<HostedServiceProviderService, LocalServiceProviderConfiguration, ServiceProviderMetadata, IdentityProviderMetadata, ExternalIdentityProviderConfiguration> provisioning)
  {
    this(provisioning, "saml-sp-metadata.xml");
  }

  public ServiceProviderMetadataFilter(SamlProviderProvisioning<HostedServiceProviderService, LocalServiceProviderConfiguration, ServiceProviderMetadata, IdentityProviderMetadata, ExternalIdentityProviderConfiguration> provisioning,
                                       String filename)
  {
    super(provisioning, filename);
  }

  public ServiceProviderMetadataFilter(SamlProviderProvisioning<HostedServiceProviderService, LocalServiceProviderConfiguration, ServiceProviderMetadata, IdentityProviderMetadata, ExternalIdentityProviderConfiguration> provisioning,
                                       RequestMatcher requestMatcher,
                                       String filename)
  {
    super(provisioning, requestMatcher, filename);
  }
}
