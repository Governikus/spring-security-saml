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

package org.springframework.security.saml.provider.provisioning;

import static org.springframework.security.saml.saml2.metadata.Binding.POST;
import static org.springframework.security.saml.saml2.metadata.Binding.REDIRECT;
import static org.springframework.util.StringUtils.hasText;

import java.util.Collections;
import java.util.List;
import java.util.UUID;

import org.springframework.security.saml.SamlMetadataCache;
import org.springframework.security.saml.SamlTransformer;
import org.springframework.security.saml.SamlValidator;
import org.springframework.security.saml.key.SigningKey;
import org.springframework.security.saml.provider.config.SamlConfigurationRepository;
import org.springframework.security.saml.provider.service.AuthenticationRequestEnhancer;
import org.springframework.security.saml.provider.service.HostedServiceProviderService;
import org.springframework.security.saml.provider.service.config.ExternalIdentityProviderConfiguration;
import org.springframework.security.saml.provider.service.config.LocalServiceProviderConfiguration;
import org.springframework.security.saml.saml2.metadata.IdentityProviderMetadata;
import org.springframework.security.saml.saml2.metadata.NameId;
import org.springframework.security.saml.saml2.metadata.ServiceProvider;
import org.springframework.security.saml.saml2.metadata.ServiceProviderMetadata;
import org.springframework.util.CollectionUtils;


public class HostBasedSamlServiceProviderProvisioning extends AbstractHostbasedSamlProviderProvisioning implements
  SamlProviderProvisioning<HostedServiceProviderService, LocalServiceProviderConfiguration, ServiceProviderMetadata, IdentityProviderMetadata, ExternalIdentityProviderConfiguration>
{

  private final AuthenticationRequestEnhancer authnRequestEnhancer;

  public HostBasedSamlServiceProviderProvisioning(SamlConfigurationRepository configuration,
                                                  SamlTransformer transformer,
                                                  SamlValidator validator,
                                                  SamlMetadataCache cache,
                                                  AuthenticationRequestEnhancer authnRequestEnhancer)
  {
    super(configuration, transformer, validator, cache);
    this.authnRequestEnhancer = authnRequestEnhancer;
  }

  @Override
  public HostedServiceProviderService getHostedProvider()
  {
    LocalServiceProviderConfiguration config = getConfigurationRepository().getServerConfiguration()
                                                                           .getServiceProvider();
    return getHostedServiceProvider(config);
  }

  @Override
  protected HostedServiceProviderService getHostedServiceProvider(LocalServiceProviderConfiguration spConfig)
  {
    ServiceProviderMetadata metadata = serviceProviderMetadata(spConfig);

    return new HostedServiceProviderService(spConfig, metadata, getTransformer(), getValidator(), getCache(),
                                            authnRequestEnhancer);
  }

  protected ServiceProviderMetadata serviceProviderMetadata(LocalServiceProviderConfiguration spConfig)
  {
    String baseUrl = spConfig.getBasePath();
    SigningKey activeSigningKey = spConfig.isSignMetadata() ? spConfig.getSigningKeys().getActive() : null;

    ServiceProviderMetadata metadata = new ServiceProviderMetadata();
    metadata.setEntityId(hasText(spConfig.getEntityId()) ? spConfig.getEntityId() : baseUrl)
            .setId("SPM" + UUID.randomUUID())
            .setSigningKey(activeSigningKey, spConfig.getDefaultSigningAlgorithm(), spConfig.getDefaultDigest())
            .setProviders(List.of(serviceProvider(spConfig, baseUrl)));

    if (hasText(spConfig.getAlias()))
    {
      metadata.setEntityAlias(spConfig.getAlias());
    }

    return metadata;
  }

  protected ServiceProvider serviceProvider(LocalServiceProviderConfiguration spConfig, String baseUrl)
  {
    String prefix = hasText(spConfig.getPrefix()) ? spConfig.getPrefix() : "saml/sp/";
    String aliasPath = getAliasPath(spConfig);

    ServiceProvider sp = new ServiceProvider();

    sp.setWantAssertionsSigned(spConfig.isWantAssertionsSigned())
      .setAuthnRequestsSigned(spConfig.isSignRequests())
      .setEncryptionKeys(getEncryptionKeys(spConfig.getEncryptionKeys(), spConfig.getDataEncryptionAlgorithm()))
      .setSigningKeys(getSigningKeys(spConfig.getSigningKeys()));

    if (CollectionUtils.isEmpty(spConfig.getAssertionConsumerServices()))
    {
      sp.setAssertionConsumerService(List.of(getEndpoint(baseUrl, prefix + "SSO/alias/" + aliasPath, POST, 0, true),
                                             getEndpoint(baseUrl,
                                                         prefix + "SSO/alias/" + aliasPath,
                                                         REDIRECT,
                                                         1,
                                                         false)));
    }
    else
    {
      sp.setAssertionConsumerService(spConfig.getAssertionConsumerServices());
    }

    if (spConfig.getNameIds().isEmpty())
    {
      sp.setNameIds(List.of(NameId.PERSISTENT, NameId.EMAIL));
    }
    else
    {
      sp.setNameIds(spConfig.getNameIds());
    }

    if (spConfig.isSingleLogoutEnabled())
    {
      sp.setSingleLogoutService(List.of(getEndpoint(baseUrl, prefix + "logout/alias/" + aliasPath, REDIRECT, 0, true)));
    }
    else
    {
      sp.setSingleLogoutService(Collections.emptyList());
    }

    if (!CollectionUtils.isEmpty(spConfig.getManageNameIdServices()))
    {
      sp.setManageNameIDService(spConfig.getManageNameIdServices());
    }

    return sp;
  }

}
