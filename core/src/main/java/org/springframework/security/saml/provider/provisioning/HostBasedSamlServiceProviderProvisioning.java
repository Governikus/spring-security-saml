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

import static org.springframework.util.StringUtils.hasText;

import java.util.Collections;
import java.util.LinkedList;
import java.util.List;

import org.springframework.security.saml.SamlMetadataCache;
import org.springframework.security.saml.SamlTransformer;
import org.springframework.security.saml.SamlValidator;
import org.springframework.security.saml.key.EncryptionKey;
import org.springframework.security.saml.key.SigningKey;
import org.springframework.security.saml.provider.config.SamlConfigurationRepository;
import org.springframework.security.saml.provider.service.AuthenticationRequestEnhancer;
import org.springframework.security.saml.provider.service.HostedServiceProviderService;
import org.springframework.security.saml.provider.service.config.ExternalIdentityProviderConfiguration;
import org.springframework.security.saml.provider.service.config.LocalServiceProviderConfiguration;
import org.springframework.security.saml.saml2.metadata.IdentityProviderMetadata;
import org.springframework.security.saml.saml2.metadata.ServiceProviderMetadata;


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
    String basePath = spConfig.getBasePath();
    SigningKey activeSigningKey = spConfig.isSignMetadata() ? spConfig.getSigningKeys().getActive() : null;
    List<SigningKey> signingKeys = new LinkedList<>();
    if (spConfig.getSigningKeys() != null)
    {
      signingKeys.add(activeSigningKey);
      signingKeys.addAll(spConfig.getSigningKeys().getStandBy());
    }

    List<EncryptionKey> encryptionKeys = new LinkedList<>();
    if (spConfig.getEncryptionKeys() != null)
    {
      if (spConfig.getEncryptionKeys().getActive() != null)
      {
        encryptionKeys.add(spConfig.getEncryptionKeys().getActive());
      }
      encryptionKeys.addAll(spConfig.getEncryptionKeys().getStandBy());

      encryptionKeys.forEach(e -> e.setDataEncryptionMethod(spConfig.getDataEncryptionAlgorithm()));
    }

    String prefix = hasText(spConfig.getPrefix()) ? spConfig.getPrefix() : "saml/sp/";
    String aliasPath = getAliasPath(spConfig);
    ServiceProviderMetadata metadata = serviceProviderMetadata(basePath,
                                                               activeSigningKey,
                                                               encryptionKeys,
                                                               signingKeys,
                                                               prefix,
                                                               aliasPath,
                                                               spConfig.getDefaultSigningAlgorithm(),
                                                               spConfig.getDefaultDigest());
    if (!spConfig.getNameIds().isEmpty())
    {
      metadata.getServiceProvider().setNameIds(spConfig.getNameIds());
    }

    if (!spConfig.isSingleLogoutEnabled())
    {
      metadata.getServiceProvider().setSingleLogoutService(Collections.emptyList());
    }
    if (hasText(spConfig.getEntityId()))
    {
      metadata.setEntityId(spConfig.getEntityId());
    }
    if (hasText(spConfig.getAlias()))
    {
      metadata.setEntityAlias(spConfig.getAlias());
    }
    metadata.getServiceProvider().setWantAssertionsSigned(spConfig.isWantAssertionsSigned());
    metadata.getServiceProvider().setAuthnRequestsSigned(spConfig.isSignRequests());

    return new HostedServiceProviderService(spConfig, metadata, getTransformer(), getValidator(), getCache(),
                                            authnRequestEnhancer);
  }
}
