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
import org.springframework.security.saml.provider.identity.AssertionEnhancer;
import org.springframework.security.saml.provider.identity.HostedIdentityProviderService;
import org.springframework.security.saml.provider.identity.ResponseEnhancer;
import org.springframework.security.saml.provider.identity.config.ExternalServiceProviderConfiguration;
import org.springframework.security.saml.provider.identity.config.LocalIdentityProviderConfiguration;
import org.springframework.security.saml.saml2.metadata.IdentityProviderMetadata;
import org.springframework.security.saml.saml2.metadata.ServiceProviderMetadata;


public class HostBasedSamlIdentityProviderProvisioning extends AbstractHostbasedSamlProviderProvisioning implements
  SamlProviderProvisioning<HostedIdentityProviderService, LocalIdentityProviderConfiguration, IdentityProviderMetadata, ServiceProviderMetadata, ExternalServiceProviderConfiguration>
{


  private AssertionEnhancer assertionEnhancer;

  private ResponseEnhancer responseEnhancer;

  public HostBasedSamlIdentityProviderProvisioning(SamlConfigurationRepository configuration,
                                                   SamlTransformer transformer,
                                                   SamlValidator validator,
                                                   SamlMetadataCache cache,
                                                   AssertionEnhancer assertionEnhancer,
                                                   ResponseEnhancer responseEnhancer)
  {
    super(configuration, transformer, validator, cache);
    this.assertionEnhancer = assertionEnhancer;
    this.responseEnhancer = responseEnhancer;
  }


  @Override
  public HostedIdentityProviderService getHostedProvider()
  {
    LocalIdentityProviderConfiguration config = getConfigurationRepository().getServerConfiguration()
                                                                            .getIdentityProvider();
    return getHostedIdentityProvider(config);
  }

  @Override
  protected HostedIdentityProviderService getHostedIdentityProvider(LocalIdentityProviderConfiguration idpConfig)
  {
    String basePath = idpConfig.getBasePath();
    SigningKey activeSigningKey = idpConfig.isSignMetadata() ? idpConfig.getSigningKeys().getActive() : null;
    List<SigningKey> signingKeys = new LinkedList<>();
    if (idpConfig.getSigningKeys() != null)
    {
      signingKeys.add(activeSigningKey);
      signingKeys.addAll(idpConfig.getSigningKeys().getStandBy());
    }

    List<EncryptionKey> encryptionKeys = new LinkedList<>();
    if (idpConfig.getEncryptionKeys() != null)
    {
      if (idpConfig.getEncryptionKeys().getActive() != null)
      {
        encryptionKeys.add(idpConfig.getEncryptionKeys().getActive());
      }
      encryptionKeys.addAll(idpConfig.getEncryptionKeys().getStandBy());

      encryptionKeys.forEach(e -> e.setDataEncryptionMethod(idpConfig.getDataEncryptionAlgorithm()));
    }

    String prefix = hasText(idpConfig.getPrefix()) ? idpConfig.getPrefix() : "saml/idp/";
    String aliasPath = getAliasPath(idpConfig);

    IdentityProviderMetadata metadata = identityProviderMetadata(basePath,
                                                                 activeSigningKey,
                                                                 encryptionKeys,
                                                                 signingKeys,
                                                                 prefix,
                                                                 aliasPath,
                                                                 idpConfig.getDefaultSigningAlgorithm(),
                                                                 idpConfig.getDefaultDigest());

    if (!idpConfig.getNameIds().isEmpty())
    {
      metadata.getIdentityProvider().setNameIds(idpConfig.getNameIds());
    }

    if (!idpConfig.isSingleLogoutEnabled())
    {
      metadata.getIdentityProvider().setSingleLogoutService(Collections.emptyList());
    }
    if (hasText(idpConfig.getEntityId()))
    {
      metadata.setEntityId(idpConfig.getEntityId());
    }
    if (hasText(idpConfig.getAlias()))
    {
      metadata.setEntityAlias(idpConfig.getAlias());
    }

    metadata.getIdentityProvider().setWantAuthnRequestsSigned(idpConfig.isWantRequestsSigned());

    return new HostedIdentityProviderService(idpConfig, metadata, getTransformer(), getValidator(), getCache(),
                                             assertionEnhancer, responseEnhancer);
  }


}

