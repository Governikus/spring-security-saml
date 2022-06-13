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
import org.springframework.security.saml.provider.identity.AssertionEnhancer;
import org.springframework.security.saml.provider.identity.HostedIdentityProviderService;
import org.springframework.security.saml.provider.identity.ResponseEnhancer;
import org.springframework.security.saml.provider.identity.config.ExternalServiceProviderConfiguration;
import org.springframework.security.saml.provider.identity.config.LocalIdentityProviderConfiguration;
import org.springframework.security.saml.saml2.metadata.IdentityProvider;
import org.springframework.security.saml.saml2.metadata.IdentityProviderMetadata;
import org.springframework.security.saml.saml2.metadata.NameId;
import org.springframework.security.saml.saml2.metadata.ServiceProviderMetadata;
import org.springframework.util.CollectionUtils;


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
    IdentityProviderMetadata metadata = identityProviderMetadata(idpConfig);

    return new HostedIdentityProviderService(idpConfig, metadata, getTransformer(), getValidator(), getCache(),
                                             assertionEnhancer, responseEnhancer);
  }

  protected IdentityProviderMetadata identityProviderMetadata(LocalIdentityProviderConfiguration idpConfig)
  {
    String baseUrl = idpConfig.getBasePath();
    SigningKey activeSigningKey = idpConfig.isSignMetadata() ? idpConfig.getSigningKeys().getActive() : null;

    IdentityProviderMetadata metadata = new IdentityProviderMetadata();
    metadata.setEntityId(hasText(idpConfig.getEntityId()) ? idpConfig.getEntityId() : baseUrl)
            .setId("IDPM" + UUID.randomUUID())
            .setSigningKey(activeSigningKey, idpConfig.getDefaultSigningAlgorithm(), idpConfig.getDefaultDigest())
            .setProviders(List.of(identityProvider(idpConfig, baseUrl)));

    if (hasText(idpConfig.getAlias()))
    {
      metadata.setEntityAlias(idpConfig.getAlias());
    }

    return metadata;
  }

  protected IdentityProvider identityProvider(LocalIdentityProviderConfiguration idpConfig, String baseUrl)
  {
    IdentityProvider idp = new IdentityProvider();
    idp.setWantAuthnRequestsSigned(idpConfig.isWantRequestsSigned())
       .setEncryptionKeys(getEncryptionKeys(idpConfig.getEncryptionKeys(), idpConfig.getDataEncryptionAlgorithm()))
       .setSigningKeys(getSigningKeys(idpConfig.getSigningKeys()));

    String prefix = hasText(idpConfig.getPrefix()) ? idpConfig.getPrefix() : "saml/idp/";
    String aliasPath = getAliasPath(idpConfig);

    if (CollectionUtils.isEmpty(idpConfig.getSingleSignOnServices()))
    {
      idp.setSingleSignOnService(List.of(getEndpoint(baseUrl, prefix + "SSO/alias/" + aliasPath, POST, 0, true),
                                         getEndpoint(baseUrl, prefix + "SSO/alias/" + aliasPath, REDIRECT, 1, false)));
    }
    else
    {
      idp.setSingleSignOnService(idpConfig.getSingleSignOnServices());
    }

    if (idpConfig.getNameIds().isEmpty())
    {
      idp.setNameIds(List.of(NameId.PERSISTENT, NameId.EMAIL));
    }
    else
    {
      idp.setNameIds(idpConfig.getNameIds());
    }

    if (idpConfig.isSingleLogoutEnabled())
    {
      idp.setSingleLogoutService(List.of(getEndpoint(baseUrl,
                                                     prefix + "logout/alias/" + aliasPath,
                                                     REDIRECT,
                                                     0,
                                                     true)));
    }
    else
    {
      idp.setSingleLogoutService(Collections.emptyList());
    }

    if (!CollectionUtils.isEmpty(idpConfig.getAttributes()))
    {
      idp.setAttribute(idpConfig.getAttributes());
    }

    return idp;
  }

}

