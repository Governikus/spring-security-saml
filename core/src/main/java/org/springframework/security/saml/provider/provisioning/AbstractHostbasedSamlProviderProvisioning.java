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

import java.nio.charset.StandardCharsets;
import java.util.LinkedList;
import java.util.List;

import org.springframework.security.saml.SamlMetadataCache;
import org.springframework.security.saml.SamlTransformer;
import org.springframework.security.saml.SamlValidator;
import org.springframework.security.saml.key.EncryptionKey;
import org.springframework.security.saml.key.SigningKey;
import org.springframework.security.saml.provider.config.LocalProviderConfiguration;
import org.springframework.security.saml.provider.config.RotatingEncryptionKeys;
import org.springframework.security.saml.provider.config.RotatingSigningKeys;
import org.springframework.security.saml.provider.config.SamlConfigurationRepository;
import org.springframework.security.saml.provider.identity.IdentityProviderService;
import org.springframework.security.saml.provider.identity.config.LocalIdentityProviderConfiguration;
import org.springframework.security.saml.provider.service.ServiceProviderService;
import org.springframework.security.saml.provider.service.config.LocalServiceProviderConfiguration;
import org.springframework.security.saml.saml2.encrypt.DataEncryptionMethod;
import org.springframework.security.saml.saml2.metadata.Binding;
import org.springframework.security.saml.saml2.metadata.Endpoint;
import org.springframework.web.util.UriComponentsBuilder;
import org.springframework.web.util.UriUtils;


public abstract class AbstractHostbasedSamlProviderProvisioning
{

  private final SamlConfigurationRepository configuration;

  private final SamlTransformer transformer;

  private final SamlValidator validator;

  private final SamlMetadataCache cache;

  public AbstractHostbasedSamlProviderProvisioning(SamlConfigurationRepository configuration,
                                                   SamlTransformer transformer,
                                                   SamlValidator validator,
                                                   SamlMetadataCache cache)
  {
    this.configuration = configuration;
    this.transformer = transformer;
    this.validator = validator;
    this.cache = cache;
  }

  public SamlConfigurationRepository getConfigurationRepository()
  {
    return configuration;
  }

  public SamlTransformer getTransformer()
  {
    return transformer;
  }

  public SamlValidator getValidator()
  {
    return validator;
  }

  public SamlMetadataCache getCache()
  {
    return cache;
  }

  protected IdentityProviderService getHostedIdentityProvider(LocalIdentityProviderConfiguration idpConfig)
  {
    return null;
  }

  protected ServiceProviderService getHostedServiceProvider(LocalServiceProviderConfiguration spConfig)
  {
    return null;
  }

  protected String getAliasPath(LocalProviderConfiguration<?, ?> configuration)
  {
    return hasText(configuration.getAlias())
      ? UriUtils.encode(configuration.getAlias(), StandardCharsets.ISO_8859_1.name())
      : UriUtils.encode(configuration.getEntityId(), StandardCharsets.ISO_8859_1.name());
  }

  protected Endpoint getEndpoint(String baseUrl, String path, Binding binding, int index, boolean isDefault)
  {
    String url = UriComponentsBuilder.fromUriString(baseUrl).pathSegment(path).build().toUriString();
    return getEndpoint(url, binding, index, isDefault);
  }

  protected Endpoint getEndpoint(String url, Binding binding, int index, boolean isDefault)
  {
    return new Endpoint().setIndex(index).setBinding(binding).setLocation(url).setDefault(isDefault);
  }

  protected List<SigningKey> getSigningKeys(RotatingSigningKeys configSigningKeys)
  {
    List<SigningKey> signingKeys = new LinkedList<>();
    if (configSigningKeys != null)
    {
      signingKeys.add(configSigningKeys.getActive());
      signingKeys.addAll(configSigningKeys.getStandBy());
    }
    return signingKeys;
  }

  protected List<EncryptionKey> getEncryptionKeys(RotatingEncryptionKeys configuredEncryptionKeys,
                                                  DataEncryptionMethod dataEncryptionAlgorithm)
  {
    List<EncryptionKey> encryptionKeys = new LinkedList<>();
    if (configuredEncryptionKeys != null)
    {
      if (configuredEncryptionKeys.getActive() != null)
      {
        encryptionKeys.add(configuredEncryptionKeys.getActive());
      }

      encryptionKeys.addAll(configuredEncryptionKeys.getStandBy());
      encryptionKeys.forEach(e -> e.setDataEncryptionMethod(dataEncryptionAlgorithm));
    }
    return encryptionKeys;
  }

}
