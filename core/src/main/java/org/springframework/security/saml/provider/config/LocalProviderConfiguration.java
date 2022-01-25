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

package org.springframework.security.saml.provider.config;

import static org.springframework.util.StringUtils.hasText;

import java.util.LinkedList;
import java.util.List;
import java.util.stream.Collectors;

import org.springframework.security.saml.saml2.encrypt.DataEncryptionMethod;
import org.springframework.security.saml.saml2.encrypt.KeyEncryptionMethod;
import org.springframework.security.saml.saml2.metadata.NameId;
import org.springframework.security.saml.saml2.signature.AlgorithmMethod;
import org.springframework.security.saml.saml2.signature.DigestMethod;


public class LocalProviderConfiguration<L extends LocalProviderConfiguration<L, E>, E extends ExternalProviderConfiguration<E>>
  implements Cloneable
{

  private String entityId;

  private String alias;

  private boolean signMetadata;

  private String metadata;

  private RotatingSigningKeys signingKeys;

  private RotatingEncryptionKeys encryptionKeys;

  private String prefix;

  private boolean singleLogoutEnabled = true;

  private List<NameId> nameIds = new LinkedList<>();

  private AlgorithmMethod defaultSigningAlgorithm = AlgorithmMethod.RSA_SHA256;

  private DigestMethod defaultDigest = DigestMethod.SHA256;

  private List<E> providers = new LinkedList<>();

  private String basePath;

  private KeyEncryptionMethod keyEncryptionAlgorithm = KeyEncryptionMethod.RSA_1_5;

  private DataEncryptionMethod dataEncryptionAlgorithm = DataEncryptionMethod.AES256_CBC;

  public LocalProviderConfiguration(String prefix)
  {
    setPrefix(prefix);
  }

  protected String cleanPrefix(String prefix)
  {
    if (hasText(prefix) && prefix.startsWith("/"))
    {
      prefix = prefix.substring(1);
    }
    if (hasText(prefix) && !prefix.endsWith("/"))
    {
      prefix = prefix + "/";
    }
    return prefix;
  }

  @SuppressWarnings("unchecked")
  protected L _this()
  {
    return (L)this;
  }

  public String getEntityId()
  {
    return entityId;
  }

  public L setEntityId(String entityId)
  {
    this.entityId = entityId;
    return _this();
  }

  public boolean isSignMetadata()
  {
    return signMetadata;
  }

  public L setSignMetadata(boolean signMetadata)
  {
    this.signMetadata = signMetadata;
    return _this();
  }

  public String getMetadata()
  {
    return metadata;
  }

  public L setMetadata(String metadata)
  {
    this.metadata = metadata;
    return _this();
  }

  public RotatingSigningKeys getSigningKeys()
  {
    return signingKeys;
  }

  public L setSigningKeys(RotatingSigningKeys signingKeys)
  {
    this.signingKeys = signingKeys;
    return _this();
  }

  public RotatingEncryptionKeys getEncryptionKeys()
  {
    return encryptionKeys;
  }

  public L setEncryptionKeys(RotatingEncryptionKeys encryptionKeys)
  {
    this.encryptionKeys = encryptionKeys;
    return _this();
  }

  public String getAlias()
  {
    return alias;
  }

  public L setAlias(String alias)
  {
    this.alias = alias;
    return _this();
  }

  public String getPrefix()
  {
    return prefix;
  }

  public L setPrefix(String prefix)
  {
    prefix = cleanPrefix(prefix);
    this.prefix = prefix;

    return _this();
  }

  public boolean isSingleLogoutEnabled()
  {
    return singleLogoutEnabled;
  }

  public L setSingleLogoutEnabled(boolean singleLogoutEnabled)
  {
    this.singleLogoutEnabled = singleLogoutEnabled;
    return _this();
  }

  public List<NameId> getNameIds()
  {
    return nameIds;
  }

  public L setNameIds(List<Object> nameIds)
  {
    this.nameIds = nameIds.stream()
                          .map(n -> n instanceof String ? NameId.fromUrn((String)n) : (NameId)n)
                          .collect(Collectors.toList());
    return _this();
  }

  public AlgorithmMethod getDefaultSigningAlgorithm()
  {
    return defaultSigningAlgorithm;
  }

  public L setDefaultSigningAlgorithm(AlgorithmMethod defaultSigningAlgorithm)
  {
    this.defaultSigningAlgorithm = defaultSigningAlgorithm;
    return _this();
  }

  public DigestMethod getDefaultDigest()
  {
    return defaultDigest;
  }

  public L setDefaultDigest(DigestMethod defaultDigest)
  {
    this.defaultDigest = defaultDigest;
    return _this();
  }

  public String getBasePath()
  {
    return basePath;
  }

  public LocalProviderConfiguration<L, E> setBasePath(String basePath)
  {
    this.basePath = basePath;
    return this;
  }

  @Override
  public L clone() throws CloneNotSupportedException
  {
    @SuppressWarnings("unchecked")
    L result = (L)super.clone();
    LinkedList<E> newProviders = new LinkedList<>();
    for ( E externalConfiguration : getProviders() )
    {
      newProviders.add(externalConfiguration.clone());
    }
    result.setProviders(newProviders);
    return result;
  }

  public List<E> getProviders()
  {
    return providers;
  }

  public L setProviders(List<E> providers)
  {
    this.providers = providers;
    return _this();
  }

  public KeyEncryptionMethod getKeyEncryptionAlgorithm()
  {
    return keyEncryptionAlgorithm;
  }

  public L setKeyEncryptionAlgorithm(KeyEncryptionMethod keyEncryptionAlgorithm)
  {
    this.keyEncryptionAlgorithm = keyEncryptionAlgorithm;
    return _this();
  }

  public DataEncryptionMethod getDataEncryptionAlgorithm()
  {
    return dataEncryptionAlgorithm;
  }

  public L setDataEncryptionAlgorithm(DataEncryptionMethod dataEncryptionAlgorithm)
  {
    this.dataEncryptionAlgorithm = dataEncryptionAlgorithm;
    return _this();
  }
}
