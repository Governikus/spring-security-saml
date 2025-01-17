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
package org.springframework.security.saml.saml2.metadata;

import java.time.Instant;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;

import javax.xml.datatype.Duration;

import org.springframework.security.saml.key.EncryptionKey;
import org.springframework.security.saml.key.SigningKey;
import org.springframework.security.saml.saml2.signature.Signature;


/**
 * Base class for SAML providers
 *
 * @param <T> return class for builder pattern
 */
public class Provider<T extends Provider<T>>
{

  private Signature signature;

  private List<SigningKey> signingKeys = new LinkedList<>();

  private List<EncryptionKey> encryptionKeys = new LinkedList<>();

  private String id;

  private Instant validUntil;

  private Duration cacheDuration;

  private List<String> protocolSupportEnumeration;

  public Signature getSignature()
  {
    return signature;
  }

  @SuppressWarnings("unchecked")
  public T setSignature(Signature signature)
  {
    this.signature = signature;
    return (T)this;
  }

  public List<SigningKey> getSigningKeys()
  {
    return Collections.unmodifiableList(signingKeys);
  }

  public T setSigningKeys(List<SigningKey> signingKeys)
  {
    this.signingKeys.clear();
    if (signingKeys != null)
    {
      this.signingKeys.addAll(signingKeys);
    }
    return _this();
  }

  public List<EncryptionKey> getEncryptionKeys()
  {
    return Collections.unmodifiableList(encryptionKeys);
  }

  public T setEncryptionKeys(List<EncryptionKey> encryptionKeys)
  {
    this.encryptionKeys.clear();
    if (encryptionKeys != null)
    {
      this.encryptionKeys.addAll(encryptionKeys);
    }
    return _this();
  }

  @SuppressWarnings("unchecked")
  protected T _this()
  {
    return (T)this;
  }

  public String getId()
  {
    return id;
  }

  @SuppressWarnings("unchecked")
  public T setId(String id)
  {
    this.id = id;
    return (T)this;
  }

  public Instant getValidUntil()
  {
    return validUntil;
  }

  @SuppressWarnings("unchecked")
  public T setValidUntil(Instant validUntil)
  {
    this.validUntil = validUntil;
    return (T)this;
  }

  public Duration getCacheDuration()
  {
    return cacheDuration;

  }

  @SuppressWarnings("unchecked")
  public T setCacheDuration(Duration cacheDuration)
  {
    this.cacheDuration = cacheDuration;
    return (T)this;
  }

  public List<String> getProtocolSupportEnumeration()
  {
    return protocolSupportEnumeration;
  }

  @SuppressWarnings("unchecked")
  public T setProtocolSupportEnumeration(List<String> protocolSupportEnumeration)
  {
    this.protocolSupportEnumeration = protocolSupportEnumeration;
    return (T)this;
  }
}
