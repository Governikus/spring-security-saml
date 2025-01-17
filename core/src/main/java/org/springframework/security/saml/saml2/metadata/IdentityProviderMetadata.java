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

/**
 * Represents metadata providing the IDPSSODescriptor entity
 */
public class IdentityProviderMetadata extends Metadata<IdentityProviderMetadata>
{

  private NameId defaultNameId = null;

  public IdentityProviderMetadata()
  {}

  public IdentityProviderMetadata(IdentityProviderMetadata other)
  {
    super(other);
    defaultNameId = other.defaultNameId;
  }

  public IdentityProviderMetadata(Metadata<IdentityProviderMetadata> other)
  {
    super(other);
  }

  public IdentityProvider getIdentityProvider()
  {
    return getProviders().stream()
                         .filter(IdentityProvider.class::isInstance)
                         .map(IdentityProvider.class::cast)
                         .findFirst()
                         .orElse(null);

  }

  public NameId getDefaultNameId()
  {
    return defaultNameId;
  }

  public IdentityProviderMetadata setDefaultNameId(NameId defaultNameId)
  {
    this.defaultNameId = defaultNameId;
    return this;
  }
}
