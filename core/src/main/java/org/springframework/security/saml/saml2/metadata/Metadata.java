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

import org.springframework.security.saml.saml2.Saml2Object;


/**
 * Represents metadata for a
 * <ul>
 * <li>SSO Service Provider</li>
 * <li>SSO Identity Provider</li>
 * </ul>
 * May be chained if read from EntitiesDescriptor element.
 *
 * Currently does <b>not support</b> metadata for
 * <ul>
 * <li>Authentication Authority</li>
 * <li>Attribute Authority</li>
 * <li>Policy Decision Point</li>
 * <li>Affiliation</li>
 * </ul>
 */
public class Metadata<T extends EntityDescriptor<T>> extends EntityDescriptor<T> implements Saml2Object
{

  /*
   * In case of parsing EntitiesDescriptor, we can have more than one provider
   */
  private T next = null;

  private String organizationName;

  private String organizationNameLang;

  private String organizationDisplayName;

  private String organizationDisplayNameLang;

  private String organizationURL;

  private String organizationURLLang;

  public Metadata()
  {}

  public Metadata(Metadata<T> other)
  {
    super(other);
    organizationName = other.getOrganizationName();
    organizationNameLang = other.getOrganizationNameLang();
    organizationDisplayName = other.getOrganizationDisplayName();
    organizationDisplayNameLang = other.getOrganizationDisplayNameLang();
    organizationURL = other.getOrganizationURL();
    organizationURLLang = other.getOrganizationURLLang();
    this.next = other.next;
  }

  public T getNext()
  {
    return next;
  }

  public Metadata<T> setNext(T next)
  {
    this.next = next;
    return this;
  }

  public boolean hasNext()
  {
    return next != null;
  }

  public String getOrganizationName()
  {
    return organizationName;
  }

  public Metadata<T> organizationName(String organizationName)
  {
    this.organizationName = organizationName;
    return this;
  }

  public String getOrganizationNameLang()
  {
    return organizationNameLang;
  }

  public Metadata<T> organizationNameLang(String organizationNameLang)
  {
    this.organizationNameLang = organizationNameLang;
    return this;
  }

  public String getOrganizationDisplayName()
  {
    return organizationDisplayName;
  }

  public Metadata<T> organizationDisplayName(String organizationDisplayName)
  {
    this.organizationDisplayName = organizationDisplayName;
    return this;
  }

  public String getOrganizationDisplayNameLang()
  {
    return organizationDisplayNameLang;
  }

  public Metadata<T> organizationDisplayNameLang(String organizationDisplayNameLang)
  {
    this.organizationDisplayNameLang = organizationDisplayNameLang;
    return this;
  }

  public String getOrganizationURL()
  {
    return organizationURL;
  }

  public Metadata<T> organizationURL(String organizationURL)
  {
    this.organizationURL = organizationURL;
    return this;
  }

  public String getOrganizationURLLang()
  {
    return organizationURLLang;
  }

  public Metadata<T> organizationURLLang(String organizationURLLang)
  {
    this.organizationURLLang = organizationURLLang;
    return this;
  }
}
