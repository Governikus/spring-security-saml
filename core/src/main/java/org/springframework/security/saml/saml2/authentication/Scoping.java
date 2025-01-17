/*
 * Copyright 2002-2019 the original author or authors.
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
package org.springframework.security.saml.saml2.authentication;

import java.util.List;


/**
 * Implementation samlp:ScopingType as defined by
 * https://www.oasis-open.org/committees/download.php/35711/sstc-saml-core-errata-2.0-wd-06-diff.pdf
 * Page 53, Line 2277
 */
public class Scoping
{

  private List<String> idpList;

  private List<String> requesterIds;

  private Integer proxyCount;

  public Scoping(List<String> idpList, List<String> requesterIds, Integer proxyCount)
  {
    this.idpList = idpList;
    this.requesterIds = requesterIds;
    this.proxyCount = proxyCount;
  }

  public List<String> getIdpList()
  {
    return idpList;
  }

  public List<String> getRequesterIds()
  {
    return requesterIds;
  }

  public Integer getProxyCount()
  {
    return proxyCount;
  }
}
