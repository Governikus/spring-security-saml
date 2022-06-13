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

package org.springframework.security.saml.provider.service.config;

import java.util.ArrayList;
import java.util.List;

import org.springframework.security.saml.provider.config.LocalProviderConfiguration;
import org.springframework.security.saml.saml2.metadata.Endpoint;


public class LocalServiceProviderConfiguration
  extends LocalProviderConfiguration<LocalServiceProviderConfiguration, ExternalIdentityProviderConfiguration>
{

  private boolean signRequests = false;

  private boolean wantAssertionsSigned = false;

  private List<Endpoint> assertionConsumerServices = new ArrayList<>();

  private List<Endpoint> manageNameIdServices = new ArrayList<>();

  public LocalServiceProviderConfiguration()
  {
    super("saml/sp");
  }

  public boolean isSignRequests()
  {
    return signRequests;
  }

  public LocalServiceProviderConfiguration setSignRequests(boolean signRequests)
  {
    this.signRequests = signRequests;
    return this;
  }

  public boolean isWantAssertionsSigned()
  {
    return wantAssertionsSigned;
  }

  public LocalServiceProviderConfiguration setWantAssertionsSigned(boolean wantAssertionsSigned)
  {
    this.wantAssertionsSigned = wantAssertionsSigned;
    return this;
  }

  public List<Endpoint> getAssertionConsumerServices()
  {
    return assertionConsumerServices;
  }

  public LocalServiceProviderConfiguration setAssertionConsumerServices(List<Endpoint> assertionConsumerServices)
  {
    this.assertionConsumerServices = assertionConsumerServices;
    return this;
  }

  public List<Endpoint> getManageNameIdServices()
  {
    return manageNameIdServices;
  }

  public LocalServiceProviderConfiguration setManageNameIdServices(List<Endpoint> manageNameIdServices)
  {
    this.manageNameIdServices = manageNameIdServices;
    return this;
  }
}
