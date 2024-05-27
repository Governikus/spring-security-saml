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

package org.springframework.security.saml.provider.identity;

import org.springframework.http.HttpMethod;
import org.springframework.security.saml.SamlMessageStore;
import org.springframework.security.saml.SamlRequestMatcher;
import org.springframework.security.saml.provider.identity.config.ExternalServiceProviderConfiguration;
import org.springframework.security.saml.provider.identity.config.LocalIdentityProviderConfiguration;
import org.springframework.security.saml.provider.provisioning.SamlProviderProvisioning;
import org.springframework.security.saml.saml2.authentication.Assertion;
import org.springframework.security.saml.saml2.authentication.AuthenticationRequest;
import org.springframework.security.saml.saml2.metadata.IdentityProviderMetadata;
import org.springframework.security.saml.saml2.metadata.ServiceProviderMetadata;

import jakarta.servlet.http.HttpServletRequest;


public class IdpAuthenticationRequestFilter extends IdpInitiatedLoginFilter
{

  public IdpAuthenticationRequestFilter(SamlProviderProvisioning<HostedIdentityProviderService, LocalIdentityProviderConfiguration, IdentityProviderMetadata, ServiceProviderMetadata, ExternalServiceProviderConfiguration> provisioning,
                                        SamlMessageStore<Assertion, HttpServletRequest> assertionStore)
  {
    this(provisioning, assertionStore, new SamlRequestMatcher<>(provisioning, "SSO"));
  }

  public IdpAuthenticationRequestFilter(SamlProviderProvisioning<HostedIdentityProviderService, LocalIdentityProviderConfiguration, IdentityProviderMetadata, ServiceProviderMetadata, ExternalServiceProviderConfiguration> provisioning,
                                        SamlMessageStore<Assertion, HttpServletRequest> assertionStore,
                                        SamlRequestMatcher<HostedIdentityProviderService, LocalIdentityProviderConfiguration, IdentityProviderMetadata, ServiceProviderMetadata, ExternalServiceProviderConfiguration> requestMatcher)
  {
    super(provisioning, assertionStore, requestMatcher);
  }

  @Override
  protected ServiceProviderMetadata getTargetProvider(HttpServletRequest request, AuthenticationRequest authn)
  {
    IdentityProviderService provider = getProvisioning().getHostedProvider();
    return provider.getRemoteProvider(authn);
  }

  @Override
  protected AuthenticationRequest getAuthenticationRequest(HttpServletRequest request)
  {
    IdentityProviderService provider = getProvisioning().getHostedProvider();
    String param = request.getParameter("SAMLRequest");
    return provider.fromXml(param, true, isRequestRedirectBinding(request), AuthenticationRequest.class);
  }

  @Override
  protected void validateAuthenticationRequest(HttpServletRequest request,
                                               AuthenticationRequest authn,
                                               ServiceProviderMetadata recipient)
  {
    if (isRequestRedirectBinding(request))
    {
      getSamlRedirectBindingSigner().validateSignature(true, request, recipient.getServiceProvider().getSigningKeys());
    }

    IdentityProviderService provider = getProvisioning().getHostedProvider();
    provider.validate(authn, null);
  }

  private boolean isRequestRedirectBinding(HttpServletRequest request)
  {
    return HttpMethod.GET.name().equalsIgnoreCase(request.getMethod());
  }

}
