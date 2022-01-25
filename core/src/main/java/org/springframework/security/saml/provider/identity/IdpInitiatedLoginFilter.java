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

import static java.lang.String.format;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.saml.SamlException;
import org.springframework.security.saml.SamlMessageStore;
import org.springframework.security.saml.SamlRequestMatcher;
import org.springframework.security.saml.provider.SamlFilter;
import org.springframework.security.saml.provider.identity.config.ExternalServiceProviderConfiguration;
import org.springframework.security.saml.provider.identity.config.LocalIdentityProviderConfiguration;
import org.springframework.security.saml.provider.provisioning.SamlProviderProvisioning;
import org.springframework.security.saml.saml2.authentication.Assertion;
import org.springframework.security.saml.saml2.authentication.AuthenticationRequest;
import org.springframework.security.saml.saml2.authentication.Response;
import org.springframework.security.saml.saml2.metadata.Binding;
import org.springframework.security.saml.saml2.metadata.Endpoint;
import org.springframework.security.saml.saml2.metadata.IdentityProviderMetadata;
import org.springframework.security.saml.saml2.metadata.NameId;
import org.springframework.security.saml.saml2.metadata.ServiceProviderMetadata;


public class IdpInitiatedLoginFilter extends
  SamlFilter<HostedIdentityProviderService, LocalIdentityProviderConfiguration, IdentityProviderMetadata, ServiceProviderMetadata, ExternalServiceProviderConfiguration>
{

  private static final Log log = LogFactory.getLog(IdpInitiatedLoginFilter.class);

  private final SamlRequestMatcher<HostedIdentityProviderService, LocalIdentityProviderConfiguration, IdentityProviderMetadata, ServiceProviderMetadata, ExternalServiceProviderConfiguration> requestMatcher;

  private final SamlMessageStore<Assertion, HttpServletRequest> assertionStore;

  public IdpInitiatedLoginFilter(SamlProviderProvisioning<HostedIdentityProviderService, LocalIdentityProviderConfiguration, IdentityProviderMetadata, ServiceProviderMetadata, ExternalServiceProviderConfiguration> provisioning,
                                 SamlMessageStore<Assertion, HttpServletRequest> assertionStore)
  {
    this(provisioning, assertionStore, new SamlRequestMatcher<>(provisioning, "init"));
  }

  public IdpInitiatedLoginFilter(SamlProviderProvisioning<HostedIdentityProviderService, LocalIdentityProviderConfiguration, IdentityProviderMetadata, ServiceProviderMetadata, ExternalServiceProviderConfiguration> provisioning,
                                 SamlMessageStore<Assertion, HttpServletRequest> assertionStore,
                                 SamlRequestMatcher<HostedIdentityProviderService, LocalIdentityProviderConfiguration, IdentityProviderMetadata, ServiceProviderMetadata, ExternalServiceProviderConfiguration> requestMatcher)
  {
    super(provisioning);
    this.requestMatcher = requestMatcher;
    this.assertionStore = assertionStore;
  }

  @Override
  protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
    throws ServletException, IOException
  {
    Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
    if (requestMatcher.matches(request) && authentication != null && authentication.isAuthenticated())
    {
      HostedIdentityProviderService provider = getProvisioning().getHostedProvider();

      AuthenticationRequest authenticationRequest = getAuthenticationRequest(request);
      ServiceProviderMetadata recipient = getTargetProvider(request, authenticationRequest);
      validateAuthenticationRequest(request, authenticationRequest, recipient);

      Assertion assertion = getAssertion(authentication, authenticationRequest, provider, recipient);
      assertionStore.addMessage(request, assertion.getId(), assertion);
      Response r = provider.response(authenticationRequest, assertion, recipient);

      Endpoint acsUrl = provider.getPreferredEndpoint(recipient.getServiceProvider().getAssertionConsumerService(),
                                                      Binding.POST,
                                                      -1);

      log.debug(format("Sending assertion for SP:%s to URL:%s using Binding:%s",
                       recipient.getEntityId(),
                       acsUrl.getLocation(),
                       acsUrl.getBinding()));
      String relayState = request.getParameter("RelayState");
      if (acsUrl.getBinding() == Binding.REDIRECT)
      {
        sendWithRedirectBinding(request, response, provider, r, acsUrl, relayState);
      }
      else if (acsUrl.getBinding() == Binding.POST)
      {
        sendWithPostBinding(request, response, provider, r, acsUrl, relayState);
      }
      else
      {
        throw new SamlException("Unsupported binding:" + acsUrl.getBinding());
      }
    }
    else
    {
      filterChain.doFilter(request, response);
    }
  }

  protected ServiceProviderMetadata getTargetProvider(HttpServletRequest request, AuthenticationRequest authn)
  {
    String entityId = request.getParameter("sp");
    return getProvisioning().getHostedProvider().getRemoteProvider(entityId);
  }

  protected AuthenticationRequest getAuthenticationRequest(HttpServletRequest request)
  {
    return null;
  }

  protected void validateAuthenticationRequest(HttpServletRequest request,
                                               AuthenticationRequest authn,
                                               ServiceProviderMetadata recipient)
  {
    // no default validation
  }

  protected Assertion getAssertion(Authentication authentication,
                                   AuthenticationRequest authenticationRequest,
                                   IdentityProviderService provider,
                                   ServiceProviderMetadata recipient)
  {
    return provider.assertion(recipient, authenticationRequest, authentication.getName(), NameId.PERSISTENT);
  }

}
