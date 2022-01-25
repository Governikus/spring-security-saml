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

package org.springframework.security.saml.provider.service;

import static org.springframework.util.StringUtils.hasText;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.saml.SamlException;
import org.springframework.security.saml.SamlProviderNotFoundException;
import org.springframework.security.saml.SamlRequestMatcher;
import org.springframework.security.saml.provider.SamlFilter;
import org.springframework.security.saml.provider.provisioning.SamlProviderProvisioning;
import org.springframework.security.saml.provider.service.cache.RequestContextCache;
import org.springframework.security.saml.provider.service.config.ExternalIdentityProviderConfiguration;
import org.springframework.security.saml.provider.service.config.LocalServiceProviderConfiguration;
import org.springframework.security.saml.saml2.authentication.AuthenticationRequest;
import org.springframework.security.saml.saml2.metadata.Binding;
import org.springframework.security.saml.saml2.metadata.Endpoint;
import org.springframework.security.saml.saml2.metadata.IdentityProviderMetadata;
import org.springframework.security.saml.saml2.metadata.ServiceProviderMetadata;
import org.springframework.security.web.util.matcher.RequestMatcher;


public class SamlAuthenticationRequestFilter extends
  SamlFilter<HostedServiceProviderService, LocalServiceProviderConfiguration, ServiceProviderMetadata, IdentityProviderMetadata, ExternalIdentityProviderConfiguration>
{

  private final SamlProviderProvisioning<HostedServiceProviderService, LocalServiceProviderConfiguration, ServiceProviderMetadata, IdentityProviderMetadata, ExternalIdentityProviderConfiguration> provisioning;

  private final RequestMatcher requestMatcher;

  private final RequestContextCache requestContextCache;

  public SamlAuthenticationRequestFilter(SamlProviderProvisioning<HostedServiceProviderService, LocalServiceProviderConfiguration, ServiceProviderMetadata, IdentityProviderMetadata, ExternalIdentityProviderConfiguration> provisioning,
                                         RequestContextCache requestContextCache)
  {
    this(provisioning, new SamlRequestMatcher<>(provisioning, "discovery", false), requestContextCache);
  }


  public SamlAuthenticationRequestFilter(SamlProviderProvisioning<HostedServiceProviderService, LocalServiceProviderConfiguration, ServiceProviderMetadata, IdentityProviderMetadata, ExternalIdentityProviderConfiguration> provisioning,
                                         RequestMatcher requestMatcher,
                                         RequestContextCache requestContextCache)
  {
    super(provisioning);
    this.provisioning = provisioning;
    this.requestMatcher = requestMatcher;
    this.requestContextCache = requestContextCache;
  }

  @Override
  protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
    throws ServletException, IOException
  {

    String idpIdentifier = request.getParameter("idp");
    if (getRequestMatcher().matches(request) && hasText(idpIdentifier))
    {
      String relayState = null;
      try
      {
        HostedServiceProviderService provider = provisioning.getHostedProvider();
        IdentityProviderMetadata idp = getIdentityProvider(provider, idpIdentifier);

        AuthenticationRequest authenticationRequest = getAuthenticationRequest(provider, idp, request);
        relayState = getRelayState(request, authenticationRequest);
        sendAuthenticationRequest(provider,
                                  request,
                                  response,
                                  authenticationRequest,
                                  authenticationRequest.getDestination(),
                                  relayState);
      }
      catch (AuthenticationServiceException | SamlProviderNotFoundException e)
      {
        cleanUpRequestContext(request, relayState);
        throw new SamlException(e.getMessage(), e);
      }
    }
    else
    {
      filterChain.doFilter(request, response);
    }

  }

  protected AuthenticationRequest getAuthenticationRequest(ServiceProviderService provider,
                                                           IdentityProviderMetadata idp,
                                                           HttpServletRequest request)
  {
    return provider.authenticationRequest(idp);
  }

  protected RequestMatcher getRequestMatcher()
  {
    return requestMatcher;
  }

  protected IdentityProviderMetadata getIdentityProvider(ServiceProviderService provider, String idpIdentifier)
  {
    return provider.getRemoteProvider(idpIdentifier);
  }

  protected void sendAuthenticationRequest(HostedServiceProviderService provider,
                                           HttpServletRequest request,
                                           HttpServletResponse response,
                                           AuthenticationRequest authenticationRequest,
                                           Endpoint location,
                                           String relayState)
    throws IOException
  {
    if (location.getBinding().equals(Binding.REDIRECT))
    {
      sendWithRedirectBinding(request, response, provider, authenticationRequest, location, relayState);
    }
    else if (location.getBinding().equals(Binding.POST))
    {
      sendWithPostBinding(request, response, provider, authenticationRequest, location, relayState);
    }
    else
    {
      throw new SamlException("Unsupported binding:" + location.getBinding().toString());
    }
  }

  protected String getRelayState(HttpServletRequest request, AuthenticationRequest authenticationRequest)
  {
    return requestContextCache.createRequestContext(request, authenticationRequest).getRelayState();
  }

  protected void cleanUpRequestContext(HttpServletRequest request, String relayState)
  {
    requestContextCache.removeRequestContext(request, relayState);
  }

}
