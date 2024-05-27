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

package org.springframework.security.saml.provider.service.authentication;

import static org.springframework.util.StringUtils.hasText;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.saml.SamlException;
import org.springframework.security.saml.SamlRequestMatcher;
import org.springframework.security.saml.provider.provisioning.SamlProviderProvisioning;
import org.springframework.security.saml.provider.service.HostedServiceProviderService;
import org.springframework.security.saml.provider.service.ServiceProviderService;
import org.springframework.security.saml.provider.service.cache.RequestContextCache;
import org.springframework.security.saml.provider.service.cache.RequestContextCache.RequestContext;
import org.springframework.security.saml.provider.service.config.ExternalIdentityProviderConfiguration;
import org.springframework.security.saml.provider.service.config.LocalServiceProviderConfiguration;
import org.springframework.security.saml.saml2.authentication.Response;
import org.springframework.security.saml.saml2.metadata.IdentityProviderMetadata;
import org.springframework.security.saml.saml2.metadata.ServiceProviderMetadata;
import org.springframework.security.saml.spi.DefaultRedirectBindingSigner;
import org.springframework.security.saml.spi.DefaultSamlAuthentication;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.authentication.session.ChangeSessionIdAuthenticationStrategy;
import org.springframework.security.web.util.matcher.RequestMatcher;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;


public class SamlAuthenticationResponseFilter extends AbstractAuthenticationProcessingFilter
{

  private static final Log log = LogFactory.getLog(SamlAuthenticationResponseFilter.class);

  private final SamlProviderProvisioning<HostedServiceProviderService, LocalServiceProviderConfiguration, ServiceProviderMetadata, IdentityProviderMetadata, ExternalIdentityProviderConfiguration> provisioning;

  private final RequestContextCache requestContextCache;

  private boolean refuseRedirectBindingForSAMLResponse = true;

  public SamlAuthenticationResponseFilter(SamlProviderProvisioning<HostedServiceProviderService, LocalServiceProviderConfiguration, ServiceProviderMetadata, IdentityProviderMetadata, ExternalIdentityProviderConfiguration> provisioning,
                                          RequestContextCache requestContextCache)
  {
    this(new SamlRequestMatcher<>(provisioning, "SSO"), provisioning, requestContextCache);
  }

  public SamlAuthenticationResponseFilter(RequestMatcher requiresAuthenticationRequestMatcher,
                                          SamlProviderProvisioning<HostedServiceProviderService, LocalServiceProviderConfiguration, ServiceProviderMetadata, IdentityProviderMetadata, ExternalIdentityProviderConfiguration> provisioning,
                                          RequestContextCache requestContextCache)
  {
    super(requiresAuthenticationRequestMatcher);
    this.provisioning = provisioning;
    setSessionAuthenticationStrategy(new ChangeSessionIdAuthenticationStrategy());
    this.requestContextCache = requestContextCache;
  }

  public boolean isRefuseRedirectBindingForSAMLResponse()
  {
    return refuseRedirectBindingForSAMLResponse;
  }

  /**
   * Note: Redirect binding is not allowed in the Web SSO profile
   *
   * @param refuse (default is true)
   */
  public void setRefuseRedirectBindingForSAMLResponse(boolean refuse)
  {
    refuseRedirectBindingForSAMLResponse = refuse;
  }

  @Override
  public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
    throws AuthenticationException
  {
    boolean isHttpRedirectBindingRequest = isHttpRedirectBindingRequest(request);
    if (isHttpRedirectBindingRequest && isRefuseRedirectBindingForSAMLResponse())
    {
      throw new InsufficientAuthenticationException("HTTP Redirect Binding is not allowed for a SAMLResponse.");
    }

    String relayState = getRelayState(request);
    RequestContext requestContext = requestContextCache.getRequestContext(request, relayState);
    if (requestContext == null)
    {
      removeRequestContext(request, relayState);
      throw new InsufficientAuthenticationException("SAMLResponse contains an invalid relay state value.");
    }

    String responseData = getSamlResponseData(request);
    if (!hasText(responseData))
    {
      removeRequestContext(request, relayState);
      throw new AuthenticationCredentialsNotFoundException("SAMLResponse parameter missing");
    }

    ServiceProviderService provider = getProvisioning().getHostedProvider();

    Response r;
    try
    {
      r = provider.fromXml(responseData, true, isHttpRedirectBindingRequest, Response.class);
    }
    catch (Exception e)
    {
      removeRequestContext(request, relayState);
      log.error(e.getMessage(), e);
      throw new InsufficientAuthenticationException(e.getMessage(), e);
    }
    if (log.isTraceEnabled())
    {
      log.trace("Received SAMLResponse XML:" + r.getOriginalXML());
    }

    IdentityProviderMetadata remote = provider.getRemoteProvider(r);
    if (isHttpRedirectBindingRequest(request) && !isRefuseRedirectBindingForSAMLResponse())
    {
      validateRedirectBindingSignature(request, remote);
    }

    validateResponse(r, requestContext, provider, request);
    removeRequestContext(request, relayState);

    return getAuthenticationManager().authenticate(createAuthentication(request,
                                                                        relayState,
                                                                        requestContext,
                                                                        provider,
                                                                        r,
                                                                        remote));
  }

  protected void validateResponse(Response r,
                                  RequestContext requestContext,
                                  ServiceProviderService provider,
                                  HttpServletRequest request)
  {
    try
    {
      provider.validate(r, requestContext);
    }
    catch (SamlException e)
    {
      removeRequestContext(request, requestContext.getRelayState());
      throw new InsufficientAuthenticationException(e.getMessage(), e);
    }
  }

  protected Authentication createAuthentication(HttpServletRequest request,
                                                String relayState,
                                                RequestContext requestContext,
                                                ServiceProviderService provider,
                                                Response r,
                                                IdentityProviderMetadata remote)
  {
    DefaultSamlAuthentication authentication = new DefaultSamlAuthentication(true, r.getAssertions().get(0),
                                                                             remote.getEntityId(),
                                                                             provider.getMetadata().getEntityId(),
                                                                             relayState, r.getInResponseTo());
    authentication.setResponseXml(r.getOriginalXML());
    return authentication;
  }

  protected void removeRequestContext(HttpServletRequest request, String relayState)
  {
    requestContextCache.removeRequestContext(request, relayState);
  }

  private SamlProviderProvisioning<HostedServiceProviderService, LocalServiceProviderConfiguration, ServiceProviderMetadata, IdentityProviderMetadata, ExternalIdentityProviderConfiguration> getProvisioning()
  {
    return provisioning;
  }

  protected String getSamlResponseData(HttpServletRequest request)
  {
    return request.getParameter("SAMLResponse");
  }

  protected String getRelayState(HttpServletRequest request)
  {
    return request.getParameter("RelayState");
  }

  protected boolean isHttpRedirectBindingRequest(HttpServletRequest request)
  {
    return HttpMethod.GET.name().equalsIgnoreCase(request.getMethod());
  }

  /**
   * only called if {@link #refuseRedirectBindingForSAMLResponse} is false
   */
  protected void validateRedirectBindingSignature(HttpServletRequest request, IdentityProviderMetadata remote)
  {
    new DefaultRedirectBindingSigner().validateSignature(false, request, remote.getIdentityProvider().getSigningKeys());
  }

}
