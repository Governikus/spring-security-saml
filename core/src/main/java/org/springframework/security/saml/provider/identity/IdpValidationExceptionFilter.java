/*
 * Copyright 2002-2022 the original author or authors.
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

import java.io.IOException;
import java.util.Collections;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.saml.provider.SamlFilter;
import org.springframework.security.saml.provider.identity.config.ExternalServiceProviderConfiguration;
import org.springframework.security.saml.provider.identity.config.LocalIdentityProviderConfiguration;
import org.springframework.security.saml.provider.provisioning.SamlProviderProvisioning;
import org.springframework.security.saml.saml2.authentication.AuthenticationRequest;
import org.springframework.security.saml.saml2.authentication.Response;
import org.springframework.security.saml.saml2.authentication.Status;
import org.springframework.security.saml.saml2.metadata.Binding;
import org.springframework.security.saml.saml2.metadata.Endpoint;
import org.springframework.security.saml.saml2.metadata.IdentityProviderMetadata;
import org.springframework.security.saml.saml2.metadata.ServiceProviderMetadata;
import org.springframework.security.saml.validation.ValidationException;
import org.springframework.security.saml.validation.ValidationResult;


public class IdpValidationExceptionFilter extends
  SamlFilter<HostedIdentityProviderService, LocalIdentityProviderConfiguration, IdentityProviderMetadata, ServiceProviderMetadata, ExternalServiceProviderConfiguration>
{

  private static final Log LOG = LogFactory.getLog(IdpValidationExceptionFilter.class);

  public IdpValidationExceptionFilter(SamlProviderProvisioning<HostedIdentityProviderService, LocalIdentityProviderConfiguration, IdentityProviderMetadata, ServiceProviderMetadata, ExternalServiceProviderConfiguration> provisioning)
  {
    super(provisioning);
  }

  @Override
  protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
    throws ServletException, IOException
  {
    try
    {
      filterChain.doFilter(request, response);
    }
    catch (ValidationException e)
    {
      ValidationResult validationResult = e.getErrors();
      AuthenticationRequest authnRequest = getAuthnRequest(validationResult);

      if (authnRequest == null)
      {
        displayErrorTemplate(request, response, e);
      }
      else
      {
        HostedIdentityProviderService provider = getProvisioning().getHostedProvider();
        ServiceProviderMetadata recipient = provider.getRemoteProvider(authnRequest);
        Endpoint assertionConsumerService = authnRequest.getAssertionConsumerService();
        Endpoint acsUrl = provider.getPreferredEndpoint(recipient.getServiceProvider().getAssertionConsumerService(),
                                                        assertionConsumerService.getBinding(),
                                                        assertionConsumerService.getIndex());

        Status status = validationResult.getErrorStatus().setMessage(e.getMessage());
        Response errorResponse = getErrorResponse(authnRequest, provider, acsUrl, status);

        String relayState = getRelayState(request);
        if (acsUrl.getBinding() == Binding.REDIRECT)
        {
          sendWithRedirectBinding(request, response, provider, errorResponse, acsUrl, relayState);
        }
        else if (acsUrl.getBinding() == Binding.POST)
        {
          sendWithPostBinding(request, response, provider, errorResponse, acsUrl, relayState);
        }
        else
        {
          displayErrorTemplate(request, response, e);
        }
      }
    }
  }

  protected Response getErrorResponse(AuthenticationRequest authnRequest,
                                      HostedIdentityProviderService provider,
                                      Endpoint acsUrl,
                                      Status status)
  {
    return provider.errorResponse(authnRequest, status, acsUrl);
  }

  protected AuthenticationRequest getAuthnRequest(ValidationResult validationResult)
  {
    if (validationResult != null && validationResult.getErrorStatus() != null
        && validationResult.getSaml2Object() instanceof AuthenticationRequest)
    {
      return (AuthenticationRequest)validationResult.getSaml2Object();
    }
    return null;
  }

  protected String getRelayState(HttpServletRequest request)
  {
    return request.getParameter("RelayState");
  }

  protected void displayErrorTemplate(HttpServletRequest request, HttpServletResponse response, Exception e)
  {
    if (LOG.isErrorEnabled())
    {
      LOG.error(e.getMessage());
    }
    processHtml(request, response, getErrorTemplate(), Collections.singletonMap("message", e.getMessage()));
  }

}
