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

import static java.lang.String.format;
import static org.springframework.security.saml.provider.SamlLogoutSuccessHandler.RUN_SUCCESS;
import static org.springframework.util.StringUtils.hasText;

import java.io.IOException;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.saml.SamlAuthentication;
import org.springframework.security.saml.SamlException;
import org.springframework.security.saml.provider.SamlLogoutHandler;
import org.springframework.security.saml.provider.SamlLogoutSuccessHandler;
import org.springframework.security.saml.provider.provisioning.SamlProviderProvisioning;
import org.springframework.security.saml.provider.service.HostedServiceProviderService;
import org.springframework.security.saml.provider.service.ServiceProviderService;
import org.springframework.security.saml.provider.service.config.ExternalIdentityProviderConfiguration;
import org.springframework.security.saml.provider.service.config.LocalServiceProviderConfiguration;
import org.springframework.security.saml.saml2.authentication.LogoutRequest;
import org.springframework.security.saml.saml2.authentication.LogoutResponse;
import org.springframework.security.saml.saml2.metadata.IdentityProviderMetadata;
import org.springframework.security.saml.saml2.metadata.ServiceProviderMetadata;
import org.springframework.security.web.authentication.logout.LogoutHandler;


public class ServiceProviderLogoutHandler extends
  SamlLogoutHandler<HostedServiceProviderService, LocalServiceProviderConfiguration, ServiceProviderMetadata, IdentityProviderMetadata, ExternalIdentityProviderConfiguration>
  implements LogoutHandler
{

  private static final Log log = LogFactory.getLog(ServiceProviderLogoutHandler.class);

  private final SamlProviderProvisioning<HostedServiceProviderService, LocalServiceProviderConfiguration, ServiceProviderMetadata, IdentityProviderMetadata, ExternalIdentityProviderConfiguration> provisioning;

  public ServiceProviderLogoutHandler(SamlProviderProvisioning<HostedServiceProviderService, LocalServiceProviderConfiguration, ServiceProviderMetadata, IdentityProviderMetadata, ExternalIdentityProviderConfiguration> provisioning)
  {
    super(provisioning);
    this.provisioning = provisioning;
  }

  @Override
  public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication)
  {
    String logoutRequest = request.getParameter("SAMLRequest");
    String logoutResponse = request.getParameter("SAMLResponse");
    try
    {
      if (hasText(logoutRequest))
      {
        receivedLogoutRequest(request, response, authentication, logoutRequest);
      }
      else if (hasText(logoutResponse))
      {
        receivedLogoutResponse(request, response, authentication, logoutResponse);
      }
      else
      {
        spInitiatedLogout(request, response, authentication);
      }
    }
    catch (IOException x)
    {
      throw new SamlException(x);
    }
  }

  protected void receivedLogoutRequest(HttpServletRequest request,
                                       HttpServletResponse response,
                                       Authentication authentication,
                                       String logoutRequest)
    throws IOException
  {
    ServiceProviderService provider = provisioning.getHostedProvider();
    LogoutRequest lr = provider.fromXml(logoutRequest, true, isRedirectBinding(request), LogoutRequest.class);
    validate(request, lr);

    IdentityProviderMetadata idp = provider.getRemoteProvider(lr);

    LogoutResponse logoutResponse = provider.logoutResponse(lr, idp);
    String redirect = createRedirectBindingUrl(request, logoutResponse, logoutResponse.getDestination());
    request.setAttribute(RUN_SUCCESS, SamlLogoutSuccessHandler.LogoutStatus.REDIRECT);
    response.sendRedirect(redirect);
  }

  protected void receivedLogoutResponse(HttpServletRequest request,
                                        HttpServletResponse response,
                                        Authentication authentication,
                                        String logoutResponse)
  {
    request.setAttribute(RUN_SUCCESS, SamlLogoutSuccessHandler.LogoutStatus.SUCCESS);
  }

  protected void spInitiatedLogout(HttpServletRequest request,
                                   HttpServletResponse response,
                                   Authentication authentication)
    throws IOException
  {
    if (authentication instanceof SamlAuthentication)
    {
      SamlAuthentication sa = (SamlAuthentication)authentication;
      log.debug(format("Initiating SP logout for SP:%s", sa.getHoldingEntityId()));
      ServiceProviderService provider = provisioning.getHostedProvider();
      IdentityProviderMetadata idp = provider.getRemoteProvider(sa.getAssertingEntityId());
      LogoutRequest lr = provider.logoutRequest(idp, sa.getSamlPrincipal());
      if (lr.getDestination() != null)
      {
        log.debug("Sending logout request through redirect.");
        String redirect = createRedirectBindingUrl(request, lr, lr.getDestination().getLocation());
        response.sendRedirect(redirect);
      }
      else
      {
        log.debug("Unable to send logout request. No destination set.");
      }
    }
  }

}
