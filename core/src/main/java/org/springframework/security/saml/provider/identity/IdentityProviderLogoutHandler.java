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

import static java.lang.Boolean.TRUE;
import static java.lang.String.format;
import static java.util.stream.Collectors.toList;
import static org.springframework.security.saml.provider.SamlLogoutSuccessHandler.RUN_SUCCESS;
import static org.springframework.util.StringUtils.hasText;

import java.io.IOException;
import java.util.List;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.saml.SamlException;
import org.springframework.security.saml.SamlMessageStore;
import org.springframework.security.saml.provider.SamlLogoutHandler;
import org.springframework.security.saml.provider.SamlLogoutSuccessHandler;
import org.springframework.security.saml.provider.identity.config.ExternalServiceProviderConfiguration;
import org.springframework.security.saml.provider.identity.config.LocalIdentityProviderConfiguration;
import org.springframework.security.saml.provider.provisioning.SamlProviderProvisioning;
import org.springframework.security.saml.saml2.authentication.Assertion;
import org.springframework.security.saml.saml2.authentication.LogoutRequest;
import org.springframework.security.saml.saml2.authentication.LogoutResponse;
import org.springframework.security.saml.saml2.authentication.NameIdPrincipal;
import org.springframework.security.saml.saml2.metadata.IdentityProviderMetadata;
import org.springframework.security.saml.saml2.metadata.NameId;
import org.springframework.security.saml.saml2.metadata.ServiceProviderMetadata;
import org.springframework.security.web.authentication.logout.LogoutHandler;


public class IdentityProviderLogoutHandler extends
  SamlLogoutHandler<HostedIdentityProviderService, LocalIdentityProviderConfiguration, IdentityProviderMetadata, ServiceProviderMetadata, ExternalServiceProviderConfiguration>
  implements LogoutHandler
{

  private static final Log log = LogFactory.getLog(IdentityProviderLogoutHandler.class);

  private static final String ATTRIBUTE_REQUEST_ID = IdentityProviderLogoutHandler.class.getName()
                                                     + ".logout.request.id";

  private static final String ATTRIBUTE_ENTITY_ID = IdentityProviderLogoutHandler.class.getName()
                                                    + ".logout.request.entity.id";

  private final SamlProviderProvisioning<HostedIdentityProviderService, LocalIdentityProviderConfiguration, IdentityProviderMetadata, ServiceProviderMetadata, ExternalServiceProviderConfiguration> provisioning;

  private final SamlMessageStore<Assertion, HttpServletRequest> assertionStore;

  public IdentityProviderLogoutHandler(SamlProviderProvisioning<HostedIdentityProviderService, LocalIdentityProviderConfiguration, IdentityProviderMetadata, ServiceProviderMetadata, ExternalServiceProviderConfiguration> provisioning,
                                       SamlMessageStore<Assertion, HttpServletRequest> assertionStore)
  {
    super(provisioning);
    this.provisioning = provisioning;
    this.assertionStore = assertionStore;
  }

  private void removeAssertionFromStore(HttpServletRequest request, LogoutRequest logoutRequest)
  {
    List<Assertion> messages = getAssertionStore().getMessages(request);
    String issuer = logoutRequest.getIssuer().getValue();
    List<Assertion> assertion = messages.stream()
                                        .filter(a -> issuer.equals(a.getIssuer().getValue()))
                                        .collect(toList());
    assertion.forEach(a -> getAssertionStore().removeMessage(request, a.getId()));
  }

  private boolean idpHasOtherSessions(HttpServletRequest request, LogoutRequest lr)
  {
    List<Assertion> assertions = getAssertionStore().getMessages(request);
    if (assertions.size() > 1)
    {
      return true;
    }
    else if (assertions.size() == 1)
    {
      String assertionEntityId = assertions.get(0).getSubject().getPrincipal().getSpNameQualifier();
      String lrEntityId = lr.getIssuer().getValue();
      return !assertionEntityId.equals(lrEntityId);
    }
    else
    {
      return false;
    }
  }

  private void setInitialSpRequest(HttpServletRequest request, LogoutRequest lr)
  {
    if (lr != null)
    {
      request.getSession().setAttribute(ATTRIBUTE_ENTITY_ID, lr.getIssuer() == null ? null : lr.getIssuer().getValue());
      request.getSession().setAttribute(ATTRIBUTE_REQUEST_ID, lr.getId());
    }
  }

  public SamlProviderProvisioning<HostedIdentityProviderService, LocalIdentityProviderConfiguration, IdentityProviderMetadata, ServiceProviderMetadata, ExternalServiceProviderConfiguration> getProvisioning()
  {
    return provisioning;
  }

  public SamlMessageStore<Assertion, HttpServletRequest> getAssertionStore()
  {
    return assertionStore;
  }

  protected void receivedLogoutRequest(HttpServletRequest request,
                                       HttpServletResponse response,
                                       Authentication authentication,
                                       String logoutRequestValue)
    throws IOException
  {
    IdentityProviderService provider = provisioning.getHostedProvider();
    LogoutRequest logoutRequest = provider.fromXml(logoutRequestValue,
                                                   true,
                                                   isRedirectBinding(request),
                                                   LogoutRequest.class);
    validate(request, logoutRequest);

    log.debug("Local IDP received logout request.");
    // remove any assertions matching the sender from the store
    // so that the sender is not included in the intermediate messages
    removeAssertionFromStore(request, logoutRequest);

    if (idpHasOtherSessions(request, logoutRequest))
    {
      // this IDP is holding onto more than one SP session
      log.debug("Multiple SP sessions present, starting logout sequence.");
      // save the original request, this will be the
      // last message we respond to
      setInitialSpRequest(request, logoutRequest);
      // send the first message
      idpInitiatedLogout(request, response, authentication);
    }
    else
    {
      log.debug("No SP sessions found, returning logout response");
      ServiceProviderMetadata sp = provider.getRemoteProvider(logoutRequest);
      LogoutResponse lr = provider.logoutResponse(logoutRequest.getId(), sp);
      String redirect = createRedirectBindingUrl(request, lr, lr.getDestination());
      request.setAttribute(RUN_SUCCESS, SamlLogoutSuccessHandler.LogoutStatus.REDIRECT);
      response.sendRedirect(redirect);
    }
  }

  protected void receivedLogoutResponse(HttpServletRequest request,
                                        HttpServletResponse response,
                                        Authentication authentication,
                                        String logoutResponseValue)
    throws IOException
  {
    IdentityProviderService provider = getProvisioning().getHostedProvider();
    LogoutResponse logoutResponse = provider.fromXml(logoutResponseValue,
                                                     true,
                                                     isRedirectBinding(request),
                                                     LogoutResponse.class);
    validate(request, logoutResponse);

    if (getAssertionStore().hasMessages(request))
    {
      // send the next request
      idpInitiatedLogout(request, response, authentication);
    }
    else
    {
      HttpSession session = request.getSession(false);
      if (session != null)
      {
        String entityId = (String)session.getAttribute(ATTRIBUTE_ENTITY_ID);
        String requestId = (String)session.getAttribute(ATTRIBUTE_REQUEST_ID);

        if (entityId != null && requestId != null)
        {
          // respond to the request
          logoutResponse = provider.logoutResponse(requestId, provider.getRemoteProvider(entityId));
          String redirect = createRedirectBindingUrl(request, logoutResponse, logoutResponse.getDestination());
          request.setAttribute(RUN_SUCCESS, SamlLogoutSuccessHandler.LogoutStatus.REDIRECT);
          response.sendRedirect(redirect);
          return;
        }
      }

      // let the other handlers finish
      request.setAttribute(RUN_SUCCESS, SamlLogoutSuccessHandler.LogoutStatus.SUCCESS);
    }
  }

  protected void idpInitiatedLogout(HttpServletRequest request,
                                    HttpServletResponse response,
                                    Authentication authentication)
    throws IOException
  {
    if (authentication != null && authentication.isAuthenticated())
    {

      Assertion assertion = getAssertionStore().removeFirst(request);
      if (assertion == null)
      {
        request.setAttribute(RUN_SUCCESS, TRUE);
      }
      else
      {
        IdentityProviderService provider = provisioning.getHostedProvider();
        log.debug(format("Sending IDP logout request to SP:%s", assertion.getIssuer().getValue()));
        ServiceProviderMetadata sp = provider.getRemoteProvider(assertion);
        LogoutRequest logoutRequest = provider.logoutRequest(sp,
                                                             new NameIdPrincipal().setFormat(NameId.PERSISTENT)
                                                                                  .setValue(authentication.getName()));


        if (logoutRequest.getDestination() != null)
        {
          log.debug("Sending logout request through redirect.");
          // TODO review binding and send POST if needed
          String redirect = createRedirectBindingUrl(request,
                                                     logoutRequest,
                                                     logoutRequest.getDestination().getLocation());
          response.sendRedirect(redirect);
        }
        else
        {
          log.debug("Unable to send logout request. No destination set.");
          // TODO handle error
        }
      }
    }
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
        idpInitiatedLogout(request, response, authentication);
      }
    }
    catch (IOException x)
    {
      throw new SamlException(x);
    }
  }
}
