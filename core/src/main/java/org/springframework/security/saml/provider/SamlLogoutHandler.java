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
package org.springframework.security.saml.provider;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.springframework.util.StringUtils.hasText;

import java.util.Collections;
import java.util.List;

import javax.servlet.http.HttpServletRequest;

import org.springframework.http.HttpMethod;
import org.springframework.security.saml.SamlRedirectBindingSigner;
import org.springframework.security.saml.key.SigningKey;
import org.springframework.security.saml.provider.config.ExternalProviderConfiguration;
import org.springframework.security.saml.provider.config.LocalProviderConfiguration;
import org.springframework.security.saml.provider.provisioning.SamlProviderProvisioning;
import org.springframework.security.saml.saml2.Saml2Object;
import org.springframework.security.saml.saml2.authentication.Request;
import org.springframework.security.saml.saml2.metadata.IdentityProviderMetadata;
import org.springframework.security.saml.saml2.metadata.Metadata;
import org.springframework.security.saml.saml2.metadata.ServiceProviderMetadata;
import org.springframework.security.saml.spi.DefaultRedirectBindingSigner;
import org.springframework.web.util.UriComponentsBuilder;
import org.springframework.web.util.UriUtils;


public abstract class SamlLogoutHandler<T extends HostedProviderService<C, L, R, E>, C extends LocalProviderConfiguration<C, E>, L extends Metadata<L>, R extends Metadata<R>, E extends ExternalProviderConfiguration<E>>
{

  private final SamlProviderProvisioning<T, C, L, R, E> provisioning;

  private SamlRedirectBindingSigner redirectBindingSigner = new DefaultRedirectBindingSigner();

  protected SamlLogoutHandler(SamlProviderProvisioning<T, C, L, R, E> provisioning)
  {
    this.provisioning = provisioning;
  }

  protected boolean isRedirectBinding(HttpServletRequest request)
  {
    return HttpMethod.GET.name().equalsIgnoreCase(request.getMethod());
  }

  /**
   * Override this method and add validation of the redirect-binding signature before productive usage
   */
  protected void validate(HttpServletRequest request, Saml2Object saml2Object)
  {
    T provider = provisioning.getHostedProvider();
    provider.validate(saml2Object, null);

    if (isRedirectBinding(request))
    {
      List<SigningKey> verificationKeys = getSignatureVerificationKeys(provider, saml2Object);
      redirectBindingSigner.validateSignature(saml2Object instanceof Request, request, verificationKeys);
    }
  }

  protected List<SigningKey> getSignatureVerificationKeys(T provider, Saml2Object saml2Object)
  {
    R remoteProvider = provider.getRemoteProvider(saml2Object);
    if (remoteProvider instanceof IdentityProviderMetadata)
    {
      return ((IdentityProviderMetadata)remoteProvider).getIdentityProvider().getSigningKeys();
    }
    else if (remoteProvider instanceof ServiceProviderMetadata)
    {
      return ((ServiceProviderMetadata)remoteProvider).getServiceProvider().getSigningKeys();
    }
    return Collections.emptyList();
  }

  protected String createRedirectBindingUrl(HttpServletRequest request, Saml2Object saml2Object, String location)
  {
    UriComponentsBuilder url = UriComponentsBuilder.fromUriString(location);

    String relayState = getRelayState(request);
    if (hasText(relayState))
    {
      url.queryParam("RelayState", UriUtils.encode(relayState, UTF_8.name()));
    }

    String parameterName = saml2Object instanceof Request ? "SAMLRequest" : "SAMLResponse";
    T provider = provisioning.getHostedProvider();
    String encoded = provider.toEncodedXml(saml2Object, true);
    return url.queryParam(parameterName, UriUtils.encode(encoded, UTF_8.name())).build().toUriString();
  }

  protected String getRelayState(HttpServletRequest request)
  {
    return request.getParameter("RelayState");
  }

  public SamlRedirectBindingSigner getSamlRedirectBindingSigner()
  {
    return redirectBindingSigner;
  }

  public SamlLogoutHandler<T, C, L, R, E> setSamlRedirectBindingSigner(SamlRedirectBindingSigner redirectBindingSigner)
  {
    this.redirectBindingSigner = redirectBindingSigner;
    return this;
  }

}
