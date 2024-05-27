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

package org.springframework.security.saml.provider;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.springframework.http.MediaType.TEXT_HTML_VALUE;
import static org.springframework.util.StringUtils.hasText;

import java.io.IOException;
import java.io.StringWriter;
import java.util.HashMap;
import java.util.Map;

import org.springframework.security.saml.SamlException;
import org.springframework.security.saml.SamlRedirectBindingSigner;
import org.springframework.security.saml.SamlTemplateEngine;
import org.springframework.security.saml.key.SigningKey;
import org.springframework.security.saml.provider.config.ExternalProviderConfiguration;
import org.springframework.security.saml.provider.config.LocalProviderConfiguration;
import org.springframework.security.saml.provider.provisioning.SamlProviderProvisioning;
import org.springframework.security.saml.saml2.Saml2Object;
import org.springframework.security.saml.saml2.SignableRedirectBindingObject;
import org.springframework.security.saml.saml2.authentication.Request;
import org.springframework.security.saml.saml2.authentication.Response;
import org.springframework.security.saml.saml2.metadata.Endpoint;
import org.springframework.security.saml.saml2.metadata.Metadata;
import org.springframework.security.saml.saml2.signature.AlgorithmMethod;
import org.springframework.security.saml.spi.DefaultRedirectBindingSigner;
import org.springframework.security.saml.spi.opensaml.OpenSamlVelocityEngine;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.header.HeaderWriter;
import org.springframework.security.web.header.writers.CacheControlHeadersWriter;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.HtmlUtils;
import org.springframework.web.util.UriComponentsBuilder;
import org.springframework.web.util.UriUtils;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;


public abstract class SamlFilter<T extends HostedProviderService<C, L, R, E>, C extends LocalProviderConfiguration<C, E>, L extends Metadata<L>, R extends Metadata<R>, E extends ExternalProviderConfiguration<E>>
  extends OncePerRequestFilter
{

  private final SamlProviderProvisioning<T, C, L, R, E> provisioning;

  private String errorTemplate = "/templates/spi/generic-error.vm";

  private String postBindingTemplate = "/templates/spi/saml2-post-binding.vm";

  private SamlTemplateEngine samlTemplateEngine = new OpenSamlVelocityEngine();

  private HeaderWriter cacheHeaderWriter = new CacheControlHeadersWriter();

  private SamlRedirectBindingSigner redirectBindingSigner = new DefaultRedirectBindingSigner();

  private RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();

  protected SamlFilter(SamlProviderProvisioning<T, C, L, R, E> provisioning)
  {
    this.provisioning = provisioning;
  }

  public String getErrorTemplate()
  {
    return errorTemplate;
  }

  public SamlFilter<T, C, L, R, E> setErrorTemplate(String errorTemplate)
  {
    this.errorTemplate = errorTemplate;
    return this;
  }

  public String getPostBindingTemplate()
  {
    return postBindingTemplate;
  }

  public SamlFilter<T, C, L, R, E> setPostBindingTemplate(String postBindingTemplate)
  {
    this.postBindingTemplate = postBindingTemplate;
    return this;
  }

  public SamlProviderProvisioning<T, C, L, R, E> getProvisioning()
  {
    return provisioning;
  }

  public HeaderWriter getCacheHeaderWriter()
  {
    return cacheHeaderWriter;
  }

  public SamlRedirectBindingSigner getSamlRedirectBindingSigner()
  {
    return redirectBindingSigner;
  }

  public SamlFilter<T, C, L, R, E> setSamlRedirectBindingSigner(SamlRedirectBindingSigner samlRedirectBindingSigner)
  {
    redirectBindingSigner = samlRedirectBindingSigner;
    return this;
  }

  public SamlTemplateEngine getSamlTemplateEngine()
  {
    return samlTemplateEngine;
  }

  public SamlFilter<T, C, L, R, E> setSamlTemplateEngine(SamlTemplateEngine samlTemplateEngine)
  {
    this.samlTemplateEngine = samlTemplateEngine;
    return this;
  }

  public RedirectStrategy getRedirectStrategy()
  {
    return redirectStrategy;
  }

  public void setRedirectStrategy(RedirectStrategy redirectStrategy)
  {
    this.redirectStrategy = redirectStrategy;
  }

  protected void sendWithPostBinding(HttpServletRequest request,
                                     HttpServletResponse response,
                                     T provider,
                                     Saml2Object saml2Object,
                                     Endpoint location,
                                     String relayState)
  {
    String encoded = provider.toEncodedXml(saml2Object, false);

    Map<String, Object> model = new HashMap<>();
    model.put("action", location.getLocation());
    String samlType = "SAMLResponse";
    if (saml2Object instanceof Request)
    {
      samlType = "SAMLRequest";
    }
    model.put(samlType, encoded);
    if (hasText(relayState))
    {
      model.put("RelayState", HtmlUtils.htmlEscape(relayState));
    }
    String javaScriptNonceValue = getJavaScriptNonceValue(request);
    if (javaScriptNonceValue != null)
    {
      model.put("nonce", javaScriptNonceValue);
    }

    processHtml(request, response, postBindingTemplate, model);
  }

  protected void processHtml(HttpServletRequest request,
                             HttpServletResponse response,
                             String html,
                             Map<String, Object> model)
  {
    cacheHeaderWriter.writeHeaders(request, response);
    response.setContentType(TEXT_HTML_VALUE);
    response.setCharacterEncoding(UTF_8.name());
    StringWriter out = new StringWriter();
    getSamlTemplateEngine().process(request, html, model, out);
    try
    {
      response.getWriter().write(out.toString());
    }
    catch (IOException e)
    {
      throw new SamlException(e);
    }
  }

  protected String getJavaScriptNonceValue(HttpServletRequest request)
  {
    return null;
  }

  protected void sendWithRedirectBinding(HttpServletRequest request,
                                         HttpServletResponse response,
                                         T provider,
                                         Saml2Object saml2Object,
                                         Endpoint location,
                                         String relayState)
    throws IOException
  {
    boolean isSamlResponse = saml2Object instanceof Response;
    String parameterName = isSamlResponse ? "SAMLResponse" : "SAMLRequest";

    UriComponentsBuilder url = UriComponentsBuilder.fromUriString(location.getLocation());

    if (!(saml2Object instanceof SignableRedirectBindingObject))
    {
      // send request via redirect-binding without signature
      String encoded = provider.toEncodedXml(saml2Object, true);

      url.queryParam(parameterName, UriUtils.encode(encoded, UTF_8.name()));
      if (hasText(relayState))
      {
        url.queryParam("RelayState", UriUtils.encode(relayState, UTF_8.name()));
      }
    }
    else
    {
      SignableRedirectBindingObject signableObject = (SignableRedirectBindingObject)saml2Object;
      AlgorithmMethod sigAlg = signableObject.getAlgorithm();
      SigningKey key = signableObject.getSigningKey();
      signableObject.removeSigningKey();
      String deflated = provider.toEncodedXml(saml2Object, true);

      String encodedRequest = UriUtils.encode(deflated, UTF_8);
      url.queryParam(parameterName, encodedRequest);

      String encodedRelayState = null;
      if (hasText(relayState))
      {
        encodedRelayState = UriUtils.encode(relayState, UTF_8);
        url.queryParam("RelayState", encodedRelayState);
      }

      String encodedSigAlg = UriUtils.encode(sigAlg.toString(), UTF_8);
      String signature = getSamlRedirectBindingSigner().createSignature(!isSamlResponse,
                                                                        encodedRequest,
                                                                        encodedRelayState,
                                                                        encodedSigAlg,
                                                                        sigAlg,
                                                                        key);
      if (signature != null)
      {
        url.queryParam("SigAlg", encodedSigAlg);
        url.queryParam("Signature", UriUtils.encode(signature, UTF_8));
      }
    }

    String redirect = url.build(true).toUriString();
    redirectStrategy.sendRedirect(request, response, redirect);
  }

}
