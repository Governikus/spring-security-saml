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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.io.IOException;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.saml.SamlRedirectBindingSigner;
import org.springframework.security.saml.key.SigningKey;
import org.springframework.security.saml.provider.provisioning.SamlProviderProvisioning;
import org.springframework.security.saml.saml2.Saml2Object;
import org.springframework.security.saml.saml2.authentication.AuthenticationRequest;
import org.springframework.security.saml.saml2.authentication.LogoutRequest;
import org.springframework.security.saml.saml2.authentication.Response;
import org.springframework.security.saml.saml2.metadata.Endpoint;
import org.springframework.security.saml.saml2.signature.AlgorithmMethod;
import org.springframework.security.saml.saml2.signature.DigestMethod;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;


class SamlFilterTest
{

  private final SamlProviderProvisioning provisioning = mock(SamlProviderProvisioning.class);

  private final HostedProviderService provider = mock(HostedProviderService.class);

  private final SamlRedirectBindingSigner signer = mock(SamlRedirectBindingSigner.class);

  @Test
  void testSendRedirectBindingAuthnRequest() throws IOException
  {
    when(signer.createSignature(anyBoolean(), any(), any(), any(), any(), any())).thenReturn("created-signature");
    when(provider.toEncodedXml(any(Saml2Object.class), anyBoolean())).thenReturn("encoded-value");

    SamlFilterTestImpl samlFilter = new SamlFilterTestImpl();
    MockHttpServletRequest request = new MockHttpServletRequest();
    MockHttpServletResponse response = new MockHttpServletResponse();

    String relayState = "relay-state-value";
    String location = "https://localhost/saml/idp";
    Endpoint endpoint = new Endpoint().setLocation(location);
    AuthenticationRequest authnRequest = new AuthenticationRequest().setId("generated-request-id")
                                                                    .setSigningKey(new SigningKey("signature-key",
                                                                                                  null),
                                                                                   AlgorithmMethod.RSA_SHA256,
                                                                                   DigestMethod.SHA256);

    samlFilter.sendWithRedirectBinding(request, response, provider, authnRequest, endpoint, relayState);

    String expected = location + "?SAMLRequest=encoded-value&RelayState=" + relayState
                      + "&SigAlg=http%3A%2F%2Fwww.w3.org%2F2001%2F04%2Fxmldsig-more%23rsa-sha256"
                      + "&Signature=created-signature";
    assertEquals(expected, response.getRedirectedUrl());
  }

  @Test
  void testSendRedirectBindingResponse() throws IOException
  {
    when(signer.createSignature(anyBoolean(), any(), any(), any(), any(), any())).thenReturn("created-signature");
    when(provider.toEncodedXml(any(Saml2Object.class), anyBoolean())).thenReturn("encoded-value");

    SamlFilterTestImpl samlFilter = new SamlFilterTestImpl();
    MockHttpServletRequest request = new MockHttpServletRequest();
    MockHttpServletResponse response = new MockHttpServletResponse();

    String location = "https://localhost/saml/sp";
    Endpoint endpoint = new Endpoint().setLocation(location);
    Response r = new Response().setId("generated-response-id")
                               .setSigningKey(new SigningKey("signature-key", null),
                                              AlgorithmMethod.RSA_SHA256,
                                              DigestMethod.SHA256);

    samlFilter.sendWithRedirectBinding(request, response, provider, r, endpoint, null);

    String expected = location + "?SAMLResponse=encoded-value"
                      + "&SigAlg=http%3A%2F%2Fwww.w3.org%2F2001%2F04%2Fxmldsig-more%23rsa-sha256"
                      + "&Signature=created-signature";
    assertEquals(expected, response.getRedirectedUrl());
  }

  @Test
  void testSendRedirectBindingLogoutRequest() throws IOException
  {
    when(signer.createSignature(anyBoolean(), any(), any(), any(), any(), any())).thenReturn("created-signature");
    when(provider.toEncodedXml(any(Saml2Object.class), anyBoolean())).thenReturn("encoded-value");

    SamlFilterTestImpl samlFilter = new SamlFilterTestImpl();
    MockHttpServletRequest request = new MockHttpServletRequest();
    MockHttpServletResponse response = new MockHttpServletResponse();

    String relayState = "relay-state-value";
    String location = "https://localhost/saml/idp";
    Endpoint endpoint = new Endpoint().setLocation(location);
    LogoutRequest logoutRequest = new LogoutRequest().setId("generated-request-id")
                                                     .setDestination(endpoint)
                                                     .setSigningKey(new SigningKey("signature-key", null, null,
                                                                                   "sppassword"),
                                                                    AlgorithmMethod.RSA_SHA256,
                                                                    DigestMethod.SHA256);

    samlFilter.sendWithRedirectBinding(request, response, provider, logoutRequest, endpoint, relayState);

    String expected = location + "?SAMLRequest=encoded-value&RelayState=" + relayState;
    assertEquals(expected, response.getRedirectedUrl());
  }

  class SamlFilterTestImpl extends SamlFilter
  {

    protected SamlFilterTestImpl()
    {
      super(provisioning);
      setSamlRedirectBindingSigner(signer);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
      throws ServletException, IOException
    {
      // test impl, do nothing
    }

  }

}
