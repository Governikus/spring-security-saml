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
package org.springframework.security.samples;

import static java.util.Arrays.asList;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.notNullValue;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.springframework.security.saml.helper.SamlTestObjectHelper.queryParams;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.authentication;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.authenticated;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.unauthenticated;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.net.URI;
import java.time.Clock;
import java.util.Collections;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.stubbing.Answer;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.SpringBootConfiguration;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.saml.SamlMetadataCache;
import org.springframework.security.saml.SamlTransformer;
import org.springframework.security.saml.helper.SamlTestObjectHelper;
import org.springframework.security.saml.key.EncryptionKey;
import org.springframework.security.saml.key.SigningKey;
import org.springframework.security.saml.provider.SamlServerConfiguration;
import org.springframework.security.saml.provider.identity.AssertionEnhancer;
import org.springframework.security.saml.provider.identity.HostedIdentityProviderService;
import org.springframework.security.saml.provider.identity.IdentityProviderService;
import org.springframework.security.saml.provider.identity.ResponseEnhancer;
import org.springframework.security.saml.provider.identity.config.ExternalServiceProviderConfiguration;
import org.springframework.security.saml.provider.identity.config.LocalIdentityProviderConfiguration;
import org.springframework.security.saml.provider.provisioning.SamlProviderProvisioning;
import org.springframework.security.saml.saml2.attribute.Attribute;
import org.springframework.security.saml.saml2.authentication.Assertion;
import org.springframework.security.saml.saml2.authentication.AuthenticationRequest;
import org.springframework.security.saml.saml2.authentication.LogoutRequest;
import org.springframework.security.saml.saml2.authentication.LogoutResponse;
import org.springframework.security.saml.saml2.authentication.NameIdPolicy;
import org.springframework.security.saml.saml2.authentication.NameIdPrincipal;
import org.springframework.security.saml.saml2.authentication.Response;
import org.springframework.security.saml.saml2.authentication.StatusCode;
import org.springframework.security.saml.saml2.metadata.Binding;
import org.springframework.security.saml.saml2.metadata.Endpoint;
import org.springframework.security.saml.saml2.metadata.IdentityProviderMetadata;
import org.springframework.security.saml.saml2.metadata.Metadata;
import org.springframework.security.saml.saml2.metadata.NameId;
import org.springframework.security.saml.saml2.metadata.ServiceProviderMetadata;
import org.springframework.security.saml.spi.DefaultSessionAssertionStore;
import org.springframework.security.saml.spi.ExamplePemKey;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;


@ExtendWith(SpringExtension.class)
@SpringBootTest
@AutoConfigureMockMvc
class SimpleIdentityProviderBootTests
{

  @Autowired
  private MockMvc mockMvc;

  @Autowired
  private SamlTransformer transformer;

  @MockBean
  private SamlMetadataCache cache;

  @MockBean
  private AssertionEnhancer samlAssertionEnhancer;

  @MockBean
  private ResponseEnhancer samlResponseEnhancer;

  @Autowired
  @Qualifier("idpSamlServerConfiguration")
  private SamlServerConfiguration config;

  @Autowired
  private DefaultSessionAssertionStore sessionAssertionStore;

  @Autowired
  private SamlProviderProvisioning<HostedIdentityProviderService, LocalIdentityProviderConfiguration, IdentityProviderMetadata, ServiceProviderMetadata, ExternalServiceProviderConfiguration> provisioning;

  @Autowired
  private Clock samlTime;

  private String baseUrl = "http://localhost";

  private SamlTestObjectHelper helper;

  @BeforeEach
  public void mockCache()
  {
    // since we're using objects outside of the mock request
    config.getIdentityProvider().setBasePath(baseUrl);

    given(cache.getMetadata(eq("http://simplesaml-for-spring-saml.cfapps.io/module.php/saml/sp/metadata.php/default-sp"),
                            anyBoolean())).willReturn(CACHED_SIMPLESAML_META_DATA.getBytes());

    given(cache.getMetadata(eq("spring.security.saml.sp.id"),
                            anyBoolean())).willReturn(CACHED_SSS_META_DATA.getBytes());

    helper = new SamlTestObjectHelper(samlTime);
    given(samlAssertionEnhancer.enhance(any(Assertion.class))).willAnswer((Answer<Assertion>)invocation -> invocation.getArgument(0));

    given(samlResponseEnhancer.enhance(any(Response.class))).willAnswer((Answer<Response>)invocation -> invocation.getArgument(0));
  }

  @AfterEach
  public void resetConfiguration()
  {
    config.getIdentityProvider().setEncryptAssertions(false);
    config.getIdentityProvider().setSingleLogoutEnabled(true);
  }

  @SpringBootConfiguration
  @EnableAutoConfiguration
  @ComponentScan(basePackages = "sample")
  public static class SpringBootApplicationTestConfig
  {}

  @Test
  void testCloneConfiguration() throws CloneNotSupportedException
  {
    SamlServerConfiguration clone = config.clone();
    clone.getIdentityProvider().getProviders().get(0).setMetadata("changed");
    assertThat(config.getIdentityProvider().getProviders().get(0).getMetadata(), not(equalTo("changed")));
    assertThat(clone.getIdentityProvider().getProviders().get(0).getMetadata(), equalTo("changed"));
  }

  @Test
  void idpInitiateLogout() throws Exception
  {
    IdentityProviderMetadata idpm = getIdentityProviderMetadata();
    IdentityProviderService provider = provisioning.getHostedProvider();
    ServiceProviderMetadata spm = provider.getRemoteProvider("spring.security.saml.xml.sp.id");
    UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken("user", null,
                                                                                        Collections.emptyList());
    MvcResult mvcResult = idpToSpLogin(token, "spring.security.saml.xml.sp.id");
    MockHttpServletRequest request = mvcResult.getRequest();
    MockHttpSession session = (MockHttpSession)request.getSession(false);
    assertThat(sessionAssertionStore.size(request), equalTo(1));

    mvcResult = mockMvc.perform(get("/saml/idp/logout").session(session))
                       .andExpect(status().isFound())
                       .andExpect(header().exists("Location"))
                       .andReturn();

    String location = mvcResult.getResponse().getHeader("Location");
    assertThat(location, containsString("SAMLRequest"));
    String lrXML = queryParams(new URI(location)).get("SAMLRequest");
    LogoutRequest logoutRequest = (LogoutRequest)transformer.fromXml(transformer.samlDecode(lrXML, true),
                                                                     idpm.getIdentityProvider().getSigningKeys(),
                                                                     spm.getServiceProvider().getEncryptionKeys());
    assertNotNull(logoutRequest);
    assertThat(logoutRequest.getDestination().getLocation(), equalTo("http://localhost:8080/sample-sp/saml/sp/logout"));

    request = mvcResult.getRequest();
    assertThat(sessionAssertionStore.size(request), equalTo(0));

  }

  @Test
  void receiveLogoutRequestNoOtherParties() throws Exception
  {

    IdentityProviderMetadata idpm = getIdentityProviderMetadata();
    String spm1EntityId = "spring.security.saml.xml.sp.id";
    IdentityProviderService provider = provisioning.getHostedProvider();
    ServiceProviderMetadata spm1 = provider.getRemoteProvider(spm1EntityId);
    UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken("user", null,
                                                                                        Collections.emptyList());
    MvcResult mvcResult = idpToSpLogin(token, spm1EntityId);
    MockHttpServletRequest request = mvcResult.getRequest();
    MockHttpSession session = (MockHttpSession)request.getSession(false);
    assertNotNull(session);
    assertThat(sessionAssertionStore.size(request), equalTo(1));

    LogoutRequest logoutRequest = helper.logoutRequest(idpm,
                                                       spm1,
                                                       new NameIdPrincipal().setValue("user")
                                                                            .setFormat(NameId.PERSISTENT));

    // initiate a logout on the IDP
    mvcResult = mockMvc.perform(get("/saml/idp/logout").session(session)
                                                       .queryParam("SAMLRequest",
                                                                   transformer.samlEncode(transformer.toXml(logoutRequest),
                                                                                          true)))
                       .andExpect(status().isFound())
                       .andExpect(header().exists("Location"))
                       .andExpect(unauthenticated())
                       .andReturn();

    // extract the LogoutRequest (should be for SP1)
    String location = mvcResult.getResponse().getHeader("Location");
    assertThat(location, containsString("SAMLResponse"));
    String lrXML = queryParams(new URI(location)).get("SAMLResponse");
    LogoutResponse logoutResponse = (LogoutResponse)transformer.fromXml(transformer.samlDecode(lrXML, true),
                                                                        idpm.getIdentityProvider().getSigningKeys(),
                                                                        spm1.getServiceProvider().getEncryptionKeys());
    assertNotNull(logoutResponse);
    assertThat(logoutResponse.getDestination(), equalTo("http://localhost:8080/sample-sp/saml/sp/logout"));

    request = mvcResult.getRequest();
    session = (MockHttpSession)request.getSession(false);
    assertNull(session);
  }

  @Test
  void receiveLogoutFollowThrough() throws Exception
  {

    IdentityProviderMetadata idpm = getIdentityProviderMetadata();
    String spm1EntityId = "spring.security.saml.xml.sp.id";
    String spm2EntityId = "http://simplesaml-for-spring-saml.cfapps.io/module.php/saml/sp/metadata.php/default-sp";
    IdentityProviderService provider = provisioning.getHostedProvider();
    ServiceProviderMetadata spm1 = provider.getRemoteProvider(spm1EntityId);
    ServiceProviderMetadata spm2 = provider.getRemoteProvider(spm2EntityId);
    UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken("user", null,
                                                                                        Collections.emptyList());

    // log in to SP1
    MvcResult mvcResult = idpToSpLogin(token, spm1EntityId);
    MockHttpServletRequest request = mvcResult.getRequest();
    MockHttpSession session = (MockHttpSession)request.getSession(false);
    assertThat(sessionAssertionStore.size(request), equalTo(1));

    // log in to SP2
    mvcResult = idpToSpLogin(session, spm2EntityId);
    request = mvcResult.getRequest();

    // assert that the IDP is tracking two remote authenticated sessions
    assertThat(sessionAssertionStore.size(request), equalTo(2));

    // initiate a logout on the IDP
    mvcResult = mockMvc.perform(get("/saml/idp/logout").session(session))
                       .andExpect(status().isFound())
                       .andExpect(header().exists("Location"))
                       .andReturn();

    // extract the LogoutRequest (should be for SP1)
    String location = mvcResult.getResponse().getHeader("Location");
    assertThat(location, containsString("SAMLRequest"));
    String lrXML = queryParams(new URI(location)).get("SAMLRequest");
    LogoutRequest logoutRequest = (LogoutRequest)transformer.fromXml(transformer.samlDecode(lrXML, true),
                                                                     idpm.getIdentityProvider().getSigningKeys(),
                                                                     spm1.getServiceProvider().getEncryptionKeys());
    assertNotNull(logoutRequest);
    assertThat(logoutRequest.getDestination().getLocation(), equalTo("http://localhost:8080/sample-sp/saml/sp/logout"));

    request = mvcResult.getRequest();
    session = (MockHttpSession)request.getSession(false);
    assertThat(sessionAssertionStore.size(request), equalTo(1));

    // SP1 responds to the LogoutRequest
    LogoutResponse logoutResponse = helper.logoutResponse(logoutRequest, idpm, spm1);
    // The IDP should then create a new LogoutRequest for SP2
    mvcResult = mockMvc.perform(get("/saml/idp/logout").queryParam("SAMLResponse",
                                                                   transformer.samlEncode(transformer.toXml(logoutResponse),
                                                                                          true))
                                                       .session(session))
                       .andExpect(status().isFound())
                       .andExpect(header().exists("Location"))
                       .andExpect(authenticated())
                       .andReturn();

    // no more SP sessions tracked
    assertThat(sessionAssertionStore.size(request), equalTo(0));

    request = mvcResult.getRequest();
    location = mvcResult.getResponse().getHeader("Location");
    assertThat(location, containsString("SAMLRequest"));
    lrXML = queryParams(new URI(location)).get("SAMLRequest");
    logoutRequest = (LogoutRequest)transformer.fromXml(transformer.samlDecode(lrXML, true),
                                                       idpm.getIdentityProvider().getSigningKeys(),
                                                       spm2.getServiceProvider().getEncryptionKeys());
    assertNotNull(logoutRequest);
    assertThat(logoutRequest.getDestination().getLocation(),
               equalTo("http://simplesaml-for-spring-saml.cfapps.io/module.php/saml/sp/saml2-logout.php/default-sp"));

    // SP2 responds to the LogoutRequest
    logoutResponse = helper.logoutResponse(logoutRequest, idpm, spm2);
    mvcResult = mockMvc.perform(get("/saml/idp/logout").queryParam("SAMLResponse",
                                                                   transformer.samlEncode(transformer.toXml(logoutResponse),
                                                                                          true))
                                                       .session(session))
                       .andExpect(status().isFound())
                       .andExpect(header().exists("Location"))
                       .andExpect(unauthenticated())
                       .andReturn();

    request = mvcResult.getRequest();
    session = (MockHttpSession)request.getSession(false);
    assertNull(session);
    location = mvcResult.getResponse().getHeader("Location");

    assertThat(location, equalTo("/"));

  }

  @Test
  void testIdentityProviderMetadata() throws Exception
  {
    IdentityProviderMetadata idpm = getIdentityProviderMetadata();
    assertThat(idpm.getIdentityProvider().getSingleLogoutService().isEmpty(), equalTo(false));
    assertThat(idpm.getEntityAlias(), equalTo("spring.security.saml.idp.id"));
    for ( Endpoint ep : idpm.getIdentityProvider().getSingleSignOnService() )
    {
      assertThat(ep.getLocation(), equalTo("http://localhost/saml/idp/SSO/alias/boot-sample-idp"));
    }
    assertThat(idpm.getIdentityProvider().getNameIds(),
               containsInAnyOrder(NameId.UNSPECIFIED, NameId.PERSISTENT, NameId.EMAIL));
    Optional<SigningKey> firstSigningKey = idpm.getIdentityProvider().getSigningKeys().stream().findFirst();
    assertThat("SigningKey", firstSigningKey.isPresent(), equalTo(true));
    Optional<EncryptionKey> firstEncryptionKeys = idpm.getIdentityProvider().getEncryptionKeys().stream().findFirst();
    assertThat("EncryptionKey", firstEncryptionKeys.isPresent(), equalTo(true));
  }

  @Test
  void singleLogoutDisabledMetadata() throws Exception
  {
    config.getIdentityProvider().setSingleLogoutEnabled(false);
    IdentityProviderMetadata idpm = getIdentityProviderMetadata();
    assertThat(idpm.getIdentityProvider().getSingleLogoutService(), containsInAnyOrder());
  }

  @Test
  void idpInitiatedLogin() throws Exception
  {
    UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken("user", null,
                                                                                        Collections.emptyList());
    MvcResult result = idpToSpLogin(token, "spring.security.saml.xml.sp.id");
    String html = result.getResponse().getContentAsString();
    assertThat(html, containsString("name=\"SAMLResponse\""));
    String response = extractResponse(html, "SAMLResponse");
    Response r = (Response)transformer.fromXml(transformer.samlDecode(response, false), null, null);
    assertNotNull(r);
    assertThat(r.getAssertions(), notNullValue());
    assertThat(r.getAssertions().size(), equalTo(1));
  }

  @Test
  void enhancedAssertion() throws Exception
  {
    reset(samlAssertionEnhancer);
    given(samlAssertionEnhancer.enhance(any(Assertion.class))).willAnswer(invocation -> {
      Assertion original = invocation.getArgument(0);
      original.addAttribute(new Attribute().setName("test")
                                           .setFriendlyName("testFriendly")
                                           .setValues(asList("testValue1", "testValue2")));
      return original;
    });
    UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken("user", null,
                                                                                        Collections.emptyList());
    MvcResult result = idpToSpLogin(token, "spring.security.saml.xml.sp.id");
    String html = result.getResponse().getContentAsString();
    assertThat(html, containsString("name=\"SAMLResponse\""));
    String response = extractResponse(html, "SAMLResponse");
    Response r = (Response)transformer.fromXml(transformer.samlDecode(response, false), null, null);
    assertNotNull(r);
    assertThat(r.getAssertions(), notNullValue());
    assertThat(r.getAssertions().size(), equalTo(1));
    Attribute test = r.getAssertions().get(0).getFirstAttribute("test");
    assertNotNull(test);
    assertThat(test.getName(), equalTo("test"));
    assertThat(test.getFriendlyName(), equalTo("testFriendly"));
    assertThat(test.getValues(), containsInAnyOrder("testValue1", "testValue2"));
    verify(samlResponseEnhancer, times(1)).enhance(any(Response.class));
  }

  @Test
  void idpInitiatedLoginGeneratedEncryptedAssertion() throws Exception
  {
    config.getIdentityProvider().setEncryptAssertions(true);
    UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken("user", null,
                                                                                        Collections.emptyList());
    MvcResult result = idpToSpLogin(token, "spring.security.saml.xml.sp.id");
    String html = result.getResponse().getContentAsString();
    assertThat(html, containsString("name=\"SAMLResponse\""));
    String response = extractResponse(html, "SAMLResponse");
    String decodedXml = transformer.samlDecode(response, false);
    assertThat(decodedXml, containsString("xenc:CipherValue"));
    assertThat(decodedXml, containsString("saml2:EncryptedAssertion"));
    Response r = (Response)transformer.fromXml(decodedXml,
                                               null,
                                               asList(ExamplePemKey.RSA_TEST_KEY.getEncryptionKey("encryption")));
    assertNotNull(r);
    assertThat(r.getAssertions(), notNullValue());
    assertThat(r.getAssertions().size(), equalTo(1));
  }

  @Test
  void receiveAuthenticationRequest() throws Exception
  {
    IdentityProviderService provider = provisioning.getHostedProvider();
    IdentityProviderMetadata local = provider.getMetadata();
    ServiceProviderMetadata sp = provider.getRemoteProvider("spring.security.saml.xml.sp.id");
    assertNotNull(sp);

    AuthenticationRequest authenticationRequest = helper.authenticationRequest(sp, local);
    String xml = transformer.toXml(authenticationRequest);
    String deflated = transformer.samlEncode(xml, true);

    UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken("user", null,
                                                                                        Collections.emptyList());
    MvcResult result = mockMvc.perform(get("/saml/idp/SSO/alias/boot-sample-idp?SAMLRequest="
                                           + deflated).with(authentication(token)))
                              .andExpect(status().isOk())
                              .andReturn();
    String html = result.getResponse().getContentAsString();
    assertThat(html, containsString("name=\"SAMLResponse\""));
    String response = extractResponse(html, "SAMLResponse");
    Response r = (Response)transformer.fromXml(transformer.samlDecode(response, false), null, null);
    assertNotNull(r);
    assertThat(r.getAssertions(), notNullValue());
    assertThat(r.getAssertions().size(), equalTo(1));
  }

  /**
   * AuthnRequest contains invalid NameID format, check that error response is returned
   */
  @Test
  void receiveAuthenticationRequestReturnErrorResponse() throws Exception
  {
    IdentityProviderService provider = provisioning.getHostedProvider();
    IdentityProviderMetadata local = provider.getMetadata();
    ServiceProviderMetadata sp = provider.getRemoteProvider("spring.security.saml.xml.sp.id");
    assertNotNull(sp);

    AuthenticationRequest authenticationRequest = helper.authenticationRequest(sp, local);
    authenticationRequest.setNameIdPolicy(new NameIdPolicy().setFormat(NameId.UNSPECIFIED)); // invalid NameIDPolicy
    String xml = transformer.toXml(authenticationRequest);
    String deflated = transformer.samlEncode(xml, true);

    UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken("user", null,
                                                                                        Collections.emptyList());
    MvcResult result = mockMvc.perform(get("/saml/idp/SSO/alias/boot-sample-idp?SAMLRequest="
                                           + deflated).with(authentication(token)))
                              .andExpect(status().isOk())
                              .andExpect(content().string(containsString("name=\"SAMLResponse\"")))
                              .andReturn();
    String html = result.getResponse().getContentAsString();
    String response = extractResponse(html, "SAMLResponse");
    Response r = (Response)transformer.fromXml(transformer.samlDecode(response, false), null, null);
    assertNotNull(r);
    assertThat(r.getAssertions(), notNullValue());
    assertThat(r.getAssertions().size(), equalTo(0));
    assertNotNull(r.getStatus());
    assertThat(r.getStatus().getCode(), equalTo(StatusCode.REQUESTER));
    assertThat(r.getStatus().getMinorCode(), equalTo(StatusCode.INVALID_NAME_ID));
  }

  /**
   * AuthnRequest contains invalid assertion consumer service, check that error page is displayed
   */
  @Test
  void receiveInvalidAuthenticationRequestReturnErrorTemplate() throws Exception
  {
    IdentityProviderService provider = provisioning.getHostedProvider();
    IdentityProviderMetadata local = provider.getMetadata();
    ServiceProviderMetadata sp = provider.getRemoteProvider("spring.security.saml.xml.sp.id");
    assertNotNull(sp);

    AuthenticationRequest authenticationRequest = helper.authenticationRequest(sp, local);
    authenticationRequest.setAssertionConsumerService(new Endpoint().setBinding(Binding.ARTIFACT).setIndex(-1));
    String xml = transformer.toXml(authenticationRequest);
    String deflated = transformer.samlEncode(xml, true);

    UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken("user", null,
                                                                                        Collections.emptyList());
    mockMvc.perform(get("/saml/idp/SSO/alias/boot-sample-idp?SAMLRequest=" + deflated).with(authentication(token)))
           .andExpect(status().isOk())
           .andExpect(content().string(containsString("A SAML error occurred")))
           .andExpect(content().string(not(containsString("name=\"SAMLResponse\""))));
  }

  @Test
  void selectServiceProvider() throws Exception
  {
    UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken("user", null,
                                                                                        Collections.emptyList());
    mockMvc.perform(get("/saml/idp/select").accept(MediaType.TEXT_HTML).with(authentication(token)))
           .andExpect(status().isOk())
           .andExpect(content().string(containsString("<h1>Select a Service Provider</h1>")))
           .andExpect(content().string(containsString("Simple SAML PHP SP")))
           .andExpect(content().string(containsString("Example SP Config Using XML")))
           .andReturn();
  }

  protected IdentityProviderMetadata getIdentityProviderMetadata() throws Exception
  {
    MvcResult result = mockMvc.perform(get("/saml/idp/metadata")).andExpect(status().isOk()).andReturn();
    String xml = result.getResponse().getContentAsString();
    Metadata m = (Metadata)transformer.fromXml(xml, null, null);
    assertNotNull(m);
    assertThat(m.getClass(), equalTo(IdentityProviderMetadata.class));
    return (IdentityProviderMetadata)m;
  }

  private String extractResponse(String html, String name)
  {
    Pattern p = Pattern.compile(" name=\"(.*?)\" value=\"(.*?)\"");
    Matcher m = p.matcher(html);
    while (m.find())
    {
      String pname = m.group(1);
      String value = m.group(2);
      if (name.equals(pname))
      {
        return value;
      }
    }
    return null;
  }

  public static final String CACHED_SIMPLESAML_META_DATA = "<?xml version=\"1.0\"?>\n"
                                                           + "<md:EntityDescriptor ID=\"pfx5adc5a2c-6518-b025-b3f1-90cbaa59075f\" entityID=\"http://simplesaml-for-spring-saml.cfapps.io/module.php/saml/sp/metadata.php/default-sp\" xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\">\n"
                                                           + "\t<ds:Signature xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\n"
                                                           + "\t\t<ds:SignedInfo>\n"
                                                           + "\t\t\t<ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n"
                                                           + "\t\t\t<ds:SignatureMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#rsa-sha1\"/>\n"
                                                           + "\t\t\t<ds:Reference URI=\"#pfx5adc5a2c-6518-b025-b3f1-90cbaa59075f\">\n"
                                                           + "\t\t\t\t<ds:Transforms>\n"
                                                           + "\t\t\t\t\t<ds:Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/>\n"
                                                           + "\t\t\t\t\t<ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n"
                                                           + "\t\t\t\t</ds:Transforms>\n"
                                                           + "\t\t\t\t<ds:DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"/>\n"
                                                           + "\t\t\t\t<ds:DigestValue>FhDHN8ZwPqVrOhRwNtdGh6mDt2o=</ds:DigestValue>\n"
                                                           + "\t\t\t</ds:Reference>\n" + "\t\t</ds:SignedInfo>\n"
                                                           + "\t\t<ds:SignatureValue>SNf1KPwsl6qmO9PVi0i3P8EdGTebHu43/wTNhi5eHcguMOfq+rLBHur0mfXa3/ZcDTvey4/hBKsROKUIvevu+uuS6/6vzNl0OZiVbIpNX43CyHAC1ly/P1sHvOvdh7YNx24eKo7lEefRSGFNgEWzPc9rrClD2SL4pdINgb7M6Ppn8dzVzLfPeJDj8Epx4TS8N8v8VH8YnPbtcMXz+AvALVBuo7ZpN+Ws2CjKH5d9XoN4WEhqBOFNBblM9XSwC14JlKqkRiiZYvjWy2/+J9bkscQpAlzXE58FF/COX1aw/G7sJRCMm2w7AWjLbHGS/suu9ZAj55sB6wGn2Nt3GoRU+Q==</ds:SignatureValue>\n"
                                                           + "\t\t<ds:KeyInfo>\n" + "\t\t\t<ds:X509Data>\n"
                                                           + "\t\t\t\t<ds:X509Certificate>MIIEEzCCAvugAwIBAgIJAIc1qzLrv+5nMA0GCSqGSIb3DQEBCwUAMIGfMQswCQYDVQQGEwJVUzELMAkGA1UECAwCQ08xFDASBgNVBAcMC0Nhc3RsZSBSb2NrMRwwGgYDVQQKDBNTYW1sIFRlc3RpbmcgU2VydmVyMQswCQYDVQQLDAJJVDEgMB4GA1UEAwwXc2ltcGxlc2FtbHBocC5jZmFwcHMuaW8xIDAeBgkqhkiG9w0BCQEWEWZoYW5pa0BwaXZvdGFsLmlvMB4XDTE1MDIyMzIyNDUwM1oXDTI1MDIyMjIyNDUwM1owgZ8xCzAJBgNVBAYTAlVTMQswCQYDVQQIDAJDTzEUMBIGA1UEBwwLQ2FzdGxlIFJvY2sxHDAaBgNVBAoME1NhbWwgVGVzdGluZyBTZXJ2ZXIxCzAJBgNVBAsMAklUMSAwHgYDVQQDDBdzaW1wbGVzYW1scGhwLmNmYXBwcy5pbzEgMB4GCSqGSIb3DQEJARYRZmhhbmlrQHBpdm90YWwuaW8wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC4cn62E1xLqpN34PmbrKBbkOXFjzWgJ9b+pXuaRft6A339uuIQeoeH5qeSKRVTl32L0gdz2ZivLwZXW+cqvftVW1tvEHvzJFyxeTW3fCUeCQsebLnA2qRa07RkxTo6Nf244mWWRDodcoHEfDUSbxfTZ6IExSojSIU2RnD6WllYWFdD1GFpBJOmQB8rAc8wJIBdHFdQnX8Ttl7hZ6rtgqEYMzYVMuJ2F2r1HSU1zSAvwpdYP6rRGFRJEfdA9mm3WKfNLSc5cljz0X/TXy0vVlAV95l9qcfFzPmrkNIst9FZSwpvB49LyAVke04FQPPwLgVH4gphiJH3jvZ7I+J5lS8VAgMBAAGjUDBOMB0GA1UdDgQWBBTTyP6Cc5HlBJ5+ucVCwGc5ogKNGzAfBgNVHSMEGDAWgBTTyP6Cc5HlBJ5+ucVCwGc5ogKNGzAMBgNVHRMEBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQAvMS4EQeP/ipV4jOG5lO6/tYCb/iJeAduOnRhkJk0DbX329lDLZhTTL/x/w/9muCVcvLrzEp6PN+VWfw5E5FWtZN0yhGtP9R+vZnrV+oc2zGD+no1/ySFOe3EiJCO5dehxKjYEmBRv5sU/LZFKZpozKN/BMEa6CqLuxbzb7ykxVr7EVFXwltPxzE9TmL9OACNNyF5eJHWMRMllarUvkcXlh4pux4ks9e6zV9DQBy2zds9f1I3qxg0eX6JnGrXi/ZiCT+lJgVe3ZFXiejiLAiKB04sXW3ti0LW3lx13Y1YlQ4/tlpgTgfIJxKV6nyPiLoK0nywbMd+vpAirDt2Oc+hk</ds:X509Certificate>\n"
                                                           + "\t\t\t</ds:X509Data>\n" + "\t\t</ds:KeyInfo>\n"
                                                           + "\t</ds:Signature>\n"
                                                           + "\t<md:SPSSODescriptor protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:1.1:protocol urn:oasis:names:tc:SAML:2.0:protocol\">\n"
                                                           + "\t\t<md:SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"http://simplesaml-for-spring-saml.cfapps.io/module.php/saml/sp/saml2-logout.php/default-sp\"/>\n"
                                                           + "\t\t<md:AssertionConsumerService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"http://simplesaml-for-spring-saml.cfapps.io/module.php/saml/sp/saml2-acs.php/default-sp\" index=\"0\"/>\n"
                                                           + "\t\t<md:AssertionConsumerService Binding=\"urn:oasis:names:tc:SAML:1.0:profiles:browser-post\" Location=\"http://simplesaml-for-spring-saml.cfapps.io/module.php/saml/sp/saml1-acs.php/default-sp\" index=\"1\"/>\n"
                                                           + "\t\t<md:AssertionConsumerService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact\" Location=\"http://simplesaml-for-spring-saml.cfapps.io/module.php/saml/sp/saml2-acs.php/default-sp\" index=\"2\"/>\n"
                                                           + "\t\t<md:AssertionConsumerService Binding=\"urn:oasis:names:tc:SAML:1.0:profiles:artifact-01\" Location=\"http://simplesaml-for-spring-saml.cfapps.io/module.php/saml/sp/saml1-acs.php/default-sp/artifact\" index=\"3\"/>\n"
                                                           + "\t</md:SPSSODescriptor>\n"
                                                           + "\t<md:ContactPerson contactType=\"technical\">\n"
                                                           + "\t\t<md:GivenName>Filip</md:GivenName>\n"
                                                           + "\t\t<md:SurName>Hanik</md:SurName>\n"
                                                           + "\t\t<md:EmailAddress>fhanik@pivotal.io</md:EmailAddress>\n"
                                                           + "\t</md:ContactPerson>\n" + "</md:EntityDescriptor>";

  public static final String CACHED_SSS_META_DATA = "\n"
                                                    + "<md:EntityDescriptor ID=\"dfc08e8f-ab6e-4682-aa34-6e7fcd812892\" entityID=\"spring.security.saml.sp.id\" xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\"><ds:Signature xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\n"
                                                    + "<ds:SignedInfo>\n"
                                                    + "<ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n"
                                                    + "<ds:SignatureMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#rsa-sha1\"/>\n"
                                                    + "<ds:Reference URI=\"#dfc08e8f-ab6e-4682-aa34-6e7fcd812892\">\n"
                                                    + "<ds:Transforms>\n"
                                                    + "<ds:Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/>\n"
                                                    + "<ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n"
                                                    + "</ds:Transforms>\n"
                                                    + "<ds:DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"/>\n"
                                                    + "<ds:DigestValue>SMvLzAh6oFKgdeC0bfQrzM6fZbk=</ds:DigestValue>\n"
                                                    + "</ds:Reference>\n" + "</ds:SignedInfo>\n"
                                                    + "<ds:SignatureValue>\n"
                                                    + "P6bbFySzan13eW77u8qs3DdYJWl65zFK0vbPLHbPWcsl2m9JwI++4iQP5QSwrde9AlHRDqOK6wUv\n"
                                                    + "UauUWqSG4mIiPb0/r9l12+stSGrjtkLU44Md+04UK1/fWOiGXKkpDVlrKirvw3RCYOtIcvGv2rqd\n"
                                                    + "nBMyf6B6PiBW1RhSlp0=\n" + "</ds:SignatureValue>\n"
                                                    + "<ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIICgTCCAeoCCQCuVzyqFgMSyDANBgkqhkiG9w0BAQsFADCBhDELMAkGA1UEBhMCVVMxEzARBgNV\n"
                                                    + "BAgMCldhc2hpbmd0b24xEjAQBgNVBAcMCVZhbmNvdXZlcjEdMBsGA1UECgwUU3ByaW5nIFNlY3Vy\n"
                                                    + "aXR5IFNBTUwxCzAJBgNVBAsMAnNwMSAwHgYDVQQDDBdzcC5zcHJpbmcuc2VjdXJpdHkuc2FtbDAe\n"
                                                    + "Fw0xODA1MTQxNDMwNDRaFw0yODA1MTExNDMwNDRaMIGEMQswCQYDVQQGEwJVUzETMBEGA1UECAwK\n"
                                                    + "V2FzaGluZ3RvbjESMBAGA1UEBwwJVmFuY291dmVyMR0wGwYDVQQKDBRTcHJpbmcgU2VjdXJpdHkg\n"
                                                    + "U0FNTDELMAkGA1UECwwCc3AxIDAeBgNVBAMMF3NwLnNwcmluZy5zZWN1cml0eS5zYW1sMIGfMA0G\n"
                                                    + "CSqGSIb3DQEBAQUAA4GNADCBiQKBgQDRu7/EI0BlNzMEBFVAcbx+lLosvzIWU+01dGTY8gBdhMQN\n"
                                                    + "YKZ92lMceo2CuVJ66cUURPym3i7nGGzoSnAxAre+0YIM+U0razrWtAUE735bkcqELZkOTZLelaoO\n"
                                                    + "ztmWqRbe5OuEmpewH7cx+kNgcVjdctOGy3Q6x+I4qakY/9qhBQIDAQABMA0GCSqGSIb3DQEBCwUA\n"
                                                    + "A4GBAAeViTvHOyQopWEiXOfI2Z9eukwrSknDwq/zscR0YxwwqDBMt/QdAODfSwAfnciiYLkmEjlo\n"
                                                    + "zWRtOeN+qK7UFgP1bRl5qksrYX5S0z2iGJh0GvonLUt3e20Ssfl5tTEDDnAEUMLfBkyaxEHDRZ/n\n"
                                                    + "bTJ7VTeZOSyRoVn5XHhpuJ0B</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature><md:SPSSODescriptor AuthnRequestsSigned=\"true\" ID=\"cabd4887-532f-4259-822f-960c55de6249\" WantAssertionsSigned=\"true\" protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\"><md:Extensions/><md:KeyDescriptor use=\"signing\"><ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"><ds:X509Data><ds:X509Certificate>MIICgTCCAeoCCQCuVzyqFgMSyDANBgkqhkiG9w0BAQsFADCBhDELMAkGA1UEBhMCVVMxEzARBgNV\n"
                                                    + "BAgMCldhc2hpbmd0b24xEjAQBgNVBAcMCVZhbmNvdXZlcjEdMBsGA1UECgwUU3ByaW5nIFNlY3Vy\n"
                                                    + "aXR5IFNBTUwxCzAJBgNVBAsMAnNwMSAwHgYDVQQDDBdzcC5zcHJpbmcuc2VjdXJpdHkuc2FtbDAe\n"
                                                    + "Fw0xODA1MTQxNDMwNDRaFw0yODA1MTExNDMwNDRaMIGEMQswCQYDVQQGEwJVUzETMBEGA1UECAwK\n"
                                                    + "V2FzaGluZ3RvbjESMBAGA1UEBwwJVmFuY291dmVyMR0wGwYDVQQKDBRTcHJpbmcgU2VjdXJpdHkg\n"
                                                    + "U0FNTDELMAkGA1UECwwCc3AxIDAeBgNVBAMMF3NwLnNwcmluZy5zZWN1cml0eS5zYW1sMIGfMA0G\n"
                                                    + "CSqGSIb3DQEBAQUAA4GNADCBiQKBgQDRu7/EI0BlNzMEBFVAcbx+lLosvzIWU+01dGTY8gBdhMQN\n"
                                                    + "YKZ92lMceo2CuVJ66cUURPym3i7nGGzoSnAxAre+0YIM+U0razrWtAUE735bkcqELZkOTZLelaoO\n"
                                                    + "ztmWqRbe5OuEmpewH7cx+kNgcVjdctOGy3Q6x+I4qakY/9qhBQIDAQABMA0GCSqGSIb3DQEBCwUA\n"
                                                    + "A4GBAAeViTvHOyQopWEiXOfI2Z9eukwrSknDwq/zscR0YxwwqDBMt/QdAODfSwAfnciiYLkmEjlo\n"
                                                    + "zWRtOeN+qK7UFgP1bRl5qksrYX5S0z2iGJh0GvonLUt3e20Ssfl5tTEDDnAEUMLfBkyaxEHDRZ/n\n"
                                                    + "bTJ7VTeZOSyRoVn5XHhpuJ0B</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor><md:KeyDescriptor use=\"signing\"><ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"><ds:X509Data><ds:X509Certificate>MIICgTCCAeoCCQCQqf5mvKPOpzANBgkqhkiG9w0BAQsFADCBhDELMAkGA1UEBhMCVVMxEzARBgNV\n"
                                                    + "BAgMCldhc2hpbmd0b24xEjAQBgNVBAcMCVZhbmNvdXZlcjEdMBsGA1UECgwUU3ByaW5nIFNlY3Vy\n"
                                                    + "aXR5IFNBTUwxCzAJBgNVBAsMAnNwMSAwHgYDVQQDDBdzcC5zcHJpbmcuc2VjdXJpdHkuc2FtbDAe\n"
                                                    + "Fw0xODA1MTQxNDQ0NDZaFw0yODA1MTExNDQ0NDZaMIGEMQswCQYDVQQGEwJVUzETMBEGA1UECAwK\n"
                                                    + "V2FzaGluZ3RvbjESMBAGA1UEBwwJVmFuY291dmVyMR0wGwYDVQQKDBRTcHJpbmcgU2VjdXJpdHkg\n"
                                                    + "U0FNTDELMAkGA1UECwwCc3AxIDAeBgNVBAMMF3NwLnNwcmluZy5zZWN1cml0eS5zYW1sMIGfMA0G\n"
                                                    + "CSqGSIb3DQEBAQUAA4GNADCBiQKBgQCXJXpaDE6QmY9eN9pwcG8k/54aK9YLzRgln64hZ6mvdK+O\n"
                                                    + "IIBB5E2Pgenfc3Pi8pF0B9dGUbbNK8+8L6HcZRT/3aXMWlJsENJdMS13pnmSFimsTqoxYnayc2Ea\n"
                                                    + "HULtvhMvLKf7UPRwX4jzxLanc6R4IcULJZ/dg9gBT5KDlm164wIDAQABMA0GCSqGSIb3DQEBCwUA\n"
                                                    + "A4GBAHDyh2B4AZ1C9LSigis+sAiVJIzODsnKg8pIWGI7bcFUK+i/Vj7qlx09ZD/GbrQts87Yp4aq\n"
                                                    + "+5OqVqb5n6bS8DWB8jHCoHC5HACSBb3J7x/mC0PBsKXA9A8NSFzScErvfD/ACjWg3DJEghxnlqAV\n"
                                                    + "Tm/DQX/t8kNTdrLdlzsYTuE0</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor><md:KeyDescriptor use=\"signing\"><ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"><ds:X509Data><ds:X509Certificate>MIICgTCCAeoCCQC3dvhia5XvzjANBgkqhkiG9w0BAQsFADCBhDELMAkGA1UEBhMCVVMxEzARBgNV\n"
                                                    + "BAgMCldhc2hpbmd0b24xEjAQBgNVBAcMCVZhbmNvdXZlcjEdMBsGA1UECgwUU3ByaW5nIFNlY3Vy\n"
                                                    + "aXR5IFNBTUwxCzAJBgNVBAsMAnNwMSAwHgYDVQQDDBdzcC5zcHJpbmcuc2VjdXJpdHkuc2FtbDAe\n"
                                                    + "Fw0xODA1MTQxNDQ1MzBaFw0yODA1MTExNDQ1MzBaMIGEMQswCQYDVQQGEwJVUzETMBEGA1UECAwK\n"
                                                    + "V2FzaGluZ3RvbjESMBAGA1UEBwwJVmFuY291dmVyMR0wGwYDVQQKDBRTcHJpbmcgU2VjdXJpdHkg\n"
                                                    + "U0FNTDELMAkGA1UECwwCc3AxIDAeBgNVBAMMF3NwLnNwcmluZy5zZWN1cml0eS5zYW1sMIGfMA0G\n"
                                                    + "CSqGSIb3DQEBAQUAA4GNADCBiQKBgQC2iAUrJXrHaSOWrU95v8GUGVVl5vWrYrNRFtsK5qkhB/nR\n"
                                                    + "bL08CbqIeD4pkJuIg0LuJdsBuMtYqOnhQSFF5tT36OIdld9SfPA5m8zqPLsCcjWPQ66xoMdReEXN\n"
                                                    + "9E8s/mZOXn3jkKIqywUxJ+wkS5qoBlvmShwDff+igFlF/fBfpwIDAQABMA0GCSqGSIb3DQEBCwUA\n"
                                                    + "A4GBACDBjvIpc1/2yZ3TQe29bKif5pr/3NdKz4MWBJ6vjRk7Bs2hbPrM2ajxLbqPx6PRPeTOw5XZ\n"
                                                    + "grufDj9HmrvKHM2LZTp/cIUpxcNpVRyDA4iVNDc7V3qszaWP9ZIswAYnvmyDL2UHVDLE8xoGz/Ak\n"
                                                    + "xsRNN9VXNHewjQO605umiAKJ</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor><md:SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"http://localhost:8080/sample-sp/saml/sp/logout\"/><md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:persistent</md:NameIDFormat><md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat><md:AssertionConsumerService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"http://localhost:8080/sample-sp/saml/sp/SSO\" index=\"0\" isDefault=\"true\"/><md:AssertionConsumerService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"http://localhost:8080/sample-sp/saml/sp/SSO\" index=\"1\" isDefault=\"false\"/><md:AttributeConsumingService index=\"0\" isDefault=\"true\"/></md:SPSSODescriptor></md:EntityDescriptor>";



  private MvcResult idpToSpLogin(MockHttpSession session, String spEntityId) throws Exception
  {
    return mockMvc.perform(get("/saml/idp/init").queryParam("sp", spEntityId).session(session))
                  .andExpect(status().isOk())
                  .andReturn();
  }

  private MvcResult idpToSpLogin(UsernamePasswordAuthenticationToken token, String spEntityId) throws Exception
  {
    return mockMvc.perform(get("/saml/idp/init").queryParam("sp", spEntityId).with(authentication(token)))
                  .andExpect(status().isOk())
                  .andReturn();
  }
}
