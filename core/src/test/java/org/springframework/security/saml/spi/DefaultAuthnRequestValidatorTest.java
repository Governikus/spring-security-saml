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
package org.springframework.security.saml.spi;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.security.saml.saml2.authentication.AuthenticationContextClassReference.AuthenticationContextClassReferenceType.PASSWORD;
import static org.springframework.security.saml.saml2.authentication.AuthenticationContextClassReference.AuthenticationContextClassReferenceType.PREVIOUS_SESSION;
import static org.springframework.security.saml.saml2.authentication.AuthenticationContextClassReference.AuthenticationContextClassReferenceType.UNSPECIFIED;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.stream.Stream;

import org.joda.time.DateTime;
import org.joda.time.Instant;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.opensaml.saml.common.SAMLVersion;
import org.springframework.security.saml.saml2.authentication.AuthenticationContextClassReference;
import org.springframework.security.saml.saml2.authentication.AuthenticationRequest;
import org.springframework.security.saml.saml2.authentication.Issuer;
import org.springframework.security.saml.saml2.authentication.NameIdPolicy;
import org.springframework.security.saml.saml2.authentication.StatusCode;
import org.springframework.security.saml.saml2.metadata.Binding;
import org.springframework.security.saml.saml2.metadata.Endpoint;
import org.springframework.security.saml.saml2.metadata.IdentityProvider;
import org.springframework.security.saml.saml2.metadata.IdentityProviderMetadata;
import org.springframework.security.saml.saml2.metadata.NameId;
import org.springframework.security.saml.saml2.metadata.ServiceProvider;
import org.springframework.security.saml.saml2.metadata.ServiceProviderMetadata;
import org.springframework.security.saml.saml2.signature.Signature;
import org.springframework.security.saml.validation.ValidationResult;


class DefaultAuthnRequestValidatorTest
{

  private static final String SERVICE_PROVIDER_ENTITY_ID = "ServiceProviderEntityID";

  private static final int RESPONSE_TIME = (int)TimeUnit.MINUTES.toMillis(2);

  final static int CHECK_BOUNDARIES = RESPONSE_TIME + 1;

  ServiceProviderMetadata requester;

  IdentityProviderMetadata responder;

  AuthenticationRequest authnRequest;

  @BeforeEach
  public void init()
  {
    requester = createServiceProviderMetadata();
    responder = createIdentityProviderMetadata();
    authnRequest = createRequest();
  }

  @Test
  void testValidAuthnRequest()
  {
    ValidationResult validationResult = new DefaultAuthnRequestValidator().validate(authnRequest,
                                                                                    requester,
                                                                                    responder,
                                                                                    Instant.now());
    assertFalse(validationResult.hasErrors(), validationResult.toString());
  }

  @Test
  void testNullInputs()
  {
    ValidationResult validationResult = new DefaultAuthnRequestValidator().validate(authnRequest,
                                                                                    null,
                                                                                    responder,
                                                                                    Instant.now());
    assertEquals("Remote service provider is null.", validationResult.getErrors().get(0).toString());


    validationResult = new DefaultAuthnRequestValidator().validate(authnRequest, requester, null, Instant.now());
    assertEquals("Identity provider is null.", validationResult.getErrors().get(0).toString());
    assertNull(validationResult.getErrorStatus());
  }

  static Stream<Arguments> invalidIssuer()
  {
    return Stream.of(Arguments.of(null, "Issuer is missing."),
                     Arguments.of(new Issuer().setValue("invalid issuer value"), "Issuer mismatches entity id."),
                     Arguments.of(new Issuer().setValue(SERVICE_PROVIDER_ENTITY_ID)
                                              .setFormat(NameId.EMAIL),
                                  "Issuer name format mismatch. Expected: '" + NameId.ENTITY + "' Actual: '"
                                                                        + NameId.EMAIL + "'"));
  }

  @ParameterizedTest(name = "Test invalid issuer, expect {1}")
  @MethodSource({"invalidIssuer"})
  void testIssuer(Issuer issuer, String expectedErrorMessage)
  {
    authnRequest.setIssuer(issuer);

    ValidationResult validationResult = new DefaultAuthnRequestValidator().validate(authnRequest,
                                                                                    requester,
                                                                                    responder,
                                                                                    Instant.now());
    assertEquals(expectedErrorMessage, validationResult.getErrors().get(0).toString());
    assertNull(validationResult.getErrorStatus());
  }

  static Stream<Arguments> invalidAssertionConsumer()
  {
    return Stream.of(Arguments.of(new Endpoint().setLocation("WrongAssertionConsumerServiceURL")
                                                .setBinding(Binding.POST)
                                                .setIndex(-1),
                                  "Invalid assertion consumer url value."),
                     Arguments.of(new Endpoint().setLocation("DummyAssertionConsumerServiceURL")
                                                .setBinding(Binding.REDIRECT)
                                                .setIndex(2),
                                  "Too many assertion consumers."),
                     Arguments.of(new Endpoint().setLocation("DummyAssertionConsumerServiceURL")
                                                .setBinding(null)
                                                .setIndex(2),
                                  "Invalid assertion consumer index value."));
  }

  @ParameterizedTest(name = "Test invalid AssertionConsumerService, expect {1}")
  @MethodSource({"invalidAssertionConsumer"})
  void testAssertionConsumer(Endpoint assertionConsumerService, String expectedErrorMessage)
  {
    authnRequest.setAssertionConsumerService(assertionConsumerService);

    ValidationResult validationResult = new DefaultAuthnRequestValidator().validate(authnRequest,
                                                                                    requester,
                                                                                    responder,
                                                                                    Instant.now());
    assertEquals(expectedErrorMessage, validationResult.getErrors().get(0).toString());
    assertNull(validationResult.getErrorStatus());
  }

  @Test
  void testSamlVersion()
  {
    authnRequest.setVersion(SAMLVersion.VERSION_11.toString());

    ValidationResult validationResult = new DefaultAuthnRequestValidator().validate(authnRequest,
                                                                                    requester,
                                                                                    responder,
                                                                                    Instant.now());
    assertEquals("SAML version is not 2.0.", validationResult.getErrors().get(0).toString());
    assertNotNull(validationResult.getErrorStatus());
    assertEquals(StatusCode.VERSION_MISMATCH, validationResult.getErrorStatus().getCode());
    assertEquals(StatusCode.REQUEST_VERSION_TOO_LOW, validationResult.getErrorStatus().getMinorCode());
  }

  @Test
  void testMissingNameIdPolicy()
  {
    authnRequest.setNameIdPolicy(null);

    ValidationResult validationResult = new DefaultAuthnRequestValidator().validate(authnRequest,
                                                                                    requester,
                                                                                    responder,
                                                                                    Instant.now());
    assertEquals("Missing NameIDPolicy.", validationResult.getErrors().get(0).toString());
    assertNotNull(validationResult.getErrorStatus());
    assertEquals(StatusCode.REQUESTER, validationResult.getErrorStatus().getCode());
    assertEquals(StatusCode.INVALID_NAME_ID, validationResult.getErrorStatus().getMinorCode());
  }

  @Test
  void testInvalidNameIdPolicy()
  {
    authnRequest.getNameIdPolicy().setFormat(NameId.EMAIL);

    ValidationResult validationResult = new DefaultAuthnRequestValidator().validate(authnRequest,
                                                                                    requester,
                                                                                    responder,
                                                                                    Instant.now());
    assertEquals("Invalid NameIDPolicy format.", validationResult.getErrors().get(0).toString());
    assertNotNull(validationResult.getErrorStatus());
    assertEquals(StatusCode.REQUESTER, validationResult.getErrorStatus().getCode());
    assertEquals(StatusCode.INVALID_NAME_ID, validationResult.getErrorStatus().getMinorCode());

    DefaultAuthnRequestValidator otherValidator = new DefaultAuthnRequestValidator(RESPONSE_TIME, NameId.EMAIL, null,
                                                                                   null, null, null);
    validationResult = otherValidator.validate(authnRequest, requester, responder, Instant.now());
    assertFalse(validationResult.hasErrors());
  }

  /**
   * Add 120001 milliseconds and remove 120001 milliseconds (RESPONSE_TIME time is 2 minutes) to check boundaries
   */
  static Stream<Arguments> invalidIssueInstant()
  {
    return Stream.of(Arguments.of(Instant.now(), "Issue time is either too old or in the future.", CHECK_BOUNDARIES),
                     Arguments.of(null, "Issue time is either too old or in the future.", 0),
                     Arguments.of(Instant.now(), "Issue time is either too old or in the future.", -CHECK_BOUNDARIES));
  }

  @ParameterizedTest
  @MethodSource({"invalidIssueInstant"})
  void testInvalidIssueInstant(Instant issueInstant, String expectedErrorMessage, int changeTimeMilliseconds)
  {
    authnRequest.setIssueInstant(issueInstant == null ? null : issueInstant.plus(changeTimeMilliseconds).toDateTime());

    ValidationResult validationResult = new DefaultAuthnRequestValidator().validate(authnRequest,
                                                                                    requester,
                                                                                    responder,
                                                                                    issueInstant);

    assertEquals(expectedErrorMessage, validationResult.getErrors().get(0).toString());
    assertNotNull(validationResult.getErrorStatus());
    assertEquals(StatusCode.REQUESTER, validationResult.getErrorStatus().getCode());
    assertEquals(StatusCode.REQUEST_DENIED, validationResult.getErrorStatus().getMinorCode());
  }

  @Test
  void testDestination()
  {
    authnRequest.getDestination().setLocation("FalseLocation");

    ValidationResult validationResult = new DefaultAuthnRequestValidator().validate(authnRequest,
                                                                                    requester,
                                                                                    responder,
                                                                                    Instant.now());

    assertEquals("Invalid destination value.", validationResult.getErrors().get(0).toString());
    assertNotNull(validationResult.getErrorStatus());
    assertEquals(StatusCode.REQUESTER, validationResult.getErrorStatus().getCode());
    assertEquals(StatusCode.REQUEST_DENIED, validationResult.getErrorStatus().getMinorCode());
  }

  @Test
  void testIsPassive()
  {
    DefaultAuthnRequestValidator ignore = new DefaultAuthnRequestValidator();
    DefaultAuthnRequestValidator expectedTrue = new DefaultAuthnRequestValidator(RESPONSE_TIME, NameId.PERSISTENT, null,
                                                                                 Boolean.TRUE, null, null);
    DefaultAuthnRequestValidator expectedFalse = new DefaultAuthnRequestValidator(RESPONSE_TIME, NameId.PERSISTENT,
                                                                                  null, Boolean.FALSE, null, null);

    authnRequest.setPassive(Boolean.TRUE);
    assertFalse(ignore.validate(authnRequest, requester, responder, Instant.now()).hasErrors());
    assertFalse(expectedTrue.validate(authnRequest, requester, responder, Instant.now()).hasErrors());
    assertTrue(expectedFalse.validate(authnRequest, requester, responder, Instant.now()).hasErrors());

    authnRequest.setPassive(Boolean.FALSE);
    assertFalse(ignore.validate(authnRequest, requester, responder, Instant.now()).hasErrors());
    assertTrue(expectedTrue.validate(authnRequest, requester, responder, Instant.now()).hasErrors());
    assertFalse(expectedFalse.validate(authnRequest, requester, responder, Instant.now()).hasErrors());
  }

  @Test
  void testAllowCreate()
  {
    DefaultAuthnRequestValidator ignore = new DefaultAuthnRequestValidator();
    DefaultAuthnRequestValidator expectedTrue = new DefaultAuthnRequestValidator(RESPONSE_TIME, NameId.PERSISTENT, null,
                                                                                 null, Boolean.TRUE, null);
    DefaultAuthnRequestValidator expectedFalse = new DefaultAuthnRequestValidator(RESPONSE_TIME, NameId.PERSISTENT,
                                                                                  null, null, Boolean.FALSE, null);

    authnRequest.getNameIdPolicy().setAllowCreate(Boolean.TRUE);
    assertFalse(ignore.validate(authnRequest, requester, responder, Instant.now()).hasErrors());
    assertFalse(expectedTrue.validate(authnRequest, requester, responder, Instant.now()).hasErrors());
    assertTrue(expectedFalse.validate(authnRequest, requester, responder, Instant.now()).hasErrors());

    authnRequest.getNameIdPolicy().setAllowCreate(Boolean.FALSE);
    assertFalse(ignore.validate(authnRequest, requester, responder, Instant.now()).hasErrors());
    assertTrue(expectedTrue.validate(authnRequest, requester, responder, Instant.now()).hasErrors());
    assertFalse(expectedFalse.validate(authnRequest, requester, responder, Instant.now()).hasErrors());
  }

  @Test
  void testForceAuthn()
  {
    DefaultAuthnRequestValidator ignore = new DefaultAuthnRequestValidator();
    DefaultAuthnRequestValidator expectedTrue = new DefaultAuthnRequestValidator(RESPONSE_TIME, NameId.PERSISTENT,
                                                                                 Boolean.TRUE, null, null, null);
    DefaultAuthnRequestValidator expectedFalse = new DefaultAuthnRequestValidator(RESPONSE_TIME, NameId.PERSISTENT,
                                                                                  Boolean.FALSE, null, null, null);

    authnRequest.setForceAuth(Boolean.TRUE);
    assertFalse(ignore.validate(authnRequest, requester, responder, Instant.now()).hasErrors());
    assertFalse(expectedTrue.validate(authnRequest, requester, responder, Instant.now()).hasErrors());
    assertTrue(expectedFalse.validate(authnRequest, requester, responder, Instant.now()).hasErrors());

    authnRequest.setForceAuth(Boolean.FALSE);
    assertFalse(ignore.validate(authnRequest, requester, responder, Instant.now()).hasErrors());
    assertTrue(expectedTrue.validate(authnRequest, requester, responder, Instant.now()).hasErrors());
    assertFalse(expectedFalse.validate(authnRequest, requester, responder, Instant.now()).hasErrors());
  }

  static Stream<Arguments> invalidSignature()
  {
    return Stream.of(Arguments.of(null, "Signature is invalid."),
                     Arguments.of(new Signature().setValidated(true), "Signature is invalid."));
  }

  @ParameterizedTest
  @MethodSource({"invalidSignature"})
  void testSignature(Signature signature, String expectedErrorMessage)
  {
    authnRequest.getSignature().setValidated(false);

    ValidationResult validationResult = new DefaultAuthnRequestValidator().validate(authnRequest,
                                                                                    requester,
                                                                                    responder,
                                                                                    Instant.now());
    assertEquals(expectedErrorMessage, validationResult.getErrors().get(0).toString());
    assertNotNull(validationResult.getErrorStatus());
    assertEquals(StatusCode.REQUESTER, validationResult.getErrorStatus().getCode());
    assertEquals(StatusCode.REQUEST_DENIED, validationResult.getErrorStatus().getMinorCode());
  }

  @Test
  void testAuthnContextClassReferences()
  {
    List<AuthenticationContextClassReference> list = Arrays.asList(AuthenticationContextClassReference.fromUrn(PREVIOUS_SESSION),
                                                                   AuthenticationContextClassReference.fromUrn(PASSWORD));
    DefaultAuthnRequestValidator validator = new DefaultAuthnRequestValidator(RESPONSE_TIME, NameId.PERSISTENT, null,
                                                                              null, null, list);

    ValidationResult validationResult = validator.validate(authnRequest, requester, responder, Instant.now());

    assertEquals("Invalid authentication context class references.", validationResult.getErrors().get(0).toString());
    assertNotNull(validationResult.getErrorStatus());
    assertEquals(StatusCode.RESPONDER, validationResult.getErrorStatus().getCode());
    assertEquals(StatusCode.NO_AUTH_CONTEXT, validationResult.getErrorStatus().getMinorCode());
  }

  private AuthenticationRequest createRequest()
  {
    AuthenticationRequest authnRequest = new AuthenticationRequest();
    authnRequest.setId("AAAAAA");
    authnRequest.setAssertionConsumerService(new Endpoint().setLocation("DummyAssertionConsumerServiceURL")
                                                           .setBinding(Binding.POST)
                                                           .setIndex(-1));
    authnRequest.setDestination(new Endpoint().setLocation("DummyDestination"));
    authnRequest.setForceAuth(true);
    authnRequest.setPassive(false);
    authnRequest.setIssueInstant(DateTime.now());
    authnRequest.setVersion("2.0");
    authnRequest.setIssuer(new Issuer().setValue("ServiceProviderEntityID"));
    authnRequest.setNameIdPolicy(new NameIdPolicy().setFormat(NameId.PERSISTENT).setAllowCreate(true));
    authnRequest.setSignature(new Signature().setValidated(true));
    authnRequest.setAuthenticationContextClassReferences(Collections.singletonList(AuthenticationContextClassReference.fromUrn(UNSPECIFIED)));
    return authnRequest;
  }

  private ServiceProviderMetadata createServiceProviderMetadata()
  {
    ServiceProvider serviceProvider = new ServiceProvider();
    serviceProvider.setNameIds(Collections.singletonList(NameId.TRANSIENT));
    serviceProvider.setAssertionConsumerService(Collections.singletonList(new Endpoint().setLocation("DummyAssertionConsumerServiceURL")
                                                                                        .setBinding(Binding.POST)));

    return new ServiceProviderMetadata().setProviders(Collections.singletonList(serviceProvider))
                                        .setEntityId(SERVICE_PROVIDER_ENTITY_ID);
  }

  private IdentityProviderMetadata createIdentityProviderMetadata()
  {
    IdentityProvider identityProvider = new IdentityProvider();
    identityProvider.setSingleSignOnService(Collections.singletonList(new Endpoint().setLocation("DummyDestination")));

    return new IdentityProviderMetadata().setProviders(Collections.singletonList(identityProvider));
  }

}
