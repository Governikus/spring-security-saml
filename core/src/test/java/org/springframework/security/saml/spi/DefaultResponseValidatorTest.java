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

import static java.lang.String.format;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import java.util.stream.Stream;

import org.joda.time.DateTime;
import org.joda.time.Instant;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.security.saml.provider.service.cache.RequestContextCache;
import org.springframework.security.saml.saml2.attribute.Attribute;
import org.springframework.security.saml.saml2.attribute.AttributeNameFormat;
import org.springframework.security.saml.saml2.authentication.Assertion;
import org.springframework.security.saml.saml2.authentication.AudienceRestriction;
import org.springframework.security.saml.saml2.authentication.AuthenticationContextClassReference;
import org.springframework.security.saml.saml2.authentication.AuthenticationStatement;
import org.springframework.security.saml.saml2.authentication.Conditions;
import org.springframework.security.saml.saml2.authentication.Issuer;
import org.springframework.security.saml.saml2.authentication.NameIdPrincipal;
import org.springframework.security.saml.saml2.authentication.Response;
import org.springframework.security.saml.saml2.authentication.Status;
import org.springframework.security.saml.saml2.authentication.StatusCode;
import org.springframework.security.saml.saml2.authentication.Subject;
import org.springframework.security.saml.saml2.authentication.SubjectConfirmation;
import org.springframework.security.saml.saml2.authentication.SubjectConfirmationData;
import org.springframework.security.saml.saml2.authentication.SubjectConfirmationMethod;
import org.springframework.security.saml.saml2.metadata.Binding;
import org.springframework.security.saml.saml2.metadata.Endpoint;
import org.springframework.security.saml.saml2.metadata.IdentityProvider;
import org.springframework.security.saml.saml2.metadata.IdentityProviderMetadata;
import org.springframework.security.saml.saml2.metadata.NameId;
import org.springframework.security.saml.saml2.metadata.ServiceProvider;
import org.springframework.security.saml.saml2.metadata.ServiceProviderMetadata;
import org.springframework.security.saml.saml2.signature.Signature;
import org.springframework.security.saml.validation.ValidationResult;


class DefaultResponseValidatorTest
{

  private static final String TEST_IN_RESPONSE_TO = "InResponseTo";

  private static final String VALID_TEST_RECIPIENT = "http://localhost/saml/sp/SSO/alias";

  private static final String ISSUER_VALUE = "IdentityProviderEntityID";

  private DefaultResponseValidator responseValidator;

  private DefaultResponseValidator laxResponseValidator;

  private ServiceProviderMetadata requester;

  private IdentityProviderMetadata responder;

  private static final int RESPONSE_TIME = (int)TimeUnit.MINUTES.toMillis(2);

  final static int CHECK_BOUNDARIES = RESPONSE_TIME + 1;

  @BeforeEach
  public void init()
  {
    responseValidator = new DefaultResponseValidator((int)TimeUnit.MINUTES.toMillis(2), TimeUnit.HOURS.toMillis(24),
                                                     false, false, NameId.TRANSIENT);
    laxResponseValidator = new DefaultResponseValidator();
    requester = createServiceProviderMetadata();
    responder = createIdentityProviderMetadata();
  }

  RequestContextCache.RequestContext requestContext()
  {
    return new RequestContextCache.RequestContext("relayState", TEST_IN_RESPONSE_TO);
  }

  @Test
  void testValidResponse()
  {
    ValidationResult validationResult = responseValidator.validate(validResponse(),
                                                                   requestContext(),
                                                                   requester,
                                                                   responder,
                                                                   Instant.now());
    assertFalse(validationResult.hasErrors(), validationResult.toString());
  }

  @Test
  void testNullInputs()
  {
    ValidationResult validationResult = responseValidator.validate(validResponse(),
                                                                   requestContext(),
                                                                   null,
                                                                   responder,
                                                                   Instant.now());
    assertEquals("Requester is null.", validationResult.getErrors().get(0).toString());

    validationResult = responseValidator.validate(validResponse(), requestContext(), requester, null, Instant.now());
    assertEquals("Responder is null.", validationResult.getErrors().get(0).toString());
  }

  @Test
  void testErrorStatus()
  {
    Response errorResponse = validResponse().setStatus(new Status().setCode(StatusCode.REQUESTER)
                                                                   .setMinorCode(StatusCode.REQUEST_DENIED));
    ValidationResult validationResult = responseValidator.validate(errorResponse,
                                                                   requestContext(),
                                                                   requester,
                                                                   responder,
                                                                   Instant.now());
    assertTrue(validationResult.hasErrors());
  }

  @Test
  void testMissingStatus()
  {
    Response errorResponse = validResponse().setStatus(null);
    ValidationResult validationResult = responseValidator.validate(errorResponse,
                                                                   requestContext(),
                                                                   requester,
                                                                   responder,
                                                                   Instant.now());
    assertTrue(validationResult.hasErrors());
    assertEquals("Response status or code is null", validationResult.getErrors().get(0).toString());
  }

  static Stream<Arguments> invalidDestinations()
  {
    return Stream.of(Arguments.of(null, "Destination mismatch: null"),
                     Arguments.of("invalid value", "Destination mismatch: invalid value"));
  }

  @ParameterizedTest(name = " test validator and expect error: {1}")
  @MethodSource({"invalidDestinations"})
  void testDestinationsInResponses(String destination, String expectedErrorMessage)
  {
    Response response = validResponse().setDestination(destination);

    ValidationResult validationResult = responseValidator.validate(response,
                                                                   requestContext(),
                                                                   requester,
                                                                   responder,
                                                                   Instant.now());
    assertTrue(validationResult.hasErrors());
    assertEquals(expectedErrorMessage, validationResult.getErrors().get(0).toString());
  }

  static Stream<Arguments> invalidInResponseTo()
  {
    return Stream.of(Arguments.of(null, "InResponseTo is missing and unsolicited responses are disabled"),
                     Arguments.of("invalid value", "Invalid InResponseTo ID, not found in supplied list"));
  }

  @ParameterizedTest(name = " test validator and expect error: {1}")
  @MethodSource({"invalidInResponseTo"})
  void testInResponseToInResponses(String inResponseTo, String expectedErrorMessage)
  {
    Response response = validResponse().setInResponseTo(inResponseTo);

    ValidationResult validationResult = responseValidator.validate(response,
                                                                   requestContext(),
                                                                   requester,
                                                                   responder,
                                                                   Instant.now());
    assertTrue(validationResult.hasErrors());
    assertEquals(expectedErrorMessage, validationResult.getErrors().get(0).toString());

    validationResult = laxResponseValidator.validate(response, requestContext(), requester, responder, Instant.now());
    assertFalse(validationResult.hasErrors());
  }

  @Test
  void testSamlVersion()
  {
    Response errorResponse = validResponse().setVersion("1.1");
    ValidationResult validationResult = responseValidator.validate(errorResponse,
                                                                   requestContext(),
                                                                   requester,
                                                                   responder,
                                                                   Instant.now());
    assertEquals("SAML version is not 2.0.", validationResult.getErrors().get(0).toString());
  }

  /**
   * Add 120001 milliseconds and remove 120001 milliseconds (RESPONSE_TIME time is 2 minutes) to check boundaries
   */
  static Stream<Arguments> invalidIssueInstants()
  {
    return Stream.of(Arguments.of(Instant.now(), "Issue time is either too old or in the future.", 0),
                     Arguments.of(Instant.now(), "Issue time is either too old or in the future.", CHECK_BOUNDARIES),
                     Arguments.of(Instant.now(), "Issue time is either too old or in the future.", -CHECK_BOUNDARIES));
  }

  @ParameterizedTest(name = " test validator and expect error: {1}")
  @MethodSource({"invalidIssueInstants"})
  void testIssueInstantsInResponses(Instant issueInstant, String expectedErrorMessage, int changeTimeMilliseconds)
  {
    Response response = validResponse().setIssueInstant(changeTimeMilliseconds == 0 ? null
      : issueInstant.plus(changeTimeMilliseconds).toDateTime());

    ValidationResult validationResult = responseValidator.validate(response,
                                                                   requestContext(),
                                                                   requester,
                                                                   responder,
                                                                   issueInstant);
    assertTrue(validationResult.hasErrors());
    assertEquals(expectedErrorMessage, validationResult.getErrors().get(0).toString());
  }

  @ParameterizedTest(name = " test validator and expect error: {1}")
  @MethodSource({"invalidIssueInstants"})
  void testIssueInstantsInAssertion(Instant issueInstant, String expectedErrorMessage, int changeTimeMilliseconds)
  {
    Assertion response = validAssertion().setIssueInstant(changeTimeMilliseconds == 0 ? null
      : issueInstant.plus(changeTimeMilliseconds).toDateTime());

    ValidationResult validationResult = responseValidator.validate(response,
                                                                   requestContext(),
                                                                   requester,
                                                                   responder,
                                                                   issueInstant);
    assertTrue(validationResult.hasErrors());
    assertEquals(expectedErrorMessage, validationResult.getErrors().get(0).toString());
  }

  static Stream<Arguments> invalidResponseIssuer()
  {
    return Stream.of(Arguments.of(new Issuer().setValue("invalid"), "Issuer mismatches entity id."),
                     Arguments.of(new Issuer().setValue(ISSUER_VALUE).setFormat(NameId.UNSPECIFIED),
                                  "Issuer name format mismatch. Expected: 'urn:oasis:names:tc:SAML:2.0:nameid-format:entity' Actual: 'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified'"));
  }

  @ParameterizedTest(name = " test validator and expect error: {1}")
  @MethodSource({"invalidResponseIssuer"})
  void testIssuerInResponse(Issuer issuer, String expectedErrorMessage)
  {
    Response response = validResponse().setIssuer(issuer);
    ValidationResult validationResult = responseValidator.validate(response,
                                                                   requestContext(),
                                                                   requester,
                                                                   responder,
                                                                   Instant.now());
    assertTrue(validationResult.hasErrors());
    assertEquals(expectedErrorMessage, validationResult.getErrors().get(0).toString());
  }

  @Test
  void testMissingAssertion()
  {
    Response response = validResponse().setAssertions(new ArrayList<>());

    ValidationResult validationResult = responseValidator.validate(response,
                                                                   requestContext(),
                                                                   requester,
                                                                   responder,
                                                                   Instant.now());
    assertEquals("Response contains no assertion.", validationResult.getErrors().get(0).toString());

    validationResult = laxResponseValidator.validate(response, requestContext(), requester, responder, Instant.now());
    assertEquals("Response contains no assertion.", validationResult.getErrors().get(0).toString());
  }

  @Test
  void testTwoAssertions()
  {
    Response response = validResponse().setAssertions(Arrays.asList(validAssertion(), validAssertion()));

    ValidationResult validationResult = responseValidator.validate(response,
                                                                   requestContext(),
                                                                   requester,
                                                                   responder,
                                                                   Instant.now());
    assertEquals("More than one assertion found.", validationResult.getErrors().get(0).toString());

    validationResult = laxResponseValidator.validate(response, requestContext(), requester, responder, Instant.now());
    assertFalse(validationResult.hasErrors());
  }

  @Test
  void testValidAssertion()
  {
    Assertion assertion = validAssertion();
    ValidationResult validationResult = responseValidator.validate(assertion,
                                                                   requestContext(),
                                                                   requester,
                                                                   responder,
                                                                   Instant.now());
    assertFalse(validationResult.hasErrors(), validationResult.toString());
  }

  @Test
  void testMissingSignatureInResponse()
  {
    Response missingSignature = validResponse().setSignature(null);
    ValidationResult validationResult = responseValidator.validate(missingSignature,
                                                                   requestContext(),
                                                                   requester,
                                                                   responder,
                                                                   Instant.now());
    assertEquals("No validated signature present", validationResult.getErrors().get(0).toString());
  }

  @Test
  void testMissingSignatureInAssertion()
  {
    Assertion missingSignature = validAssertion().setSignature(null);
    ValidationResult validationResult = responseValidator.validate(missingSignature,
                                                                   requestContext(),
                                                                   requester,
                                                                   responder,
                                                                   Instant.now());
    assertEquals("No signature present", validationResult.getErrors().get(0).toString());
  }

  @Test
  void testSignaturesInResponse()
  {
    Response invalidSignature = validResponse().setSignature(new Signature().setValidated(false));
    ValidationResult validationResult = responseValidator.validate(invalidSignature,
                                                                   requestContext(),
                                                                   requester,
                                                                   responder,
                                                                   Instant.now());
    assertEquals("No validated signature present", validationResult.getErrors().get(0).toString());
  }

  @Test
  void testSignaturesInAssertion()
  {
    Assertion invalidSignature = validAssertion().setSignature(new Signature().setValidated(false));
    ValidationResult validationResult = responseValidator.validate(invalidSignature,
                                                                   requestContext(),
                                                                   requester,
                                                                   responder,
                                                                   Instant.now());
    assertEquals("No validated signature present", validationResult.getErrors().get(0).toString());
  }

  static Stream<Arguments> invalidIssuer()
  {
    return Stream.of(Arguments.of(null, "Issuer is missing."),
                     Arguments.of(new Issuer().setValue("invalid issuer value"), "Issuer mismatches entity id."),
                     Arguments.of(new Issuer().setValue(ISSUER_VALUE).setFormat(NameId.EMAIL),
                                  format("Issuer name format mismatch. Expected: '%s' Actual: '%s'",
                                         NameId.ENTITY,
                                         NameId.EMAIL)));
  }

  @ParameterizedTest(name = "test validator expect error: {1}.")
  @MethodSource({"invalidIssuer"})
  void testIssuerInAssertion(Issuer issuer, String expectedErrorMessage)
  {
    Assertion assertion = validAssertion().setIssuer(issuer);

    ValidationResult validationResult = responseValidator.validate(assertion,
                                                                   requestContext(),
                                                                   requester,
                                                                   responder,
                                                                   Instant.now());
    assertTrue(validationResult.hasErrors());
    assertEquals(1, validationResult.getErrors().size());
    assertEquals(expectedErrorMessage, validationResult.getErrors().get(0).getMessage());
  }

  static Stream<Arguments> invalidSubject()
  {
    NameIdPrincipal principalWithWrongFormat = new NameIdPrincipal().setFormat(NameId.EMAIL).setValue("testValue");
    NameIdPrincipal principalWithNullValue = new NameIdPrincipal().setFormat(NameId.TRANSIENT).setValue(null);
    final SubjectConfirmation invalidConfirmationMethod = new SubjectConfirmation().setMethod(SubjectConfirmationMethod.HOLDER_OF_KEY)
                                                                                   .setConfirmationData(validSubjectConfirmationData());

    return Stream.of(Arguments.of(null, "Subject is missing."),
                     Arguments.of(validSubject().setPrincipal(null), "Subject principal is missing."),
                     Arguments.of(validSubject().setPrincipal(principalWithWrongFormat),
                                  "Subject principal has an invalid name id."),
                     Arguments.of(validSubject().setPrincipal(principalWithNullValue),
                                  "Subject principal value is missing."),
                     Arguments.of(validSubject().setConfirmations(new ArrayList<>()),
                                  "Subject confirmation is missing."),
                     Arguments.of(validSubject().setConfirmations(Arrays.asList(invalidConfirmationMethod)),
                                  "Invalid confirmation method:" + SubjectConfirmationMethod.HOLDER_OF_KEY.toString()));
  }

  @ParameterizedTest(name = "test validator expect error: {1}.")
  @MethodSource({"invalidSubject"})
  void testSubject(Subject subject, String expectedErrorMessage)
  {
    Assertion assertion = validAssertion();
    assertion.setSubject(subject);

    ValidationResult validationResult = responseValidator.validate(assertion,
                                                                   requestContext(),
                                                                   requester,
                                                                   responder,
                                                                   Instant.now());
    assertTrue(validationResult.hasErrors());
    assertEquals(1, validationResult.getErrors().size());
    assertEquals(expectedErrorMessage, validationResult.getErrors().get(0).getMessage());
  }

  static Stream<Arguments> invalidSubjectConfirmationData()
  {
    DateTime expired = new DateTime().minusDays(1);

    return Stream.of(Arguments.of(null, "Empty subject confirmation data"),
                     Arguments.of(validSubjectConfirmationData().setInResponseTo("unknown"),
                                  "Invalid InResponseTo ID, not found in supplied list"),
                     Arguments.of(validSubjectConfirmationData().setInResponseTo(""),
                                  "InResponseTo is missing and unsolicited responses are disabled"),
                     Arguments.of(validSubjectConfirmationData().setNotBefore(new DateTime()),
                                  "Subject confirmation data must not have NotBefore date"),
                     Arguments.of(validSubjectConfirmationData().setNotOnOrAfter(expired),
                                  "Invalid NotOnOrAfter date: '" + expired + "'"),
                     Arguments.of(validSubjectConfirmationData().setNotOnOrAfter(null),
                                  "Subject confirmation data is missing NotOnOfAfter date"),
                     Arguments.of(validSubjectConfirmationData().setRecipient("invalid Test Recipient"),
                                  "Invalid assertion Recipient field: invalid Test Recipient"),
                     Arguments.of(validSubjectConfirmationData().setRecipient(""),
                                  "Assertion Recipient field missing"));
  }

  @ParameterizedTest(name = "test validator expect validation error: {1}.")
  @MethodSource({"invalidSubjectConfirmationData"})
  void testInvalidSubjectConfirmationData(SubjectConfirmationData data, String expectedErrorMessage)
  {
    Assertion assertion = validAssertion();
    assertion.getSubject().getConfirmations().get(0).setConfirmationData(data);

    ValidationResult validationResult = responseValidator.validate(assertion,
                                                                   requestContext(),
                                                                   requester,
                                                                   responder,
                                                                   Instant.now());
    assertTrue(validationResult.hasErrors());
    assertEquals(1, validationResult.getErrors().size());
    assertEquals(expectedErrorMessage, validationResult.getErrors().get(0).getMessage());
  }

  static Stream<Arguments> invalidConditions()
  {
    DateTime invalidNotBefore = new DateTime().plusMinutes(10);
    DateTime invalidNotOnOrAfter = new DateTime().minusMinutes(10);
    AudienceRestriction emptyAudienceRestriction = new AudienceRestriction().setAudiences(new ArrayList<>());
    AudienceRestriction invalidAudienceRestriction = new AudienceRestriction().setAudiences(Arrays.asList("no valid entity id"));

    return Stream.of(Arguments.of(validConditions().setNotBefore(invalidNotBefore),
                                  "Conditions expired (not before): " + invalidNotBefore.toString()),
                     Arguments.of(validConditions().setNotOnOrAfter(invalidNotOnOrAfter),
                                  "Conditions expired (not on or after): " + invalidNotOnOrAfter.toString()),
                     Arguments.of(validConditions().setCriteria(Arrays.asList(emptyAudienceRestriction)),
                                  "Audience Conditions contains no audiences!"),
                     Arguments.of(validConditions().setCriteria(Arrays.asList(invalidAudienceRestriction)),
                                  "Audience restriction evaluation failed for assertion condition. Expected 'ServiceProviderEntityID' Was '[no valid entity id]'"));
  }

  @ParameterizedTest(name = "test validator expect validation error: {1}.")
  @MethodSource({"invalidConditions"})
  void testInvalidConditions(Conditions conditions, String expectedErrorMessage)
  {
    Assertion assertion = validAssertion();
    assertion.setConditions(conditions);

    ValidationResult validationResult = responseValidator.validate(assertion,
                                                                   requestContext(),
                                                                   requester,
                                                                   responder,
                                                                   Instant.now());
    assertTrue(validationResult.hasErrors());
    assertEquals(1, validationResult.getErrors().size());
    assertEquals(expectedErrorMessage, validationResult.getErrors().get(0).getMessage());
  }

  static Assertion validAssertion()
  {
    Signature signature = new Signature().setValidated(true);
    List<Attribute> attributes = Arrays.asList(new Attribute());

    return new Assertion().setSignature(signature)
                          .setIssuer(new Issuer().setValue(ISSUER_VALUE))
                          .setIssueInstant(new DateTime())
                          .setSubject(validSubject())
                          .setAttributes(attributes)
                          .setAuthenticationStatements(Arrays.asList(new AuthenticationStatement().setAuthInstant(DateTime.now())))
                          .setConditions(validConditions());
  }

  static Subject validSubject()
  {
    List<SubjectConfirmation> confirmation = Arrays.asList(new SubjectConfirmation().setMethod(SubjectConfirmationMethod.BEARER)
                                                                                    .setConfirmationData(validSubjectConfirmationData()));

    return new Subject().setConfirmations(confirmation)
                        .setPrincipal(new NameIdPrincipal().setFormat(NameId.TRANSIENT).setValue("testValue"));
  }

  static SubjectConfirmationData validSubjectConfirmationData()
  {
    return new SubjectConfirmationData().setNotOnOrAfter(new DateTime())
                                        .setInResponseTo(TEST_IN_RESPONSE_TO)
                                        .setRecipient(VALID_TEST_RECIPIENT);
  }

  static Conditions validConditions()
  {
    return new Conditions().setNotBefore(DateTime.now())
                           .addCriteria(new AudienceRestriction().addAudience("ServiceProviderEntityID"));
  }

  private static Response validResponse()
  {
    AuthenticationStatement authenticationStatement = new AuthenticationStatement().setAuthInstant(DateTime.now());
    authenticationStatement.getAuthenticationContext()
                           .setClassReference(AuthenticationContextClassReference.fromUrn(AuthenticationContextClassReference.AuthenticationContextClassReferenceType.PASSWORD));

    Assertion assertion = new Assertion().setVersion("2.0")
                                         .setId("AssertionId" + UUID.randomUUID().toString())
                                         .setIssueInstant(DateTime.now())
                                         .setIssuer(ISSUER_VALUE)
                                         .setSubject(validSubject())
                                         .setConditions(new Conditions().setNotBefore(DateTime.now())
                                                                        .addCriteria(new AudienceRestriction().addAudience("ServiceProviderEntityID")))
                                         .addAttribute(new Attribute().setNameFormat(AttributeNameFormat.URI)
                                                                      .addValues("Mustermann"))
                                         .setAuthenticationStatements(Arrays.asList(authenticationStatement))
                                         .setSignature(new Signature().setValidated(true));

    return new Response().setVersion("2.0")
                         .setId("ResponseId")
                         .setIssueInstant(DateTime.now())
                         .setInResponseTo(TEST_IN_RESPONSE_TO)
                         .setIssuer(new Issuer().setValue(ISSUER_VALUE).setFormat(NameId.ENTITY))
                         .setDestination("http://localhost/saml/sp/SSO/alias")
                         .addAssertion(assertion)
                         .setSignature(new Signature().setValidated(true))
                         .setStatus(new Status().setCode(StatusCode.SUCCESS));
  }

  private ServiceProviderMetadata createServiceProviderMetadata()
  {
    ServiceProvider sp = new ServiceProvider().setNameIds(Collections.singletonList(NameId.TRANSIENT))
                                              .setWantAssertionsSigned(true)
                                              .setAssertionConsumerService(createEndpointList("http://localhost/saml/sp/SSO/alias"));

    return new ServiceProviderMetadata().setProviders(Collections.singletonList(sp))
                                        .setEntityId("ServiceProviderEntityID");
  }

  private IdentityProviderMetadata createIdentityProviderMetadata()
  {
    IdentityProvider idP = new IdentityProvider().setSingleSignOnService(createEndpointList("http://localhost/saml/idp/SSO/alias"));
    return new IdentityProviderMetadata().setProviders(Collections.singletonList(idP)).setEntityId(ISSUER_VALUE);
  }

  private List<Endpoint> createEndpointList(String location)
  {
    return Collections.singletonList(new Endpoint().setLocation(location).setBinding(Binding.POST));
  }
}
