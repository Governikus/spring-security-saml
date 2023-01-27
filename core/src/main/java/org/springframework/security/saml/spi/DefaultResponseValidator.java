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
import static org.springframework.security.saml.saml2.authentication.SubjectConfirmationMethod.BEARER;
import static org.springframework.security.saml.saml2.metadata.NameId.ENTITY;
import static org.springframework.util.StringUtils.hasText;

import java.net.URI;
import java.net.URISyntaxException;
import java.time.Instant;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

import org.opensaml.saml.common.SAMLVersion;
import org.springframework.security.saml.provider.service.cache.RequestContextCache;
import org.springframework.security.saml.saml2.attribute.Attribute;
import org.springframework.security.saml.saml2.authentication.Assertion;
import org.springframework.security.saml.saml2.authentication.AudienceRestriction;
import org.springframework.security.saml.saml2.authentication.AuthenticationStatement;
import org.springframework.security.saml.saml2.authentication.Conditions;
import org.springframework.security.saml.saml2.authentication.Issuer;
import org.springframework.security.saml.saml2.authentication.Response;
import org.springframework.security.saml.saml2.authentication.Status;
import org.springframework.security.saml.saml2.authentication.StatusCode;
import org.springframework.security.saml.saml2.authentication.Subject;
import org.springframework.security.saml.saml2.authentication.SubjectConfirmation;
import org.springframework.security.saml.saml2.authentication.SubjectConfirmationData;
import org.springframework.security.saml.saml2.metadata.Endpoint;
import org.springframework.security.saml.saml2.metadata.IdentityProviderMetadata;
import org.springframework.security.saml.saml2.metadata.NameId;
import org.springframework.security.saml.saml2.metadata.ServiceProviderMetadata;
import org.springframework.security.saml.saml2.signature.Signature;
import org.springframework.security.saml.validation.ValidationResult;


public class DefaultResponseValidator
{

  private final long responseSkewTimeMillis;

  private final long maxAuthenticationAgeMillis;

  private final boolean allowUnsolicitedResponses;

  private final boolean allowSeveralAssertions;

  private final NameId expectedNameIdPolicy;

  public DefaultResponseValidator()
  {
    responseSkewTimeMillis = TimeUnit.MINUTES.toMillis(2);
    maxAuthenticationAgeMillis = TimeUnit.HOURS.toMillis(24);
    allowUnsolicitedResponses = true;
    allowSeveralAssertions = true;
    expectedNameIdPolicy = NameId.TRANSIENT;
  }

  public DefaultResponseValidator(long responseSkewTimeMillis,
                                  long maxAuthenticationAgeMillis,
                                  boolean allowUnsolicitedResponses,
                                  boolean allowSeveralAssertions,
                                  NameId expectedNameIdPolicy)
  {
    this.responseSkewTimeMillis = responseSkewTimeMillis;
    this.maxAuthenticationAgeMillis = maxAuthenticationAgeMillis;
    this.allowUnsolicitedResponses = allowUnsolicitedResponses;
    this.allowSeveralAssertions = allowSeveralAssertions;
    this.expectedNameIdPolicy = expectedNameIdPolicy;
  }

  protected long getResponseSkewTimeMillis()
  {
    return responseSkewTimeMillis;
  }

  protected long getMaxAuthenticationAgeMillis()
  {
    return maxAuthenticationAgeMillis;
  }

  protected boolean isAllowUnsolicitedResponses()
  {
    return allowUnsolicitedResponses;
  }

  protected boolean isAllowSeveralAssertions()
  {
    return allowSeveralAssertions;
  }

  protected NameId getExpectedNameIdValue()
  {
    return expectedNameIdPolicy;
  }

  public ValidationResult validate(Response response,
                                   RequestContextCache.RequestContext requestContext,
                                   ServiceProviderMetadata requester,
                                   IdentityProviderMetadata responder,
                                   Instant referenceTime)
  {
    ValidationResult result = new ValidationResult(response);

    if (requester == null)
    {
      return result.addError("Requester is null.");
    }

    if (responder == null)
    {
      return result.addError("Responder is null.");
    }

    validateSamlVersion(result, response.getVersion());
    validateStatus(result, response.getStatus());
    validateSignature(result, response.getSignature());
    validateInResponseToValue(result, response.getInResponseTo(), requestContext);
    validateIssuer(result, response.getIssuer(), responder.getEntityId(), false);

    if (!isDateTimeSkewValid(getResponseSkewTimeMillis(), response.getIssueInstant(), referenceTime))
    {
      result.addError("Issue time is either too old or in the future.");
    }

    if (!hasText(response.getDestination())
        || !compareURIs(requester.getServiceProvider().getAssertionConsumerService(), response.getDestination()))
    {
      result.addError("Destination mismatch: " + response.getDestination());
    }

    List<Assertion> assertions = response.getAssertions();
    if (assertions.isEmpty())
    {
      result.addError("Response contains no assertion.");
    }

    if (!isAllowSeveralAssertions() && assertions.size() > 1)
    {
      result.addError("More than one assertion found.");
    }

    if (result.hasErrors())
    {
      return result;
    }

    for ( Assertion a : assertions )
    {
      ValidationResult assertionResult = validate(a, requestContext, requester, responder, referenceTime);
      if (assertionResult.hasErrors())
      {
        return assertionResult;
      }
    }

    return new ValidationResult(response);
  }

  protected void validateSamlVersion(ValidationResult result, String version)
  {
    if (!SAMLVersion.VERSION_20.toString().equals(version))
    {
      result.addError("SAML version is not 2.0.");
    }
  }

  protected void validateStatus(ValidationResult result, Status status)
  {
    if (status == null || status.getCode() == null)
    {
      result.addError("Response status or code is null");
    }
    else if (status.getCode() != StatusCode.SUCCESS)
    {
      result.addError("Received error " + status);
    }
  }

  protected void validateSignature(ValidationResult result, Signature signature)
  {
    if (signature == null || !signature.isValidated())
    {
      result.addError("No validated signature present");
    }
  }

  protected void validateAssertionSignature(ValidationResult result, Signature signature, boolean wantAssertionsSigned)
  {
    if (signature == null && wantAssertionsSigned)
    {
      result.addError("No signature present");
    }
    else if (signature != null && !signature.isValidated())
    {
      result.addError("No validated signature present");
    }
  }

  protected void validateInResponseToValue(ValidationResult result,
                                           String inResponseTo,
                                           RequestContextCache.RequestContext requestContext)
  {
    if (!isAllowUnsolicitedResponses())
    {
      if (!hasText(inResponseTo))
      {
        result.addError("InResponseTo is missing and unsolicited responses are disabled");
      }
      else
      {
        if (requestContext == null || !requestContext.getAuthenticationRequestIds().contains(inResponseTo))
        {
          result.addError("Invalid InResponseTo ID, not found in supplied list");
        }
      }
    }
  }

  public ValidationResult validate(Assertion assertion,
                                   RequestContextCache.RequestContext requestContext,
                                   ServiceProviderMetadata requester,
                                   IdentityProviderMetadata responder,
                                   Instant referenceTime)
  {
    ValidationResult result = new ValidationResult(assertion);

    validateAssertionSignature(result,
                               assertion.getSignature(),
                               requester.getServiceProvider().isWantAssertionsSigned());
    validateIssuer(result, assertion.getIssuer(), responder.getEntityId(), true);

    if (!isDateTimeSkewValid(responseSkewTimeMillis, assertion.getIssueInstant(), referenceTime))
    {
      result.addError("Issue time is either too old or in the future.");
    }

    validateSubject(result, requester, assertion.getSubject(), requestContext);
    validateAttributes(result, assertion.getAttributes());
    validateAuthenticationStatements(result, assertion.getAuthenticationStatements(), requestContext, referenceTime);
    validateConditions(result, assertion.getConditions(), requester.getEntityId());

    return result;
  }

  protected void validateSubject(ValidationResult result,
                                 ServiceProviderMetadata requester,
                                 Subject subject,
                                 RequestContextCache.RequestContext requestContext)
  {
    if (subject == null)
    {
      result.addError("Subject is missing.");
      return;
    }

    if (subject.getPrincipal() == null)
    {
      result.addError("Subject principal is missing.");
    }
    else
    {
      if (!getExpectedNameIdValue().equals(subject.getPrincipal().getFormat()))
      {
        result.addError("Subject principal has an invalid name id.");
      }

      if (subject.getPrincipal().getValue() == null)
      {
        result.addError("Subject principal value is missing.");
      }
    }

    if (subject.getConfirmations().isEmpty())
    {
      result.addError("Subject confirmation is missing.");
    }
    else
    {
      for ( SubjectConfirmation confirmation : subject.getConfirmations() )
      {
        validateSubjectConfirmation(result, requester, confirmation, requestContext);
      }
    }
  }

  private void validateSubjectConfirmation(ValidationResult result,
                                           ServiceProviderMetadata requester,
                                           SubjectConfirmation subjectConfirmation,
                                           RequestContextCache.RequestContext requestContext)
  {
    if (!BEARER.equals(subjectConfirmation.getMethod()))
    {
      result.addError("Invalid confirmation method:" + subjectConfirmation.getMethod());
    }

    SubjectConfirmationData confirmationData = subjectConfirmation.getConfirmationData();
    if (confirmationData == null)
    {
      result.addError("Empty subject confirmation data");
      return;
    }

    if (confirmationData.getNotBefore() != null)
    {
      result.addError("Subject confirmation data must not have NotBefore date");
    }

    if (confirmationData.getNotOnOrAfter() == null)
    {
      result.addError("Subject confirmation data is missing NotOnOfAfter date");
      return;
    }

    if (confirmationData.getNotOnOrAfter().plusMillis(responseSkewTimeMillis).isBefore(Instant.now()))
    {
      result.addError(format("Invalid NotOnOrAfter date: '%s'", confirmationData.getNotOnOrAfter()));
    }

    validateInResponseToValue(result, confirmationData.getInResponseTo(), requestContext);

    String recipient = confirmationData.getRecipient();
    if (!hasText(recipient))
    {
      result.addError("Assertion Recipient field missing");
    }
    else if (!compareURIs(requester.getServiceProvider().getAssertionConsumerService(), recipient))
    {
      result.addError("Invalid assertion Recipient field: " + confirmationData.getRecipient());
    }
  }

  protected void validateAuthenticationStatements(ValidationResult result,
                                                  List<AuthenticationStatement> authenticationStatements,
                                                  RequestContextCache.RequestContext requestContext,
                                                  Instant referenceTime)
  {
    if (authenticationStatements.isEmpty())
    {
      result.addError("Authentication statement is missing.");
      return;
    }

    for ( AuthenticationStatement statement : authenticationStatements )
    {
      if (!isDateTimeSkewValid(getResponseSkewTimeMillis(),
                               getMaxAuthenticationAgeMillis(),
                               statement.getAuthInstant(),
                               referenceTime))
      {
        result.addError("Authentication statement is too old.");
      }

      if (statement.getSessionNotOnOrAfter() != null && statement.getSessionNotOnOrAfter().isBefore(Instant.now()))
      {
        result.addError("Authentication session expired on " + statement.getSessionNotOnOrAfter());
      }
    }
  }

  /**
   * Web Browser SSO profile <AttributeStatements> MAY be included
   */
  protected void validateAttributes(ValidationResult result, List<Attribute> attributes)
  {
    if (attributes.isEmpty())
    {
      result.addError("Assertion does not contain any AttributeStatements.");
    }
  }

  protected void validateConditions(ValidationResult result, Conditions conditions, String audienceEntityId)
  {
    if (conditions == null)
    {
      return;
    }

    if (conditions.getNotBefore() != null
        && conditions.getNotBefore().minusMillis(responseSkewTimeMillis).isAfter(Instant.now()))
    {
      result.addError("Conditions expired (not before): " + conditions.getNotBefore());
    }

    if (conditions.getNotOnOrAfter() != null
        && conditions.getNotOnOrAfter().plusMillis(responseSkewTimeMillis).isBefore(Instant.now()))
    {
      result.addError("Conditions expired (not on or after): " + conditions.getNotOnOrAfter());
    }

    List<AudienceRestriction> audienceRestrictions = conditions.getCriteria()
                                                               .stream()
                                                               .filter(AudienceRestriction.class::isInstance)
                                                               .map(AudienceRestriction.class::cast)
                                                               .collect(Collectors.toList());

    if (audienceRestrictions.isEmpty())
    {
      result.addError("Audience restriction condition is missing.");
    }

    for ( AudienceRestriction ac : audienceRestrictions )
    {
      if (ac.getAudiences().isEmpty())
      {
        result.addError("Audience Conditions contains no audiences!");
      }
      else if (!ac.getAudiences().contains(audienceEntityId))
      {
        result.addError(format("Audience restriction evaluation failed for assertion condition. Expected '%s' Was '%s'",
                               audienceEntityId,
                               ac.getAudiences()));
      }
    }
  }

  protected boolean isDateTimeSkewValid(long skewMillis, Instant time, Instant referenceTime)
  {
    return isDateTimeSkewValid(skewMillis, 0, time, referenceTime);
  }

  protected boolean isDateTimeSkewValid(long skewMillis, long backwardMillis, Instant time, Instant referenceTime)
  {
    if (time == null)
    {
      return false;
    }

    Instant since = referenceTime.minusMillis(skewMillis + backwardMillis);
    Instant until = referenceTime.plusMillis(skewMillis);
    return since.isBefore(time) && until.isAfter(time);
  }

  protected void validateIssuer(ValidationResult result, Issuer issuer, String entityId, boolean isIssuerMandatory)
  {
    if (issuer == null)
    {
      if (isIssuerMandatory)
      {
        result.addError("Issuer is missing.");
      }
      return;
    }

    if (!entityId.equals(issuer.getValue()))
    {
      result.addError("Issuer mismatches entity id.");
    }
    if (issuer.getFormat() != null && !issuer.getFormat().equals(ENTITY))
    {
      result.addError(format("Issuer name format mismatch. Expected: '%s' Actual: '%s'", ENTITY, issuer.getFormat()));
    }
  }

  protected boolean compareURIs(List<Endpoint> endpoints, String uri)
  {
    for ( Endpoint ep : endpoints )
    {
      if (compareURIs(ep.getLocation(), uri))
      {
        return true;
      }
    }
    return false;
  }

  private boolean compareURIs(String uri1AsString, String uri2AsString)
  {
    if (uri1AsString == null && uri2AsString == null)
    {
      return true;
    }
    if (uri1AsString == null || uri2AsString == null)
    {
      return false;
    }
    try
    {
      URI uri1 = new URI(uri1AsString);
      URI uri2 = new URI(uri2AsString);
      return uri1.getScheme().equals(uri2.getScheme()) && uri1.getAuthority().equals(uri2.getAuthority())
             && uri1.getPort() == uri2.getPort() && uri1.getHost().equals(uri2.getHost())
             && uri1.getPath().equalsIgnoreCase(uri2.getPath());
    }
    catch (URISyntaxException e)
    {
      return false;
    }
  }

}
