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
import static org.springframework.util.StringUtils.hasText;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

import org.opensaml.saml.common.SAMLVersion;
import org.springframework.http.HttpMethod;
import org.springframework.security.saml.saml2.authentication.AuthenticationContextClassReference;
import org.springframework.security.saml.saml2.authentication.AuthenticationRequest;
import org.springframework.security.saml.saml2.authentication.Issuer;
import org.springframework.security.saml.saml2.authentication.NameIdPolicy;
import org.springframework.security.saml.saml2.authentication.Status;
import org.springframework.security.saml.saml2.authentication.StatusCode;
import org.springframework.security.saml.saml2.metadata.Endpoint;
import org.springframework.security.saml.saml2.metadata.IdentityProviderMetadata;
import org.springframework.security.saml.saml2.metadata.NameId;
import org.springframework.security.saml.saml2.metadata.ServiceProviderMetadata;
import org.springframework.security.saml.validation.ValidationResult;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;


public class DefaultAuthnRequestValidator
{

  private final long responseSkewTimeMillis;

  private final NameId expectedNameIdPolicy;

  private final Boolean expectedForceAuthn;

  private final Boolean expectedIsPassive;

  private final Boolean expectedAllowCreate;

  private final List<AuthenticationContextClassReference> allowedAuthnContextClassReferences;

  public DefaultAuthnRequestValidator()
  {
    responseSkewTimeMillis = TimeUnit.MINUTES.toMillis(2);
    expectedNameIdPolicy = NameId.PERSISTENT;
    expectedForceAuthn = null;
    expectedIsPassive = null;
    expectedAllowCreate = null;
    allowedAuthnContextClassReferences = null;
  }

  public DefaultAuthnRequestValidator(long responseSkewTimeMillis,
                                      NameId nameId,
                                      Boolean forceAuthn,
                                      Boolean isPassive,
                                      Boolean allowCreate,
                                      List<AuthenticationContextClassReference> authnContextClassRefs)
  {
    this.responseSkewTimeMillis = responseSkewTimeMillis;
    expectedNameIdPolicy = nameId;
    expectedForceAuthn = forceAuthn;
    expectedIsPassive = isPassive;
    expectedAllowCreate = allowCreate;
    allowedAuthnContextClassReferences = authnContextClassRefs;
  }

  protected long getReponseSkewTimeMillis()
  {
    return responseSkewTimeMillis;
  }

  protected NameId getExpectedNameIdValue()
  {
    return expectedNameIdPolicy;
  }

  protected Boolean getExpectedForceAuthnValue()
  {
    return expectedForceAuthn;
  }

  protected Boolean getExpectedIsPassiveValue()
  {
    return expectedIsPassive;
  }

  protected Boolean getExpectedAllowCreateValue()
  {
    return expectedAllowCreate;
  }

  protected List<AuthenticationContextClassReference> getAllowedAuthnContextClassReferences()
  {
    return allowedAuthnContextClassReferences;
  }

  /**
   * @param authnRequest the authnRequest to be validated
   * @param requester the service provider who issued this authnRequest
   * @param responder the identity provider who validated this authnRequest
   */
  public ValidationResult validate(AuthenticationRequest authnRequest,
                                   ServiceProviderMetadata requester,
                                   IdentityProviderMetadata responder,
                                   Instant referenceTime)
  {
    ValidationResult result = new ValidationResult(authnRequest);

    if (requester == null)
    {
      return result.addError("Remote service provider is null.");
    }

    if (responder == null)
    {
      return result.addError("Identity provider is null.");
    }

    verifyIssuerValues(result, requester.getEntityId(), authnRequest.getIssuer());

    verifyAssertionConsumer(result,
                            authnRequest.getAssertionConsumerService(),
                            requester.getServiceProvider().getAssertionConsumerService());

    if (result.hasErrors())
    {
      // if result already has errors at this point no error response is possible and we skip the rest of the validation
      return result;
    }

    verifySamlVersion(result, authnRequest.getVersion());
    if (result.hasErrors())
    {
      return result.setErrorStatus(new Status().setCode(StatusCode.VERSION_MISMATCH)
                                               .setMinorCode(StatusCode.REQUEST_VERSION_TOO_LOW));
    }

    verifyNameIDPolicy(result, authnRequest.getNameIdPolicy());
    if (result.hasErrors())
    {
      return result.setErrorStatus(new Status().setCode(StatusCode.REQUESTER).setMinorCode(StatusCode.INVALID_NAME_ID));
    }

    if (authnRequest.getIssueInstant() == null
        || !isDateTimeSkewValid(getReponseSkewTimeMillis(), authnRequest.getIssueInstant(), referenceTime))
    {
      result.addError("Issue time is either too old or in the future.");
    }

    Endpoint destination = authnRequest.getDestination();
    List<String> destinationLocations = responder.getIdentityProvider()
                                                 .getSingleSignOnService()
                                                 .stream()
                                                 .map(Endpoint::getLocation)
                                                 .collect(Collectors.toList());
    if (!destinationLocations.contains(destination.getLocation()))
    {
      result.addError("Invalid destination value.");
    }

    if (getExpectedAllowCreateValue() != null
        && !getExpectedAllowCreateValue().equals(authnRequest.getNameIdPolicy().getAllowCreate()))
    {
      result.addError("Invalid AllowCreate value.");
    }

    if (getExpectedForceAuthnValue() != null && !getExpectedForceAuthnValue().equals(authnRequest.isForceAuth()))
    {
      result.addError("Invalid ForceAuthn value.");
    }

    validateSignature(result, authnRequest);

    if (result.hasErrors())
    {
      return result.setErrorStatus(new Status().setCode(StatusCode.REQUESTER).setMinorCode(StatusCode.REQUEST_DENIED));
    }

    // check for StatusCode.RESPONDER + StatusCode.NO_PASSIVE
    if (getExpectedIsPassiveValue() != null && !getExpectedIsPassiveValue().equals(authnRequest.isPassive()))
    {
      return result.addError("Invalid IsPassive value.")
                   .setErrorStatus(new Status().setCode(StatusCode.RESPONDER).setMinorCode(StatusCode.NO_PASSIVE));
    }

    // check for StatusCode.RESPONDER + StatusCode.NO_AUTH_CONTEXT
    validateAuthnContextClassReferences(result, authnRequest.getAuthenticationContextClassReferences());
    if (result.hasErrors())
    {
      return result.setErrorStatus(new Status().setCode(StatusCode.RESPONDER).setMinorCode(StatusCode.NO_AUTH_CONTEXT));
    }

    // custom checks
    validateCustomFields(result, authnRequest, requester, responder);
    return result;
  }

  /**
   * @param result an empty ValidationResult, add validation errors to this object
   * @param authnRequest the SAML AuthnRequest to validate
   * @param requester the service provider who issued this authnRequest
   * @param responder the identity provider who validated this authnRequest
   */
  protected void validateCustomFields(ValidationResult result,
                                      AuthenticationRequest authnRequest,
                                      ServiceProviderMetadata requester,
                                      IdentityProviderMetadata responder)
  {
    // implement this for your own validations
  }

  /**
   * HTTP POST Binding needs a xml signature, HTTP Redirect Binding does not. Therefore check which binding was used to
   * see if validation is necessary.
   */
  protected void validateSignature(ValidationResult result, AuthenticationRequest authnRequest)
  {
    String method = HttpMethod.POST.toString();
    RequestAttributes requestAttributes = RequestContextHolder.getRequestAttributes();
    if (requestAttributes != null)
    {
      method = ((ServletRequestAttributes)requestAttributes).getRequest().getMethod();
    }

    if (HttpMethod.POST.toString().equalsIgnoreCase(method)
        && (authnRequest.getSignature() == null || !authnRequest.getSignature().isValidated()))
    {
      result.addError("Signature is invalid.");
    }
  }

  protected void verifyIssuerValues(ValidationResult result, String entityId, Issuer issuer)
  {
    if (issuer == null)
    {
      result.addError("Issuer is missing.");
      return;
    }

    if (!entityId.equals(issuer.getValue()))
    {
      result.addError("Issuer mismatches entity id.");
    }

    if (issuer.getFormat() != null && !issuer.getFormat().equals(NameId.ENTITY))
    {
      result.addError(format("Issuer name format mismatch. Expected: '%s' Actual: '%s'",
                             NameId.ENTITY,
                             issuer.getFormat()));
    }
  }

  protected void verifyAssertionConsumer(ValidationResult result,
                                         Endpoint assertionConsumerService,
                                         List<Endpoint> consumers)
  {
    // if index is not given it is set to -1
    if (assertionConsumerService.getIndex() >= 0)
    {
      // AssertionConsumerIndex is mutually exclusive with ProtocolBinding and AssertionConsumerUrl
      if (assertionConsumerService.getBinding() != null || !hasText(assertionConsumerService.getLocation()))
      {
        result.addError("Too many assertion consumers.");
      }

      if (consumers.size() < assertionConsumerService.getIndex())
      {
        result.addError("Invalid assertion consumer index value.");
      }
    }
    else
    {
      Optional<Endpoint> match = consumers.stream()
                                          .filter(c -> c.getLocation().equals(assertionConsumerService.getLocation()))
                                          .filter(c -> c.getBinding().equals(assertionConsumerService.getBinding()))
                                          .findFirst();
      if (match.isEmpty())
      {
        result.addError("Invalid assertion consumer url value.");
      }
    }
  }

  protected void verifySamlVersion(ValidationResult result, String version)
  {
    if (!SAMLVersion.VERSION_20.toString().equals(version))
    {
      result.addError("SAML version is not 2.0.");
    }
  }

  private void verifyNameIDPolicy(ValidationResult result, NameIdPolicy<?> nameIDPolicy)
  {
    if (nameIDPolicy == null)
    {
      result.addError("Missing NameIDPolicy.");
    }
    else if (getExpectedNameIdValue() != null && !getExpectedNameIdValue().equals(nameIDPolicy.getFormat()))
    {
      result.addError("Invalid NameIDPolicy format.");
    }
  }

  protected boolean isDateTimeSkewValid(long skewMillis, Instant time, Instant referenceTime)
  {
    if (time == null)
    {
      return false;
    }

    Instant since = referenceTime.minusMillis(skewMillis);
    Instant until = referenceTime.plusMillis(skewMillis);
    return since.isBefore(time) && until.isAfter(time);
  }

  protected void validateAuthnContextClassReferences(ValidationResult result,
                                                     List<AuthenticationContextClassReference> references)
  {
    if (references != null && getAllowedAuthnContextClassReferences() != null
        && !(getAllowedAuthnContextClassReferences().containsAll(references)))
    {
      result.addError("Invalid authentication context class references.");
    }
  }

}
