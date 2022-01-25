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
package org.springframework.security.saml.spi;

import java.util.List;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.joda.time.Instant;
import org.springframework.security.saml.SamlValidator;
import org.springframework.security.saml.key.SigningKey;
import org.springframework.security.saml.provider.HostedProviderService;
import org.springframework.security.saml.provider.service.cache.RequestContextCache.RequestContext;
import org.springframework.security.saml.saml2.Saml2Object;
import org.springframework.security.saml.saml2.authentication.Assertion;
import org.springframework.security.saml.saml2.authentication.AuthenticationRequest;
import org.springframework.security.saml.saml2.authentication.LogoutRequest;
import org.springframework.security.saml.saml2.authentication.LogoutResponse;
import org.springframework.security.saml.saml2.authentication.ManageNameIDRequest;
import org.springframework.security.saml.saml2.authentication.ManageNameIDResponse;
import org.springframework.security.saml.saml2.authentication.Response;
import org.springframework.security.saml.saml2.metadata.IdentityProviderMetadata;
import org.springframework.security.saml.saml2.metadata.ServiceProviderMetadata;
import org.springframework.security.saml.saml2.signature.Signature;
import org.springframework.security.saml.saml2.signature.SignatureException;
import org.springframework.security.saml.validation.ValidationException;
import org.springframework.security.saml.validation.ValidationResult;


public class DefaultValidator implements SamlValidator
{

  private static final Log LOG = LogFactory.getLog(DefaultValidator.class);

  private final SpringSecuritySaml<?> implementation;

  private final DefaultResponseValidator responseValidator;

  private final DefaultAuthnRequestValidator authnRequestValidator;

  public DefaultValidator(SpringSecuritySaml<?> implementation)
  {
    this(implementation, new DefaultResponseValidator(), new DefaultAuthnRequestValidator());
  }

  public DefaultValidator(SpringSecuritySaml<?> implementation,
                          DefaultResponseValidator responseValidator,
                          DefaultAuthnRequestValidator authnRequestValidator)
  {
    this.implementation = implementation;
    this.responseValidator = responseValidator;
    this.authnRequestValidator = authnRequestValidator;
  }

  @Override
  public Signature validateSignature(Saml2Object saml2Object, List<SigningKey> verificationKeys)
    throws SignatureException
  {
    try
    {
      return implementation.validateSignature(saml2Object, verificationKeys);
    }
    catch (SignatureException e)
    {
      throw e;
    }
    catch (Exception x)
    {
      throw new SignatureException(x.getMessage(), x);
    }
  }

  @Override
  public void validate(Saml2Object saml2Object,
                       HostedProviderService<?, ?, ?, ?> provider,
                       RequestContext requestContext)
    throws ValidationException
  {
    ValidationResult result = null;
    Instant referenceTime = Instant.now();

    if (saml2Object == null)
    {
      throw new ValidationException("Object to be validated cannot be null", result);
    }
    else if (saml2Object instanceof ServiceProviderMetadata)
    {
      result = validate((ServiceProviderMetadata)saml2Object, provider);
    }
    else if (saml2Object instanceof IdentityProviderMetadata)
    {
      result = validate((IdentityProviderMetadata)saml2Object, provider);
    }
    else if (saml2Object instanceof AuthenticationRequest)
    {
      AuthenticationRequest a = (AuthenticationRequest)saml2Object;
      ServiceProviderMetadata requester = (ServiceProviderMetadata)provider.getRemoteProvider(a);
      IdentityProviderMetadata responder = (IdentityProviderMetadata)provider.getMetadata();
      result = authnRequestValidator.validate(a, requester, responder, referenceTime);
    }
    else if (saml2Object instanceof LogoutRequest)
    {
      result = validate((LogoutRequest)saml2Object, provider);
    }
    else if (saml2Object instanceof LogoutResponse)
    {
      result = validate((LogoutResponse)saml2Object, provider);
    }
    else if (saml2Object instanceof Response)
    {
      Response r = (Response)saml2Object;
      ServiceProviderMetadata requester = (ServiceProviderMetadata)provider.getMetadata();
      IdentityProviderMetadata responder = (IdentityProviderMetadata)provider.getRemoteProvider(r);
      result = responseValidator.validate(r, requestContext, requester, responder, referenceTime);
    }
    else if (saml2Object instanceof Assertion)
    {
      Assertion a = (Assertion)saml2Object;
      ServiceProviderMetadata requester = (ServiceProviderMetadata)provider.getMetadata();
      IdentityProviderMetadata responder = (IdentityProviderMetadata)provider.getRemoteProvider(a);
      result = responseValidator.validate(a, requestContext, requester, responder, referenceTime);
    }
    else if (saml2Object instanceof ManageNameIDRequest)
    {
      result = validate((ManageNameIDRequest)saml2Object, provider);
    }
    else if (saml2Object instanceof ManageNameIDResponse)
    {
      result = validate((ManageNameIDResponse)saml2Object, provider);
    }
    else
    {
      throw new ValidationException("No validation implemented for class:" + saml2Object.getClass().getName(),
                                    new ValidationResult(saml2Object).addError("Unable to validate SAML object. No implementation."));
    }

    if (result.hasErrors())
    {
      if (LOG.isInfoEnabled())
      {
        LOG.info(result.toString());
      }
      throw new ValidationException("Unable to validate SAML object.", result);
    }
  }

  protected ValidationResult validate(IdentityProviderMetadata metadata, HostedProviderService<?, ?, ?, ?> provider)
  {
    return new ValidationResult(metadata);
  }

  protected ValidationResult validate(ServiceProviderMetadata metadata, HostedProviderService<?, ?, ?, ?> provider)
  {
    return new ValidationResult(metadata);
  }

  protected ValidationResult validate(LogoutRequest logoutRequest, HostedProviderService<?, ?, ?, ?> provider)
  {
    return new ValidationResult(logoutRequest);
  }

  protected ValidationResult validate(LogoutResponse logoutResponse, HostedProviderService<?, ?, ?, ?> provider)
  {
    return new ValidationResult(logoutResponse);
  }

  protected ValidationResult validate(ManageNameIDRequest mniRequest, HostedProviderService<?, ?, ?, ?> provider)
  {
    return new ValidationResult(mniRequest);
  }

  protected ValidationResult validate(ManageNameIDResponse mniResponse, HostedProviderService<?, ?, ?, ?> provider)
  {
    return new ValidationResult(mniResponse);
  }
}
