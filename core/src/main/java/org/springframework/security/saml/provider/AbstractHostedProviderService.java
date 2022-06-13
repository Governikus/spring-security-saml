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

import static java.lang.String.format;
import static java.util.Collections.emptyList;

import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Instant;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import java.util.UUID;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.saml.SamlException;
import org.springframework.security.saml.SamlMetadataCache;
import org.springframework.security.saml.SamlMetadataException;
import org.springframework.security.saml.SamlProviderNotFoundException;
import org.springframework.security.saml.SamlTransformer;
import org.springframework.security.saml.SamlValidator;
import org.springframework.security.saml.key.EncryptionKey;
import org.springframework.security.saml.key.SigningKey;
import org.springframework.security.saml.provider.config.ExternalProviderConfiguration;
import org.springframework.security.saml.provider.config.LocalProviderConfiguration;
import org.springframework.security.saml.provider.service.cache.RequestContextCache.RequestContext;
import org.springframework.security.saml.saml2.Saml2Object;
import org.springframework.security.saml.saml2.authentication.Issuer;
import org.springframework.security.saml.saml2.authentication.LogoutRequest;
import org.springframework.security.saml.saml2.authentication.LogoutResponse;
import org.springframework.security.saml.saml2.authentication.NameIdPrincipal;
import org.springframework.security.saml.saml2.authentication.Status;
import org.springframework.security.saml.saml2.authentication.StatusCode;
import org.springframework.security.saml.saml2.metadata.Binding;
import org.springframework.security.saml.saml2.metadata.Endpoint;
import org.springframework.security.saml.saml2.metadata.IdentityProviderMetadata;
import org.springframework.security.saml.saml2.metadata.Metadata;
import org.springframework.security.saml.saml2.metadata.ServiceProviderMetadata;
import org.springframework.security.saml.saml2.metadata.SsoProvider;
import org.springframework.security.saml.saml2.signature.Signature;
import org.springframework.security.saml.saml2.signature.SignatureException;
import org.springframework.security.saml.validation.ValidationException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;


public abstract class AbstractHostedProviderService<C extends LocalProviderConfiguration<C, E>, L extends Metadata<L>, R extends Metadata<R>, E extends ExternalProviderConfiguration<E>>
  implements HostedProviderService<C, L, R, E>
{

  private static final Log log = LogFactory.getLog(AbstractHostedProviderService.class);

  private final C configuration;

  private final L metadata;

  private final SamlTransformer transformer;

  private final SamlValidator validator;

  private final SamlMetadataCache cache;

  private Clock clock = Clock.systemUTC();

  protected AbstractHostedProviderService(C configuration,
                                          L metadata,
                                          SamlTransformer transformer,
                                          SamlValidator validator,
                                          SamlMetadataCache cache)
  {
    this.configuration = configuration;
    this.metadata = metadata;
    this.transformer = transformer;
    this.validator = validator;
    this.cache = cache;
  }

  public Clock getClock()
  {
    return clock;
  }

  public AbstractHostedProviderService<C, L, R, E> setClock(Clock clock)
  {
    this.clock = clock;
    return this;
  }

  public SamlMetadataCache getCache()
  {
    return cache;
  }

  protected R getRemoteProvider(Issuer issuer)
  {
    if (issuer == null)
    {
      return null;
    }
    else
    {
      return getRemoteProvider(issuer.getValue());
    }
  }

  protected R throwIfNull(R metadata, String key, String value)
  {
    if (metadata == null)
    {
      String message = "Provider for key '%s' with value '%s' not found.";
      throw new SamlProviderNotFoundException(String.format(message, key, value));
    }
    else
    {
      return metadata;
    }
  }

  @Override
  public C getConfiguration()
  {
    return configuration;
  }

  @Override
  public L getMetadata()
  {
    return metadata;
  }

  @Override
  public List<R> getRemoteProviders()
  {
    List<R> result = new LinkedList<>();
    List<E> providers = getConfiguration().getProviders();
    for ( E c : providers )
    {
      try
      {
        R m = getRemoteProvider(c);
        if (m != null)
        {
          m.setEntityAlias(c.getAlias());

          result.add(m);
        }
      }
      catch (SamlException x)
      {
        log.debug("Unable to resolve identity provider metadata.", x);
      }
    }
    return result;
  }

  @Override
  public LogoutRequest logoutRequest(R recipient, NameIdPrincipal principal)
  {
    L local = this.getMetadata();

    List<SsoProvider<?>> ssoProviders = recipient.getSsoProviders();
    return new LogoutRequest().setId("LRQ" + UUID.randomUUID().toString())
                              .setDestination(getPreferredEndpoint(ssoProviders.get(0).getSingleLogoutService(),
                                                                   null,
                                                                   -1))
                              .setIssuer(new Issuer().setValue(local.getEntityId()))
                              .setIssueInstant(Instant.now(getClock()))
                              .setNameId(principal)
                              .setSigningKey(local.getSigningKey(), local.getAlgorithm(), local.getDigest());
  }

  @Override
  public LogoutResponse logoutResponse(String logoutRequestId, R recipient)
  {
    List<SsoProvider<?>> ssoProviders = recipient.getSsoProviders();
    Endpoint destination = getPreferredEndpoint(ssoProviders.get(0).getSingleLogoutService(), null, -1);
    return new LogoutResponse().setId("LRP" + UUID.randomUUID())
                               .setInResponseTo(logoutRequestId)
                               .setDestination(destination != null ? destination.getLocation() : null)
                               .setStatus(new Status().setCode(StatusCode.SUCCESS))
                               .setIssuer(new Issuer().setValue(getMetadata().getEntityId()))
                               .setSigningKey(getMetadata().getSigningKey(),
                                              getMetadata().getAlgorithm(),
                                              getMetadata().getDigest())
                               .setIssueInstant(Instant.now(getClock()))
                               .setVersion("2.0");
  }

  @Override
  public R getRemoteProvider(String entityId)
  {
    for ( R m : getRemoteProviders() )
    {
      while (m != null)
      {
        if (entityId.equals(m.getEntityId()))
        {
          return m;
        }
        m = m.hasNext() ? m.getNext() : null;
      }
    }
    return throwIfNull(null, "remote provider entityId", entityId);
  }

  @Override
  public R getRemoteProvider(ExternalProviderConfiguration<?> c)
  {
    String metadataRaw = c.getMetadata();
    R result = resolve(metadataRaw, c.isSkipSslValidation());
    if (c.isMetadataTrustCheck())
    {
      result = metadataTrustCheck(c, result);
    }
    if (result != null)
    {
      addStaticKeys(c, result);
    }
    return result;
  }

  private void addStaticKeys(ExternalProviderConfiguration<?> config, R metadata)
  {
    if (!config.getVerificationKeys().isEmpty() && metadata != null)
    {
      for ( SsoProvider<?> provider : metadata.getSsoProviders() )
      {
        List<SigningKey> keys = new LinkedList<>(provider.getSigningKeys());
        keys.addAll(config.getVerificationKeyData());
        provider.setSigningKeys(keys);
      }
    }
  }

  private R metadataTrustCheck(ExternalProviderConfiguration<?> c, R result)
  {
    if (!c.isMetadataTrustCheck())
    {
      return result;
    }
    if (c.getVerificationKeys().isEmpty())
    {
      log.warn("No keys to verify metadata for " + c.getMetadata() + " with. Unable to trust.");
      return null;
    }
    try
    {
      Signature signature = validator.validateSignature(result, c.getVerificationKeyData());
      if (signature != null && signature.isValidated() && signature.getValidatingKey() != null)
      {
        return result;
      }
      else
      {
        log.warn("Missing signature for " + c.getMetadata() + ". Unable to trust.");
      }
    }
    catch (SignatureException e)
    {
      if (log.isDebugEnabled())
      {
        log.debug("Invalid signature for remote provider metadata " + c.getMetadata() + ". Unable to trust.", e);
      }
      else
      {
        log.warn("Invalid signature for remote provider with alias: " + c.getAlias()
                 + ". Unable to trust metadata. Discarding it.");
      }
    }
    return null;
  }

  /**
   * @throws ValidationException if saml2Object is not valid
   * @throws SignatureException if xml signature on saml2object is not valid
   */
  @Override
  public void validate(Saml2Object saml2Object, RequestContext requestContext)
  {
    getValidator().validate(saml2Object, this, requestContext);

    R remote = getRemoteProvider(saml2Object);
    List<SigningKey> verificationKeys = getVerificationKeys(remote);
    if (verificationKeys != null && !verificationKeys.isEmpty())
    {
      getValidator().validateSignature(saml2Object, verificationKeys);
    }
  }

  private List<SigningKey> getVerificationKeys(R remote)
  {
    List<SigningKey> verificationKeys = emptyList();
    if (remote instanceof ServiceProviderMetadata)
    {
      verificationKeys = ((ServiceProviderMetadata)remote).getServiceProvider().getSigningKeys();
    }
    else if (remote instanceof IdentityProviderMetadata)
    {
      verificationKeys = ((IdentityProviderMetadata)remote).getIdentityProvider().getSigningKeys();
    }
    return verificationKeys;
  }

  public SamlValidator getValidator()
  {
    return validator;
  }

  @Override
  public <T extends Saml2Object> T fromXml(String xml, boolean encoded, boolean deflated, Class<T> type)
  {
    if (encoded)
    {
      xml = getTransformer().samlDecode(xml, deflated);
    }
    return fromXml(xml, type, (x, v, d) -> getTransformer().fromXml(x, v, d));
  }

  @Override
  public <T extends Saml2Object> T fromXml(Document document, Class<T> type)
  {
    return fromXml(document, type, (x, v, d) -> getTransformer().fromXml(x, v, d));
  }

  @FunctionalInterface
  private interface Transformer<R>
  {

    Saml2Object transform(R r, List<SigningKey> verificationKeys, List<EncryptionKey> decryptionKeys);

  }

  private <T extends Saml2Object, S> T fromXml(S xml, Class<T> type, Transformer<S> transformer)
  {
    List<EncryptionKey> decryptionKeys = getConfiguration().getEncryptionKeys() == null ? Arrays.asList()
      : getConfiguration().getEncryptionKeys().toList();
    Saml2Object result = type.cast(transformer.transform(xml, null, decryptionKeys));
    // in order to add signatures, we need the verification keys from the remote provider
    R remote = getRemoteProvider(result);
    List<SigningKey> verificationKeys = remote.getSsoProviders().get(0).getSigningKeys();
    // perform transformation with verification keys
    return type.cast(transformer.transform(xml, verificationKeys, decryptionKeys));
  }

  @Override
  public String toXml(Saml2Object saml2Object)
  {
    return getTransformer().toXml(saml2Object);
  }

  @Override
  public Element toXmlElement(Saml2Object saml2Object)
  {
    return getTransformer().toXmlElement(saml2Object);
  }

  @Override
  public String toEncodedXml(Saml2Object saml2Object, boolean deflate)
  {
    String xml = toXml(saml2Object);
    return toEncodedXml(xml, deflate);
  }

  @Override
  public String toEncodedXml(String xml, boolean deflate)
  {
    return getTransformer().samlEncode(xml, deflate);
  }

  @Override
  public Endpoint getPreferredEndpoint(List<Endpoint> endpoints, Binding preferredBinding, int preferredIndex)
  {
    if (endpoints == null || endpoints.isEmpty())
    {
      return null;
    }
    // find the preferred binding
    if (preferredBinding != null)
    {
      for ( Endpoint e : endpoints )
      {
        if (preferredBinding.equals(e.getBinding()))
        {
          return e;
        }
      }
    }
    // find the configured index
    for ( Endpoint e : endpoints )
    {
      if (e.getIndex() == preferredIndex)
      {
        return e;
      }
    }
    // find the default endpoint
    for ( Endpoint e : endpoints )
    {
      if (e.isDefault())
      {
        return e;
      }
    }
    // fallback to the very first available endpoint
    return endpoints.get(0);
  }

  public SamlTransformer getTransformer()
  {
    return transformer;
  }

  private R resolve(String metadata, boolean skipSslValidation)
  {
    R result = null;
    if (isUri(metadata))
    {
      try
      {
        byte[] data = cache.getMetadata(metadata, skipSslValidation);
        if (data != null)
        {
          result = transformMetadata(new String(data, StandardCharsets.UTF_8));
        }
      }
      catch (SamlException x)
      {
        throw x;
      }
      catch (Exception x)
      {
        String message = format("Unable to fetch metadata from: %s with message: %s", metadata, x.getMessage());
        if (log.isDebugEnabled())
        {
          log.debug(message, x);
        }
        else
        {
          log.info(message);
        }
        throw new SamlMetadataException("Unable to successfully get metadata from:" + metadata, x);
      }
    }
    else
    {
      result = transformMetadata(metadata);
    }
    return throwIfNull(result, "metadata", metadata);
  }

  protected abstract R transformMetadata(String data);

  private boolean isUri(String uri)
  {
    boolean isUri = false;
    try
    {
      new URI(uri);
      isUri = true;
    }
    catch (URISyntaxException e)
    {
      // ignore
    }
    return isUri;
  }

  protected R getRemoteProvider(LogoutResponse response)
  {
    String issuer = response.getIssuer() != null ? response.getIssuer().getValue() : null;
    return getRemoteProvider(issuer);
  }

  protected R getRemoteProvider(LogoutRequest request)
  {
    String issuer = request.getIssuer() != null ? request.getIssuer().getValue() : null;
    return getRemoteProvider(issuer);
  }
}
