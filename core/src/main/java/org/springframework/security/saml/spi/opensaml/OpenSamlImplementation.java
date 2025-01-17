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

package org.springframework.security.saml.spi.opensaml;

import static java.lang.Boolean.FALSE;
import static java.lang.Boolean.TRUE;
import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.Arrays.asList;
import static java.util.Collections.emptyList;
import static java.util.Optional.ofNullable;
import static org.opensaml.saml.saml2.core.AuthnContextComparisonTypeEnumeration.EXACT;
import static org.opensaml.security.crypto.KeySupport.generateKey;
import static org.springframework.security.saml.saml2.Namespace.NS_PROTOCOL;
import static org.springframework.util.StringUtils.hasText;

import java.io.ByteArrayInputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.time.Clock;
import java.time.Instant;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;
import java.util.function.Function;
import java.util.stream.Collectors;

import javax.crypto.SecretKey;
import javax.xml.datatype.Duration;
import javax.xml.namespace.QName;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.xml.security.algorithms.JCEMapper;
import org.apache.xml.security.signature.XMLSignatureException;
import org.opensaml.core.config.ConfigurationService;
import org.opensaml.core.config.InitializationException;
import org.opensaml.core.config.InitializationService;
import org.opensaml.core.criterion.EntityIdCriterion;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.XMLObjectBuilder;
import org.opensaml.core.xml.XMLObjectBuilderFactory;
import org.opensaml.core.xml.config.XMLObjectProviderRegistry;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.Marshaller;
import org.opensaml.core.xml.io.MarshallerFactory;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.core.xml.io.UnmarshallerFactory;
import org.opensaml.core.xml.io.UnmarshallingException;
import org.opensaml.core.xml.schema.XSAny;
import org.opensaml.core.xml.schema.XSBase64Binary;
import org.opensaml.core.xml.schema.XSBoolean;
import org.opensaml.core.xml.schema.XSBooleanValue;
import org.opensaml.core.xml.schema.XSDateTime;
import org.opensaml.core.xml.schema.XSInteger;
import org.opensaml.core.xml.schema.XSString;
import org.opensaml.core.xml.schema.XSURI;
import org.opensaml.core.xml.schema.impl.XSAnyBuilder;
import org.opensaml.core.xml.schema.impl.XSBooleanBuilder;
import org.opensaml.core.xml.schema.impl.XSDateTimeBuilder;
import org.opensaml.core.xml.schema.impl.XSIntegerBuilder;
import org.opensaml.core.xml.schema.impl.XSStringBuilder;
import org.opensaml.core.xml.schema.impl.XSURIBuilder;
import org.opensaml.saml.common.SAMLObject;
import org.opensaml.saml.common.SAMLObjectBuilder;
import org.opensaml.saml.common.SAMLObjectContentReference;
import org.opensaml.saml.common.SAMLVersion;
import org.opensaml.saml.common.SignableSAMLObject;
import org.opensaml.saml.ext.idpdisco.DiscoveryResponse;
import org.opensaml.saml.ext.idpdisco.impl.DiscoveryResponseBuilder;
import org.opensaml.saml.ext.saml2mdreqinit.RequestInitiator;
import org.opensaml.saml.ext.saml2mdreqinit.impl.RequestInitiatorBuilder;
import org.opensaml.saml.saml2.core.AttributeStatement;
import org.opensaml.saml.saml2.core.AttributeValue;
import org.opensaml.saml.saml2.core.Audience;
import org.opensaml.saml.saml2.core.AuthenticatingAuthority;
import org.opensaml.saml.saml2.core.AuthnContext;
import org.opensaml.saml.saml2.core.AuthnContextClassRef;
import org.opensaml.saml.saml2.core.AuthnContextComparisonTypeEnumeration;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.core.AuthnStatement;
import org.opensaml.saml.saml2.core.Condition;
import org.opensaml.saml.saml2.core.EncryptedAssertion;
import org.opensaml.saml.saml2.core.EncryptedAttribute;
import org.opensaml.saml.saml2.core.EncryptedElementType;
import org.opensaml.saml.saml2.core.EncryptedID;
import org.opensaml.saml.saml2.core.IDPEntry;
import org.opensaml.saml.saml2.core.IDPList;
import org.opensaml.saml.saml2.core.NameID;
import org.opensaml.saml.saml2.core.NameIDPolicy;
import org.opensaml.saml.saml2.core.NameIDType;
import org.opensaml.saml.saml2.core.RequestedAuthnContext;
import org.opensaml.saml.saml2.core.RequesterID;
import org.opensaml.saml.saml2.core.StatusMessage;
import org.opensaml.saml.saml2.core.impl.StatusBuilder;
import org.opensaml.saml.saml2.core.impl.StatusCodeBuilder;
import org.opensaml.saml.saml2.core.impl.StatusMessageBuilder;
import org.opensaml.saml.saml2.encryption.Decrypter;
import org.opensaml.saml.saml2.encryption.EncryptedElementTypeEncryptedKeyResolver;
import org.opensaml.saml.saml2.encryption.Encrypter;
import org.opensaml.saml.saml2.metadata.ArtifactResolutionService;
import org.opensaml.saml.saml2.metadata.AssertionConsumerService;
import org.opensaml.saml.saml2.metadata.AttributeConsumingService;
import org.opensaml.saml.saml2.metadata.EncryptionMethod;
import org.opensaml.saml.saml2.metadata.EntitiesDescriptor;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml.saml2.metadata.Extensions;
import org.opensaml.saml.saml2.metadata.IDPSSODescriptor;
import org.opensaml.saml.saml2.metadata.IndexedEndpoint;
import org.opensaml.saml.saml2.metadata.KeyDescriptor;
import org.opensaml.saml.saml2.metadata.ManageNameIDService;
import org.opensaml.saml.saml2.metadata.NameIDFormat;
import org.opensaml.saml.saml2.metadata.Organization;
import org.opensaml.saml.saml2.metadata.OrganizationDisplayName;
import org.opensaml.saml.saml2.metadata.OrganizationName;
import org.opensaml.saml.saml2.metadata.OrganizationURL;
import org.opensaml.saml.saml2.metadata.RequestedAttribute;
import org.opensaml.saml.saml2.metadata.RoleDescriptor;
import org.opensaml.saml.saml2.metadata.SPSSODescriptor;
import org.opensaml.saml.saml2.metadata.SingleLogoutService;
import org.opensaml.saml.saml2.metadata.SingleSignOnService;
import org.opensaml.saml.saml2.metadata.impl.EncryptionMethodBuilder;
import org.opensaml.saml.saml2.metadata.impl.ExtensionsBuilder;
import org.opensaml.security.SecurityException;
import org.opensaml.security.credential.BasicCredential;
import org.opensaml.security.credential.Credential;
import org.opensaml.security.credential.UsageType;
import org.opensaml.security.credential.impl.KeyStoreCredentialResolver;
import org.opensaml.xmlsec.SignatureSigningParameters;
import org.opensaml.xmlsec.config.impl.DefaultSecurityConfigurationBootstrap;
import org.opensaml.xmlsec.encryption.KeySize;
import org.opensaml.xmlsec.encryption.impl.KeySizeBuilder;
import org.opensaml.xmlsec.encryption.support.ChainingEncryptedKeyResolver;
import org.opensaml.xmlsec.encryption.support.DataEncryptionParameters;
import org.opensaml.xmlsec.encryption.support.DecryptionException;
import org.opensaml.xmlsec.encryption.support.EncryptionException;
import org.opensaml.xmlsec.encryption.support.InlineEncryptedKeyResolver;
import org.opensaml.xmlsec.encryption.support.KeyEncryptionParameters;
import org.opensaml.xmlsec.encryption.support.SimpleRetrievalMethodEncryptedKeyResolver;
import org.opensaml.xmlsec.keyinfo.KeyInfoCredentialResolver;
import org.opensaml.xmlsec.keyinfo.KeyInfoGenerator;
import org.opensaml.xmlsec.keyinfo.NamedKeyInfoGeneratorManager;
import org.opensaml.xmlsec.keyinfo.impl.StaticKeyInfoCredentialResolver;
import org.opensaml.xmlsec.signature.KeyInfo;
import org.opensaml.xmlsec.signature.X509Certificate;
import org.opensaml.xmlsec.signature.X509Data;
import org.opensaml.xmlsec.signature.impl.SignatureImpl;
import org.opensaml.xmlsec.signature.support.ContentReference;
import org.opensaml.xmlsec.signature.support.SignatureException;
import org.opensaml.xmlsec.signature.support.SignatureSupport;
import org.opensaml.xmlsec.signature.support.SignatureValidator;
import org.opensaml.xmlsec.signature.support.Signer;
import org.springframework.security.saml.SamlException;
import org.springframework.security.saml.SamlKeyException;
import org.springframework.security.saml.key.EncryptionKey;
import org.springframework.security.saml.key.SigningKey;
import org.springframework.security.saml.key.SimpleKey;
import org.springframework.security.saml.saml2.ImplementationHolder;
import org.springframework.security.saml.saml2.Saml2Object;
import org.springframework.security.saml.saml2.attribute.Attribute;
import org.springframework.security.saml.saml2.attribute.AttributeNameFormat;
import org.springframework.security.saml.saml2.authentication.Assertion;
import org.springframework.security.saml.saml2.authentication.AssertionCondition;
import org.springframework.security.saml.saml2.authentication.AudienceRestriction;
import org.springframework.security.saml.saml2.authentication.AuthenticationContext;
import org.springframework.security.saml.saml2.authentication.AuthenticationContextClassReference;
import org.springframework.security.saml.saml2.authentication.AuthenticationRequest;
import org.springframework.security.saml.saml2.authentication.AuthenticationStatement;
import org.springframework.security.saml.saml2.authentication.Conditions;
import org.springframework.security.saml.saml2.authentication.Issuer;
import org.springframework.security.saml.saml2.authentication.LogoutReason;
import org.springframework.security.saml.saml2.authentication.LogoutRequest;
import org.springframework.security.saml.saml2.authentication.LogoutResponse;
import org.springframework.security.saml.saml2.authentication.ManageNameIDRequest;
import org.springframework.security.saml.saml2.authentication.ManageNameIDResponse;
import org.springframework.security.saml.saml2.authentication.NameIdPolicy;
import org.springframework.security.saml.saml2.authentication.NameIdPrincipal;
import org.springframework.security.saml.saml2.authentication.OneTimeUse;
import org.springframework.security.saml.saml2.authentication.RequestedAuthenticationContext;
import org.springframework.security.saml.saml2.authentication.Response;
import org.springframework.security.saml.saml2.authentication.Scoping;
import org.springframework.security.saml.saml2.authentication.Status;
import org.springframework.security.saml.saml2.authentication.StatusCode;
import org.springframework.security.saml.saml2.authentication.Subject;
import org.springframework.security.saml.saml2.authentication.SubjectConfirmation;
import org.springframework.security.saml.saml2.authentication.SubjectConfirmationData;
import org.springframework.security.saml.saml2.authentication.SubjectConfirmationMethod;
import org.springframework.security.saml.saml2.encrypt.DataEncryptionMethod;
import org.springframework.security.saml.saml2.encrypt.KeyEncryptionMethod;
import org.springframework.security.saml.saml2.metadata.Binding;
import org.springframework.security.saml.saml2.metadata.Endpoint;
import org.springframework.security.saml.saml2.metadata.IdentityProvider;
import org.springframework.security.saml.saml2.metadata.IdentityProviderMetadata;
import org.springframework.security.saml.saml2.metadata.Metadata;
import org.springframework.security.saml.saml2.metadata.NameId;
import org.springframework.security.saml.saml2.metadata.Provider;
import org.springframework.security.saml.saml2.metadata.ServiceProvider;
import org.springframework.security.saml.saml2.metadata.ServiceProviderMetadata;
import org.springframework.security.saml.saml2.metadata.SsoProvider;
import org.springframework.security.saml.saml2.signature.AlgorithmMethod;
import org.springframework.security.saml.saml2.signature.CanonicalizationMethod;
import org.springframework.security.saml.saml2.signature.DigestMethod;
import org.springframework.security.saml.saml2.signature.Signature;
import org.springframework.security.saml.spi.SamlKeyStoreProvider;
import org.springframework.security.saml.spi.SpringSecuritySaml;
import org.springframework.util.CollectionUtils;
import org.springframework.util.ObjectUtils;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.resolver.CriteriaSet;
import net.shibboleth.utilities.java.support.resolver.ResolverException;
import net.shibboleth.utilities.java.support.xml.BasicParserPool;
import net.shibboleth.utilities.java.support.xml.DOMTypeSupport;
import net.shibboleth.utilities.java.support.xml.SerializeSupport;
import net.shibboleth.utilities.java.support.xml.XMLParserException;


public class OpenSamlImplementation extends SpringSecuritySaml<OpenSamlImplementation>
{

  private static final Log log = LogFactory.getLog(OpenSamlImplementation.class);

  private BasicParserPool parserPool;

  private ChainingEncryptedKeyResolver encryptedKeyResolver;

  private SamlKeyStoreProvider samlKeyStoreProvider = new SamlKeyStoreProvider()
  {};

  public OpenSamlImplementation(Clock time)
  {
    super(time);
    parserPool = new BasicParserPool();
  }

  public SamlKeyStoreProvider getSamlKeyStoreProvider()
  {
    return samlKeyStoreProvider;
  }

  public OpenSamlImplementation setSamlKeyStoreProvider(SamlKeyStoreProvider samlKeyStoreProvider)
  {
    this.samlKeyStoreProvider = samlKeyStoreProvider;
    return this;
  }

  public BasicParserPool getParserPool()
  {
    return parserPool;
  }

  public MarshallerFactory getMarshallerFactory()
  {
    return XMLObjectProviderRegistrySupport.getMarshallerFactory();
  }

  public UnmarshallerFactory getUnmarshallerFactory()
  {
    return XMLObjectProviderRegistrySupport.getUnmarshallerFactory();
  }

  public EntityDescriptor getEntityDescriptor()
  {
    XMLObjectBuilderFactory builderFactory = getBuilderFactory();
    SAMLObjectBuilder<EntityDescriptor> builder = (SAMLObjectBuilder<EntityDescriptor>)builderFactory.getBuilder(EntityDescriptor.DEFAULT_ELEMENT_NAME);
    return builder.buildObject();
  }

  public SPSSODescriptor getSPSSODescriptor()
  {
    SAMLObjectBuilder<SPSSODescriptor> builder = (SAMLObjectBuilder<SPSSODescriptor>)getBuilderFactory().getBuilder(SPSSODescriptor.DEFAULT_ELEMENT_NAME);
    return builder.buildObject();
  }

  public IDPSSODescriptor getIDPSSODescriptor()
  {
    SAMLObjectBuilder<IDPSSODescriptor> builder = (SAMLObjectBuilder<IDPSSODescriptor>)getBuilderFactory().getBuilder(IDPSSODescriptor.DEFAULT_ELEMENT_NAME);
    return builder.buildObject();
  }

  public Extensions getMetadataExtensions()
  {
    SAMLObjectBuilder<Extensions> builder = (SAMLObjectBuilder<Extensions>)getBuilderFactory().getBuilder(Extensions.DEFAULT_ELEMENT_NAME);
    return builder.buildObject();
  }

  public XMLObjectBuilderFactory getBuilderFactory()
  {
    return XMLObjectProviderRegistrySupport.getBuilderFactory();
  }

  @Override
  protected void bootstrap()
  {
    // configure default values
    parserPool.setMaxPoolSize(50);
    parserPool.setCoalescing(true);
    parserPool.setExpandEntityReferences(false);
    parserPool.setIgnoreComments(true);
    parserPool.setIgnoreElementContentWhitespace(true);
    parserPool.setNamespaceAware(true);
    parserPool.setSchema(null);
    parserPool.setDTDValidating(false);
    parserPool.setXincludeAware(false);

    Map<String, Object> builderAttributes = new HashMap<>();
    parserPool.setBuilderAttributes(builderAttributes);

    Map<String, Boolean> parserBuilderFeatures = new HashMap<>();
    parserBuilderFeatures.put("http://apache.org/xml/features/disallow-doctype-decl", TRUE);
    parserBuilderFeatures.put("http://javax.xml.XMLConstants/feature/secure-processing", TRUE);
    parserBuilderFeatures.put("http://xml.org/sax/features/external-general-entities", FALSE);
    parserBuilderFeatures.put("http://apache.org/xml/features/validation/schema/normalized-value", FALSE);
    parserBuilderFeatures.put("http://xml.org/sax/features/external-parameter-entities", FALSE);
    parserBuilderFeatures.put("http://apache.org/xml/features/dom/defer-node-expansion", FALSE);
    parserPool.setBuilderFeatures(parserBuilderFeatures);

    try
    {
      parserPool.initialize();
    }
    catch (ComponentInitializationException x)
    {
      throw new SamlException("Unable to initialize OpenSaml v3 ParserPool", x);
    }


    try
    {
      InitializationService.initialize();
    }
    catch (InitializationException e)
    {
      throw new SamlException("Unable to initialize OpenSaml v3", e);
    }

    XMLObjectProviderRegistry registry;
    synchronized (ConfigurationService.class)
    {
      registry = ConfigurationService.get(XMLObjectProviderRegistry.class);
      if (registry == null)
      {
        registry = new XMLObjectProviderRegistry();
        ConfigurationService.register(XMLObjectProviderRegistry.class, registry);
      }
    }

    registry.setParserPool(parserPool);
    encryptedKeyResolver = new ChainingEncryptedKeyResolver(asList(new InlineEncryptedKeyResolver(),
                                                                   new EncryptedElementTypeEncryptedKeyResolver(),
                                                                   new SimpleRetrievalMethodEncryptedKeyResolver()));
  }

  public java.time.Duration toJavaTimeDuration(Duration duration)
  {
    if (duration == null)
    {
      return null;
    }

    long now = getTime().millis();
    long timeInMillis = duration.getTimeInMillis(new Date(now));
    return java.time.Duration.ofMillis(timeInMillis);
  }

  public Duration toJavaXmlDuration(java.time.Duration duration)
  {
    if (duration == null)
    {
      return null;
    }
    else
    {
      return DOMTypeSupport.getDataTypeFactory().newDuration(duration.toMillis());
    }
  }

  @Override
  public Element toXmlElement(Saml2Object saml2Object)
  {
    return toXml(saml2Object, this::marshall);
  }

  @Override
  public String toXml(Saml2Object saml2Object)
  {
    return toXml(saml2Object, this::marshallToXml);
  }

  protected <R> R toXml(Saml2Object saml2Object, Function<XMLObject, R> marshallFunction)
  {
    XMLObject result = null;
    if (saml2Object instanceof AuthenticationRequest)
    {
      result = internalToXml((AuthenticationRequest)saml2Object);
    }
    else if (saml2Object instanceof Assertion)
    {
      result = internalToXml((Assertion)saml2Object);
    }
    else if (saml2Object instanceof Metadata)
    {
      result = internalToXml((Metadata)saml2Object);
    }
    else if (saml2Object instanceof Response)
    {
      result = internalToXml((Response)saml2Object);
    }
    else if (saml2Object instanceof LogoutRequest)
    {
      result = internalToXml((LogoutRequest)saml2Object);
    }
    else if (saml2Object instanceof LogoutResponse)
    {
      result = internalToXml((LogoutResponse)saml2Object);
    }
    else if (saml2Object instanceof ManageNameIDRequest)
    {
      result = internalToXml((ManageNameIDRequest)saml2Object);
    }
    else if (saml2Object instanceof ManageNameIDResponse)
    {
      result = internalToXml((ManageNameIDResponse)saml2Object);
    }
    if (result != null)
    {
      return marshallFunction.apply(result);
    }
    throw new SamlException("To xml transformation not supported for: "
                            + (saml2Object == null ? "null" : saml2Object.getClass().getName()));
  }

  @Override
  public Saml2Object resolve(String xml, List<SigningKey> verificationKeys, List<EncryptionKey> localKeys)
  {
    return resolve(xml.getBytes(UTF_8), verificationKeys, localKeys);
  }

  @Override
  public Saml2Object resolve(byte[] xml, List<SigningKey> verificationKeys, List<EncryptionKey> localKeys)
  {
    XMLObject parsed = parse(xml);
    return resolve(xml, parsed, verificationKeys, localKeys);
  }

  @Override
  public Saml2Object resolve(Document document, List<SigningKey> verificationKeys, List<EncryptionKey> localKeys)
  {
    XMLObject parsed = unmarshall(document.getDocumentElement());
    return resolve(null, parsed, verificationKeys, localKeys);
  }

  public Saml2Object resolve(byte[] originalXml,
                             XMLObject parsed,
                             List<SigningKey> verificationKeys,
                             List<EncryptionKey> localKeys)
  {
    Signature signature = validateSignature((SignableSAMLObject)parsed, verificationKeys);
    Saml2Object result = null;
    if (parsed instanceof EntityDescriptor)
    {
      result = resolveMetadata((EntityDescriptor)parsed).setSignature(signature);
    }
    else if (parsed instanceof EntitiesDescriptor)
    {
      result = resolveMetadata((EntitiesDescriptor)parsed, verificationKeys, localKeys);
    }
    else if (parsed instanceof AuthnRequest)
    {
      result = resolveAuthenticationRequest((AuthnRequest)parsed).setSignature(signature);
    }
    else if (parsed instanceof org.opensaml.saml.saml2.core.Assertion)
    {
      result = resolveAssertion((org.opensaml.saml.saml2.core.Assertion)parsed, verificationKeys, localKeys);
    }
    else if (parsed instanceof org.opensaml.saml.saml2.core.Response)
    {
      result = resolveResponse((org.opensaml.saml.saml2.core.Response)parsed,
                               verificationKeys,
                               localKeys).setSignature(signature);
    }
    else if (parsed instanceof org.opensaml.saml.saml2.core.LogoutRequest)
    {
      result = resolveLogoutRequest((org.opensaml.saml.saml2.core.LogoutRequest)parsed,
                                    verificationKeys,
                                    localKeys).setSignature(signature);
    }
    else if (parsed instanceof org.opensaml.saml.saml2.core.LogoutResponse)
    {
      result = resolveLogoutResponse((org.opensaml.saml.saml2.core.LogoutResponse)parsed,
                                     verificationKeys,
                                     localKeys).setSignature(signature);
    }
    else if (parsed instanceof org.opensaml.saml.saml2.core.ManageNameIDRequest)
    {
      result = resolveManageNameIDRequest((org.opensaml.saml.saml2.core.ManageNameIDRequest)parsed,
                                          localKeys).setSignature(signature);
    }
    else if (parsed instanceof org.opensaml.saml.saml2.core.ManageNameIDResponse)
    {
      result = resolveManageNameIDResponse((org.opensaml.saml.saml2.core.ManageNameIDResponse)parsed).setSignature(signature);
    }
    if (result != null)
    {
      if (result instanceof ImplementationHolder)
      {
        ((ImplementationHolder)result).setImplementation(parsed);
        if (originalXml != null)
        {
          ((ImplementationHolder)result).setOriginalXML(new String(originalXml, StandardCharsets.UTF_8));
        }
      }
      return result;
    }
    throw new SamlException("Deserialization not yet supported for class: " + parsed.getClass());
  }

  @Override
  public Signature validateSignature(Saml2Object saml2Object, List<SigningKey> trustedKeys)
  {
    if (saml2Object == null || saml2Object.getImplementation() == null)
    {
      throw new SamlException("No object to validate signature against.");
    }

    if (trustedKeys == null || trustedKeys.isEmpty())
    {
      throw new SamlKeyException("At least one verification key has to be provided");
    }

    if (saml2Object.getImplementation() instanceof SignableSAMLObject)
    {
      return validateSignature((SignableSAMLObject)saml2Object.getImplementation(), trustedKeys);
    }
    else
    {
      throw new SamlException("Unrecognized object type:" + saml2Object.getImplementation().getClass().getName());
    }
  }

  public Signature validateSignature(SignableSAMLObject object, List<SigningKey> keys)
  {
    Signature result = null;
    List<SigningKey> signatureKeys;
    if (keys == null || keys.isEmpty())
    {
      return result;
    }
    else
    {
      signatureKeys = keys.stream().filter(Objects::nonNull).collect(Collectors.toList());
    }

    if (object.isSigned())
    {
      SignatureException last = null;
      for ( SigningKey signatureKey : signatureKeys )
      {
        try
        {
          Credential credential = getCredential(signatureKey, getCredentialsResolver(signatureKey));
          SignatureValidator.validate(object.getSignature(), credential);
          last = null;
          result = getSignature(object).setValidated(true).setValidatingKey(signatureKey);
          break;
        }
        catch (SignatureException e)
        {
          last = e;
        }
      }
      if (last != null)
      {
        throw new org.springframework.security.saml.saml2.signature.SignatureException("Signature validation against a "
                                                                                       + object.getClass().getName()
                                                                                       + " object failed using "
                                                                                       + signatureKeys.size()
                                                                                       + (signatureKeys.size() == 1
                                                                                         ? " key." : " keys."),
                                                                                       last);
      }
    }
    return result;
  }

  public <K extends SimpleKey<K>> Credential getCredential(K key, KeyStoreCredentialResolver resolver)
  {
    try
    {
      CriteriaSet cs = new CriteriaSet();
      EntityIdCriterion criteria = new EntityIdCriterion(key.getName());
      cs.add(criteria);
      return resolver.resolveSingle(cs);
    }
    catch (ResolverException e)
    {
      throw new SamlKeyException("Can't obtain SP private key", e);
    }
  }

  public <K extends SimpleKey<K>> KeyStoreCredentialResolver getCredentialsResolver(K key)
  {
    KeyStore ks = getSamlKeyStoreProvider().getKeyStore(key);
    Map<String, String> passwords = hasText(key.getPrivateKey())
      ? Collections.singletonMap(key.getName(), key.getPassphrase()) : Collections.emptyMap();
    return new KeyStoreCredentialResolver(ks, passwords);
  }

  protected Signature getSignature(SignableSAMLObject target)
  {
    org.opensaml.xmlsec.signature.Signature signature = target.getSignature();
    Signature result = null;
    if (signature instanceof SignatureImpl)
    {
      SignatureImpl impl = (SignatureImpl)signature;
      try
      {
        result = new Signature().setSignatureAlgorithm(AlgorithmMethod.fromUrn(impl.getSignatureAlgorithm()))
                                .setCanonicalizationAlgorithm(CanonicalizationMethod.fromUrn(impl.getCanonicalizationAlgorithm()))
                                .setSignatureValue(org.apache.xml.security.utils.Base64.encode(impl.getXMLSignature()
                                                                                                   .getSignatureValue()));
        // TODO extract the digest value
        for ( ContentReference ref : ofNullable(signature.getContentReferences()).orElse(emptyList()) )
        {
          if (ref instanceof SAMLObjectContentReference)
          {
            SAMLObjectContentReference sref = (SAMLObjectContentReference)ref;
            result.setDigestAlgorithm(DigestMethod.fromUrn(sref.getDigestAlgorithm()));
          }
        }

      }
      catch (XMLSignatureException e)
      {
        // TODO - ignore for now
      }
    }
    return result;
  }

  protected EncryptedAssertion encryptAssertion(org.opensaml.saml.saml2.core.Assertion assertion,
                                                EncryptionKey key,
                                                KeyEncryptionMethod keyAlgorithm,
                                                DataEncryptionMethod dataAlgorithm)
  {
    Encrypter encrypter = getEncrypter(key, keyAlgorithm, dataAlgorithm);
    try
    {
      Encrypter.KeyPlacement keyPlacement = Encrypter.KeyPlacement.valueOf(System.getProperty("spring.security.saml.encrypt.key.placement",
                                                                                              "PEER"));
      encrypter.setKeyPlacement(keyPlacement);
      return encrypter.encrypt(assertion);
    }
    catch (EncryptionException e)
    {
      throw new SamlException("Unable to encrypt assertion.", e);
    }
  }

  protected SAMLObject decrypt(EncryptedElementType encrypted, List<EncryptionKey> keys)
  {
    if (keys == null || keys.isEmpty())
    {
      log.error("No decryption keys present. Cannot decrypt encrypted object");
      return null;
    }

    DecryptionException last = null;
    List<EncryptionKey> decryptionKeys = keys.stream().filter(Objects::nonNull).collect(Collectors.toList());
    for ( EncryptionKey key : decryptionKeys )
    {
      Decrypter decrypter = getDecrypter(key);
      try
      {
        return (SAMLObject)decrypter.decryptData(encrypted.getEncryptedData());
      }
      catch (DecryptionException e)
      {
        log.debug("Unable to decrypt element.", e);
        last = e;
      }
    }
    if (last != null)
    {
      throw new SamlKeyException("Unable to decrypt object.", last);
    }
    return null;
  }

  protected Encrypter getEncrypter(EncryptionKey key,
                                   KeyEncryptionMethod keyAlgorithm,
                                   DataEncryptionMethod dataAlgorithm)
  {
    Credential credential = getCredential(key, getCredentialsResolver(key));

    SecretKey secretKey = generateKeyFromURI(dataAlgorithm);
    BasicCredential dataCredential = new BasicCredential(secretKey);
    DataEncryptionParameters dataEncryptionParameters = new DataEncryptionParameters();
    dataEncryptionParameters.setEncryptionCredential(dataCredential);
    dataEncryptionParameters.setAlgorithm(dataAlgorithm.toString());

    KeyEncryptionParameters keyEncryptionParameters = new KeyEncryptionParameters();
    keyEncryptionParameters.setEncryptionCredential(credential);
    keyEncryptionParameters.setAlgorithm(keyAlgorithm.toString());

    return new Encrypter(dataEncryptionParameters, asList(keyEncryptionParameters));
  }

  public static SecretKey generateKeyFromURI(DataEncryptionMethod algoURI)
  {
    try
    {
      String jceAlgorithmName = JCEMapper.getJCEKeyAlgorithmFromURI(algoURI.toString());
      int keyLength = JCEMapper.getKeyLengthFromURI(algoURI.toString());
      return generateKey(jceAlgorithmName, keyLength, null);
    }
    catch (NoSuchAlgorithmException | NoSuchProviderException e)
    {
      throw new SamlException(e);
    }
  }

  protected Decrypter getDecrypter(EncryptionKey key)
  {
    Credential credential = getCredential(key, getCredentialsResolver(key));
    KeyInfoCredentialResolver resolver = new StaticKeyInfoCredentialResolver(credential);
    Decrypter decrypter = new Decrypter(null, resolver, encryptedKeyResolver);
    decrypter.setRootInNewDocument(true);
    return decrypter;
  }

  protected XMLObject parse(byte[] xml)
  {
    try
    {
      Document document = getParserPool().parse(new ByteArrayInputStream(xml));
      Element element = document.getDocumentElement();
      return unmarshall(element);
    }
    catch (XMLParserException e)
    {
      throw new SamlException(e);
    }
  }

  protected XMLObject unmarshall(Element element)
  {
    try
    {
      return getUnmarshallerFactory().getUnmarshaller(element).unmarshall(element);
    }
    catch (UnmarshallingException e)
    {
      throw new SamlException(e);
    }
  }

  protected List<? extends Provider<?>> getSsoProviders(EntityDescriptor descriptor)
  {
    final List<SsoProvider<?>> providers = new LinkedList<>();
    for ( RoleDescriptor roleDescriptor : descriptor.getRoleDescriptors() )
    {
      if (roleDescriptor instanceof IDPSSODescriptor || roleDescriptor instanceof SPSSODescriptor)
      {
        providers.add(getSsoProvider(roleDescriptor));
      }
      else
      {
        log.debug("Ignoring unknown metadata descriptor:" + roleDescriptor.getClass().getName());
      }
    }
    return providers;
  }

  protected SsoProvider<?> getSsoProvider(RoleDescriptor descriptor)
  {
    if (descriptor instanceof SPSSODescriptor)
    {
      SPSSODescriptor desc = (SPSSODescriptor)descriptor;
      ServiceProvider provider = new ServiceProvider();
      provider.setId(desc.getID());
      provider.setValidUntil(desc.getValidUntil());
      provider.setCacheDuration(toJavaXmlDuration(desc.getCacheDuration()));
      provider.setProtocolSupportEnumeration(desc.getSupportedProtocols());
      provider.setNameIds(getNameIDs(desc.getNameIDFormats()));
      provider.setArtifactResolutionService(getEndpoints(desc.getArtifactResolutionServices()));
      provider.setSingleLogoutService(getEndpoints(desc.getSingleLogoutServices()));
      provider.setManageNameIDService(getEndpoints(desc.getManageNameIDServices()));
      provider.setAuthnRequestsSigned(desc.isAuthnRequestsSigned());
      provider.setWantAssertionsSigned(desc.getWantAssertionsSigned());
      provider.setAssertionConsumerService(getEndpoints(desc.getAssertionConsumerServices()));
      provider.setRequestedAttributes(getRequestAttributes(desc));
      provider.setSigningKeys(getProviderSigningKeys(descriptor));
      provider.setEncryptionKeys(getProviderEncryptionKeys(descriptor));
      provider.setDiscovery(getDiscovery(desc));
      provider.setRequestInitiation(getRequestInitiation(desc));
      // TODO
      // provider.setAttributeConsumingService(getEndpoints(desc.getAttributeConsumingServices()));
      return provider;
    }
    else if (descriptor instanceof IDPSSODescriptor)
    {
      IDPSSODescriptor desc = (IDPSSODescriptor)descriptor;
      IdentityProvider provider = new IdentityProvider();
      provider.setId(desc.getID());
      provider.setValidUntil(desc.getValidUntil());
      provider.setCacheDuration(toJavaXmlDuration(desc.getCacheDuration()));
      provider.setProtocolSupportEnumeration(desc.getSupportedProtocols());
      provider.setNameIds(getNameIDs(desc.getNameIDFormats()));
      provider.setArtifactResolutionService(getEndpoints(desc.getArtifactResolutionServices()));
      provider.setSingleLogoutService(getEndpoints(desc.getSingleLogoutServices()));
      provider.setManageNameIDService(getEndpoints(desc.getManageNameIDServices()));
      provider.setWantAuthnRequestsSigned(desc.getWantAuthnRequestsSigned());
      provider.setSingleSignOnService(getEndpoints(desc.getSingleSignOnServices()));
      provider.setSigningKeys(getProviderSigningKeys(descriptor));
      provider.setEncryptionKeys(getProviderEncryptionKeys(descriptor));
      provider.setDiscovery(getDiscovery(desc));
      provider.setRequestInitiation(getRequestInitiation(desc));
      return provider;
    }
    else
    {

    }
    throw new UnsupportedOperationException(descriptor == null ? null : descriptor.getClass().getName());
  }

  protected List<Attribute> getRequestAttributes(SPSSODescriptor desc)
  {
    List<Attribute> result = new LinkedList<>();
    if (desc.getDefaultAttributeConsumingService() != null)
    {
      result.addAll(getRequestedAttributes(desc.getDefaultAttributeConsumingService().getRequestedAttributes()));
    }
    else
    {
      for ( AttributeConsumingService s : ofNullable(desc.getAttributeConsumingServices()).orElse(emptyList()) )
      {
        if (s != null)
        {
          // take the first one
          result.addAll(getRequestedAttributes(s.getRequestedAttributes()));
          break;
        }
      }
    }
    return result;
  }

  protected Endpoint getRequestInitiation(RoleDescriptor desc)
  {
    if (desc.getExtensions() == null)
    {
      return null;
    }
    Endpoint result = null;
    for ( XMLObject obj : desc.getExtensions().getUnknownXMLObjects() )
    {
      if (obj instanceof RequestInitiator)
      {
        RequestInitiator req = (RequestInitiator)obj;
        result = new Endpoint().setIndex(0)
                               .setDefault(false)
                               .setBinding(Binding.fromUrn(req.getBinding()))
                               .setLocation(req.getLocation())
                               .setResponseLocation(req.getResponseLocation());
      }
    }
    return result;
  }

  protected Endpoint getDiscovery(RoleDescriptor desc)
  {
    if (desc.getExtensions() == null)
    {
      return null;
    }
    Endpoint result = null;
    for ( XMLObject obj : desc.getExtensions().getUnknownXMLObjects() )
    {
      if (obj instanceof DiscoveryResponse)
      {
        DiscoveryResponse resp = (DiscoveryResponse)obj;
        result = new Endpoint().setDefault(resp.isDefault())
                               .setIndex(resp.getIndex())
                               .setBinding(Binding.fromUrn(resp.getBinding()))
                               .setLocation(resp.getLocation())
                               .setResponseLocation(resp.getResponseLocation());
      }
    }
    return result;
  }

  protected List<SigningKey> getProviderSigningKeys(RoleDescriptor descriptor)
  {
    List<SigningKey> result = new LinkedList<>();
    for ( KeyDescriptor desc : ofNullable(descriptor.getKeyDescriptors()).orElse(emptyList()) )
    {
      if (desc != null)
      {
        result.addAll(getSigningKeyFromDescriptor(desc));
      }
    }
    return result;
  }

  protected List<SigningKey> getSigningKeyFromDescriptor(KeyDescriptor desc)
  {
    List<SigningKey> result = new LinkedList<>();
    if (desc.getKeyInfo() == null)
    {
      return result;
    }
    UsageType type = desc.getUse() == null ? UsageType.SIGNING : desc.getUse();
    if (UsageType.SIGNING.equals(type) || UsageType.UNSPECIFIED.equals(type))
    {
      int index = 0;
      for ( X509Data x509 : ofNullable(desc.getKeyInfo().getX509Datas()).orElse(emptyList()) )
      {
        for ( X509Certificate cert : ofNullable(x509.getX509Certificates()).orElse(emptyList()) )
        {
          result.add(new SigningKey(type.getValue() + "-" + index++, cert.getValue()));
        }
      }
    }

    return result;
  }

  protected List<EncryptionKey> getProviderEncryptionKeys(RoleDescriptor descriptor)
  {
    List<EncryptionKey> result = new LinkedList<>();
    for ( KeyDescriptor desc : ofNullable(descriptor.getKeyDescriptors()).orElse(emptyList()) )
    {
      if (desc != null)
      {
        result.addAll(getEncryptionKeyFromDescriptor(desc));
      }
    }
    return result;
  }

  protected List<EncryptionKey> getEncryptionKeyFromDescriptor(KeyDescriptor desc)
  {
    List<EncryptionKey> result = new LinkedList<>();
    if (desc.getKeyInfo() == null)
    {
      return result;
    }
    UsageType type = desc.getUse() == null ? UsageType.ENCRYPTION : desc.getUse();
    if (UsageType.ENCRYPTION.equals(type) || UsageType.UNSPECIFIED.equals(type))
    {
      int index = 0;
      for ( X509Data x509 : ofNullable(desc.getKeyInfo().getX509Datas()).orElse(emptyList()) )
      {
        for ( X509Certificate cert : ofNullable(x509.getX509Certificates()).orElse(emptyList()) )
        {
          EncryptionKey encryptionKey = new EncryptionKey(type.getValue() + "-" + index++, cert.getValue());
          EncryptionMethod encryptionMethod = desc.getEncryptionMethods().isEmpty() ? null
            : desc.getEncryptionMethods().get(0);
          if (encryptionMethod != null)
          {
            DataEncryptionMethod dataEncryptionMethod;
            if (encryptionMethod.getKeySize() == null)
            {
              dataEncryptionMethod = DataEncryptionMethod.fromUrn(encryptionMethod.getAlgorithm());
            }
            else
            {
              dataEncryptionMethod = DataEncryptionMethod.fromUrn(encryptionMethod.getAlgorithm(),
                                                                  encryptionMethod.getKeySize().getValue());
            }
            encryptionKey.setDataEncryptionMethod(dataEncryptionMethod);
          }
          result.add(encryptionKey);
        }
      }
    }

    return result;
  }

  protected List<Endpoint> getEndpoints(List<? extends org.opensaml.saml.saml2.metadata.Endpoint> services)
  {
    List<Endpoint> result = new LinkedList<>();
    if (services != null)
    {
      services.stream().forEach(s -> {
        Endpoint endpoint = new Endpoint().setBinding(Binding.fromUrn(s.getBinding()))
                                          .setLocation(s.getLocation())
                                          .setResponseLocation(s.getResponseLocation());
        result.add(endpoint);
        if (s instanceof IndexedEndpoint)
        {
          IndexedEndpoint idxEndpoint = (IndexedEndpoint)s;
          endpoint.setIndex(idxEndpoint.getIndex()).setDefault(idxEndpoint.isDefault());
        }
      });
    }
    return result;
  }

  protected List<NameId> getNameIDs(List<NameIDFormat> nameIDFormats)
  {
    List<NameId> result = new LinkedList<>();
    if (nameIDFormats != null)
    {
      nameIDFormats.stream().forEach(n -> result.add(NameId.fromUrn(n.getURI())));
    }
    return result;
  }

  protected org.opensaml.saml.saml2.core.Response internalToXml(Response response)
  {
    org.opensaml.saml.saml2.core.Response result = buildSAMLObject(org.opensaml.saml.saml2.core.Response.class);
    result.setConsent(response.getConsent());
    result.setID(ofNullable(response.getId()).orElse("RP" + UUID.randomUUID().toString()));
    result.setInResponseTo(response.getInResponseTo());
    result.setVersion(SAMLVersion.VERSION_20);
    result.setIssueInstant(response.getIssueInstant());
    result.setDestination(response.getDestination());

    if (response.getIssuer() != null)
    {
      result.setIssuer(toIssuer(response.getIssuer()));
    }

    if (response.getStatus() == null || response.getStatus().getCode() == null)
    {
      throw new SamlException("Status cannot be null on a response");
    }
    Status status = response.getStatus();
    result.setStatus(buildStatus(status.getCode(), status.getMinorCode(), status.getMessage(), status.getDetail()));

    for ( Assertion a : ofNullable(response.getAssertions()).orElse(emptyList()) )
    {
      org.opensaml.saml.saml2.core.Assertion osAssertion = internalToXml(a);
      if (a.getEncryptionKey() != null)
      {
        EncryptedAssertion encryptedAssertion = encryptAssertion(osAssertion,
                                                                 a.getEncryptionKey(),
                                                                 a.getKeyAlgorithm(),
                                                                 a.getDataAlgorithm());
        result.getEncryptedAssertions().add(encryptedAssertion);
      }
      else
      {
        result.getAssertions().add(osAssertion);
      }
    }
    if (response.getSigningKey() != null)
    {
      signObject(result, response.getSigningKey(), response.getAlgorithm(), response.getDigest());
    }
    return result;
  }

  private org.opensaml.saml.saml2.core.Status buildStatus(StatusCode major,
                                                          StatusCode minor,
                                                          String message,
                                                          String detail)
  {
    org.opensaml.saml.saml2.core.Status result = new StatusBuilder().buildObject();
    org.opensaml.saml.saml2.core.StatusCode code = new StatusCodeBuilder().buildObject();
    code.setValue(major.toString());
    result.setStatusCode(code);

    if (minor != null)
    {
      org.opensaml.saml.saml2.core.StatusCode sc = new StatusCodeBuilder().buildObject();
      sc.setValue(minor.toString());
      code.setStatusCode(sc);
    }

    if (!ObjectUtils.isEmpty(message))
    {
      StatusMessage sm = new StatusMessageBuilder().buildObject();
      sm.setValue(message);
      result.setStatusMessage(sm);
    }

    return result;
  }

  protected <M extends Metadata<M>> EntityDescriptor internalToXml(M metadata)
  {
    EntityDescriptor desc = getEntityDescriptor();
    desc.setEntityID(metadata.getEntityId());
    if (hasText(metadata.getId()))
    {
      desc.setID(metadata.getId());
    }
    else
    {
      desc.setID("M" + UUID.randomUUID().toString());
    }
    List<RoleDescriptor> descriptors = getRoleDescriptors(metadata);
    desc.getRoleDescriptors().addAll(descriptors);
    Organization organization = getOrganizationDescriptor(metadata);
    if (organization != null)
    {
      desc.setOrganization(organization);
    }
    if (metadata.getSigningKey() != null)
    {
      signObject(desc, metadata.getSigningKey(), metadata.getAlgorithm(), metadata.getDigest());
    }
    return desc;
  }

  protected <M extends Metadata<M>> Organization getOrganizationDescriptor(M metadata)
  {
    Organization organization = buildSAMLObject(Organization.class);
    String value = metadata.getOrganizationName();
    if (hasText(value))
    {
      OrganizationName organizationName = buildSAMLObject(OrganizationName.class);
      organizationName.setValue(value);
      organizationName.setXMLLang(metadata.getOrganizationNameLang());
      organization.getOrganizationNames().add(organizationName);
    }
    value = metadata.getOrganizationDisplayName();
    if (hasText(value))
    {
      OrganizationDisplayName organizationDisplayName = buildSAMLObject(OrganizationDisplayName.class);
      organizationDisplayName.setValue(value);
      organizationDisplayName.setXMLLang(metadata.getOrganizationDisplayNameLang());
      organization.getDisplayNames().add(organizationDisplayName);
    }
    value = metadata.getOrganizationURL();
    if (hasText(value))
    {
      OrganizationURL organizationURL = buildSAMLObject(OrganizationURL.class);
      organizationURL.setURI(value);
      organizationURL.setXMLLang(metadata.getOrganizationURLLang());
      organization.getURLs().add(organizationURL);
    }
    return organization;
  }

  protected <M extends Metadata<M>> List<RoleDescriptor> getRoleDescriptors(M metadata)
  {
    List<RoleDescriptor> result = new LinkedList<>();
    for ( SsoProvider<? extends SsoProvider> p : metadata.getSsoProviders() )
    {
      RoleDescriptor roleDescriptor = null;
      if (p instanceof ServiceProvider)
      {
        roleDescriptor = getServiceProviderRoleDescriptor((ServiceProvider)p);
      }
      else if (p instanceof IdentityProvider)
      {
        roleDescriptor = getIdentityProviderRoleDescriptor((IdentityProvider)p);
      }

      roleDescriptor.setCacheDuration(toJavaTimeDuration(p.getCacheDuration()));
      roleDescriptor.setValidUntil(p.getValidUntil());
      roleDescriptor.addSupportedProtocol(NS_PROTOCOL);
      roleDescriptor.setID(ofNullable(p.getId()).orElse("RD" + UUID.randomUUID()));

      for ( SigningKey key : p.getSigningKeys() )
      {
        roleDescriptor.getKeyDescriptors().add(getKeyDescriptor(key));
      }
      for ( EncryptionKey key : p.getEncryptionKeys() )
      {
        roleDescriptor.getKeyDescriptors().add(getKeyDescriptor(key));
      }

      // md:extensions
      Endpoint requestInitiation = p.getRequestInitiation();
      Endpoint discovery = p.getDiscovery();
      if (requestInitiation != null || discovery != null)
      {
        ExtensionsBuilder extensionsBuilder = (ExtensionsBuilder)getBuilderFactory().getBuilder(Extensions.DEFAULT_ELEMENT_NAME);
        roleDescriptor.setExtensions(extensionsBuilder.buildObject());

        if (requestInitiation != null)
        {
          RequestInitiatorBuilder builder = (RequestInitiatorBuilder)getBuilderFactory().getBuilder(RequestInitiator.DEFAULT_ELEMENT_NAME);
          RequestInitiator init = builder.buildObject();
          init.setBinding(requestInitiation.getBinding().toString());
          init.setLocation(requestInitiation.getLocation());
          init.setResponseLocation(requestInitiation.getResponseLocation());
          roleDescriptor.getExtensions().getUnknownXMLObjects().add(init);
        }
        if (discovery != null)
        {
          DiscoveryResponseBuilder builder = (DiscoveryResponseBuilder)getBuilderFactory().getBuilder(DiscoveryResponse.DEFAULT_ELEMENT_NAME);
          DiscoveryResponse response = builder.buildObject(DiscoveryResponse.DEFAULT_ELEMENT_NAME);
          response.setBinding(discovery.getBinding().toString());
          response.setLocation(discovery.getLocation());
          response.setResponseLocation(discovery.getResponseLocation());
          response.setIsDefault(discovery.isDefault());
          response.setIndex(discovery.getIndex());
          roleDescriptor.getExtensions().getUnknownXMLObjects().add(response);
        }
      }
      result.add(roleDescriptor);
    }
    return result;
  }

  protected SPSSODescriptor getServiceProviderRoleDescriptor(ServiceProvider sp)
  {
    SPSSODescriptor descriptor = getSPSSODescriptor();
    descriptor.setAuthnRequestsSigned(sp.isAuthnRequestsSigned());
    descriptor.setWantAssertionsSigned(sp.isWantAssertionsSigned());

    for ( NameId id : sp.getNameIds() )
    {
      descriptor.getNameIDFormats().add(getNameIDFormat(id));
    }

    for ( int i = 0 ; i < sp.getAssertionConsumerService().size() ; i++ )
    {
      Endpoint ep = sp.getAssertionConsumerService().get(i);
      descriptor.getAssertionConsumerServices().add(getAssertionConsumerService(ep, i));
    }
    for ( int i = 0 ; i < sp.getArtifactResolutionService().size() ; i++ )
    {
      Endpoint ep = sp.getArtifactResolutionService().get(i);
      descriptor.getArtifactResolutionServices().add(getArtifactResolutionService(ep, i));
    }
    for ( Endpoint ep : sp.getSingleLogoutService() )
    {
      descriptor.getSingleLogoutServices().add(getSingleLogoutService(ep));
    }
    for ( Endpoint e : sp.getManageNameIDService() )
    {
      descriptor.getManageNameIDServices().add(getManageNameIDService(e));
    }
    if (sp.getRequestedAttributes() != null && !sp.getRequestedAttributes().isEmpty())
    {
      descriptor.getAttributeConsumingServices().add(getAttributeConsumingService(sp.getRequestedAttributes()));
    }
    return descriptor;
  }

  protected IDPSSODescriptor getIdentityProviderRoleDescriptor(IdentityProvider idp)
  {
    IDPSSODescriptor descriptor = getIDPSSODescriptor();
    descriptor.setWantAuthnRequestsSigned(idp.getWantAuthnRequestsSigned());
    for ( NameId id : idp.getNameIds() )
    {
      descriptor.getNameIDFormats().add(getNameIDFormat(id));
    }
    for ( int i = 0 ; i < idp.getSingleSignOnService().size() ; i++ )
    {
      Endpoint ep = idp.getSingleSignOnService().get(i);
      descriptor.getSingleSignOnServices().add(getSingleSignOnService(ep, i));
    }
    for ( Endpoint ep : idp.getSingleLogoutService() )
    {
      descriptor.getSingleLogoutServices().add(getSingleLogoutService(ep));
    }
    for ( int i = 0 ; i < idp.getArtifactResolutionService().size() ; i++ )
    {
      Endpoint ep = idp.getArtifactResolutionService().get(i);
      descriptor.getArtifactResolutionServices().add(getArtifactResolutionService(ep, i));
    }
    if (idp.getAttribute() != null)
    {
      for ( Attribute attribute : idp.getAttribute() )
      {
        descriptor.getAttributes().add(convertAttributeToOpensamlAttribute(attribute));
      }
    }
    return descriptor;
  }

  protected org.opensaml.saml.saml2.core.Attribute convertAttributeToOpensamlAttribute(Attribute a)
  {
    org.opensaml.saml.saml2.core.Attribute attribute = buildSAMLObject(org.opensaml.saml.saml2.core.Attribute.class);
    attribute.setFriendlyName(a.getFriendlyName());
    attribute.setName(a.getName());
    if (a.getNameFormat() != null)
    {
      attribute.setNameFormat(a.getNameFormat().toString());
    }
    a.getValues().stream().forEach(av -> attribute.getAttributeValues().add(objectToXmlObject(av)));
    return attribute;
  }

  protected AttributeConsumingService getAttributeConsumingService(List<Attribute> attributes)
  {

    AttributeConsumingService service = buildSAMLObject(AttributeConsumingService.class);
    service.setIsDefault(true);
    service.setIndex(0);
    List<RequestedAttribute> attrs = new LinkedList<>();
    for ( Attribute a : attributes )
    {
      RequestedAttribute ra = buildSAMLObject(RequestedAttribute.class);
      ra.setIsRequired(a.isRequired());
      ra.setFriendlyName(a.getFriendlyName());
      ra.setName(a.getName());
      ra.setNameFormat(a.getNameFormat().toString());
      attrs.add(ra);
    }
    service.getRequestedAttributes().addAll(attrs);
    return service;
  }

  protected ArtifactResolutionService getArtifactResolutionService(Endpoint ep, int i)
  {
    ArtifactResolutionService service = buildSAMLObject(ArtifactResolutionService.class);
    service.setLocation(ep.getLocation());
    service.setBinding(ep.getBinding().toString());
    service.setIndex(i);
    service.setIsDefault(ep.isDefault());
    service.setResponseLocation(ep.getResponseLocation());
    return service;
  }

  protected ManageNameIDService getManageNameIDService(Endpoint ep)
  {
    ManageNameIDService service = buildSAMLObject(ManageNameIDService.class);
    service.setLocation(ep.getLocation());
    service.setBinding(ep.getBinding().toString());
    service.setResponseLocation(ep.getResponseLocation());
    return service;
  }

  protected org.opensaml.saml.saml2.core.LogoutResponse internalToXml(LogoutResponse response)
  {
    org.opensaml.saml.saml2.core.LogoutResponse result = buildSAMLObject(org.opensaml.saml.saml2.core.LogoutResponse.class);
    result.setInResponseTo(response.getInResponseTo());
    result.setID(response.getId());
    result.setIssueInstant(response.getIssueInstant());
    result.setDestination(response.getDestination());

    org.opensaml.saml.saml2.core.Issuer issuer = buildSAMLObject(org.opensaml.saml.saml2.core.Issuer.class);
    issuer.setValue(response.getIssuer().getValue());
    issuer.setNameQualifier(response.getIssuer().getNameQualifier());
    issuer.setSPNameQualifier(response.getIssuer().getSpNameQualifier());
    result.setIssuer(issuer);

    org.opensaml.saml.saml2.core.Status status = buildSAMLObject(org.opensaml.saml.saml2.core.Status.class);
    org.opensaml.saml.saml2.core.StatusCode code = buildSAMLObject(org.opensaml.saml.saml2.core.StatusCode.class);
    code.setValue(response.getStatus().getCode().toString());
    status.setStatusCode(code);
    if (hasText(response.getStatus().getMessage()))
    {
      StatusMessage message = buildSAMLObject(StatusMessage.class);
      message.setValue(response.getStatus().getMessage());
      status.setStatusMessage(message);
    }
    result.setStatus(status);

    if (response.getSigningKey() != null)
    {
      signObject(result, response.getSigningKey(), response.getAlgorithm(), response.getDigest());
    }

    return result;
  }

  protected org.opensaml.saml.saml2.core.LogoutRequest internalToXml(LogoutRequest request)
  {
    org.opensaml.saml.saml2.core.LogoutRequest lr = buildSAMLObject(org.opensaml.saml.saml2.core.LogoutRequest.class);
    lr.setDestination(request.getDestination().getLocation());
    lr.setID(request.getId());
    lr.setVersion(SAMLVersion.VERSION_20);

    org.opensaml.saml.saml2.core.Issuer issuer = buildSAMLObject(org.opensaml.saml.saml2.core.Issuer.class);
    issuer.setValue(request.getIssuer().getValue());
    issuer.setNameQualifier(request.getIssuer().getNameQualifier());
    issuer.setSPNameQualifier(request.getIssuer().getSpNameQualifier());
    lr.setIssuer(issuer);
    lr.setIssueInstant(request.getIssueInstant());

    lr.setNotOnOrAfter(request.getNotOnOrAfter());
    NameID nameID = buildSAMLObject(NameID.class);
    nameID.setFormat(request.getNameId().getFormat().toString());
    nameID.setValue(request.getNameId().getValue());
    nameID.setSPNameQualifier(request.getNameId().getSpNameQualifier());
    nameID.setNameQualifier(request.getNameId().getNameQualifier());
    lr.setNameID(nameID);
    if (request.getSigningKey() != null)
    {
      signObject(lr, request.getSigningKey(), request.getAlgorithm(), request.getDigest());
    }
    return lr;
  }

  protected org.opensaml.saml.saml2.core.ManageNameIDResponse internalToXml(ManageNameIDResponse response)
  {
    org.opensaml.saml.saml2.core.ManageNameIDResponse result = buildSAMLObject(org.opensaml.saml.saml2.core.ManageNameIDResponse.class);
    result.setDestination(response.getDestination());
    result.setID(response.getId());
    result.setVersion(SAMLVersion.VERSION_20);
    result.setIssueInstant(response.getIssueInstant());
    result.setInResponseTo(response.getInResponseTo());

    result.setIssuer(toIssuer(response.getIssuer()));

    Status status = response.getStatus();
    if (status != null)
    {
      result.setStatus(buildStatus(status.getCode(), status.getMinorCode(), status.getMessage(), status.getDetail()));
    }

    if (response.getSigningKey() != null)
    {
      signObject(result, response.getSigningKey(), response.getAlgorithm(), response.getDigest());
    }
    return result;
  }

  protected org.opensaml.saml.saml2.core.ManageNameIDRequest internalToXml(ManageNameIDRequest request)
  {
    org.opensaml.saml.saml2.core.ManageNameIDRequest result = buildSAMLObject(org.opensaml.saml.saml2.core.ManageNameIDRequest.class);

    Endpoint destination = request.getDestination();
    result.setDestination(destination == null ? null : destination.getLocation());
    result.setID(request.getId());
    result.setVersion(SAMLVersion.VERSION_20);
    result.setIssueInstant(request.getIssueInstant());

    result.setIssuer(toIssuer(request.getIssuer()));

    if (request.getNameId() != null)
    {
      NameID nameID = buildSAMLObject(NameID.class);
      nameID.setFormat(request.getNameId().getFormat() == null ? null : request.getNameId().getFormat().toString());
      nameID.setValue(request.getNameId().getValue());
      nameID.setSPNameQualifier(request.getNameId().getSpNameQualifier());
      nameID.setNameQualifier(request.getNameId().getNameQualifier());
      result.setNameID(nameID);
    }

    if (request.getSigningKey() != null)
    {
      signObject(result, request.getSigningKey(), request.getAlgorithm(), request.getDigest());
    }
    return result;
  }

  protected org.opensaml.saml.saml2.core.Assertion internalToXml(Assertion request)
  {
    org.opensaml.saml.saml2.core.Assertion a = buildSAMLObject(org.opensaml.saml.saml2.core.Assertion.class);
    a.setVersion(SAMLVersion.VERSION_20);
    a.setIssueInstant(request.getIssueInstant());
    a.setID(request.getId());
    org.opensaml.saml.saml2.core.Issuer issuer = buildSAMLObject(org.opensaml.saml.saml2.core.Issuer.class);
    issuer.setValue(request.getIssuer().getValue());
    a.setIssuer(issuer);

    NameIdPrincipal principal = request.getSubject().getPrincipal();

    NameID nid = buildSAMLObject(NameID.class);
    nid.setValue(principal.getValue());
    nid.setFormat(principal.getFormat().toString());
    nid.setSPNameQualifier(principal.getSpNameQualifier());

    org.opensaml.saml.saml2.core.SubjectConfirmationData confData = buildSAMLObject(org.opensaml.saml.saml2.core.SubjectConfirmationData.class);
    confData.setInResponseTo(request.getSubject().getConfirmations().get(0).getConfirmationData().getInResponseTo());
    confData.setNotBefore(request.getSubject().getConfirmations().get(0).getConfirmationData().getNotBefore());
    confData.setNotOnOrAfter(request.getSubject().getConfirmations().get(0).getConfirmationData().getNotOnOrAfter());
    confData.setRecipient(request.getSubject().getConfirmations().get(0).getConfirmationData().getRecipient());

    org.opensaml.saml.saml2.core.SubjectConfirmation confirmation = buildSAMLObject(org.opensaml.saml.saml2.core.SubjectConfirmation.class);
    confirmation.setMethod(request.getSubject().getConfirmations().get(0).getMethod().toString());
    confirmation.setSubjectConfirmationData(confData);

    org.opensaml.saml.saml2.core.Subject subject = buildSAMLObject(org.opensaml.saml.saml2.core.Subject.class);
    a.setSubject(subject);
    subject.setNameID(nid);
    subject.getSubjectConfirmations().add(confirmation);

    if (request.getConditions() != null)
    {
      org.opensaml.saml.saml2.core.Conditions conditions = buildSAMLObject(org.opensaml.saml.saml2.core.Conditions.class);
      conditions.setNotBefore(request.getConditions().getNotBefore());
      conditions.setNotOnOrAfter(request.getConditions().getNotOnOrAfter());
      a.setConditions(conditions);

      request.getConditions().getCriteria().forEach(c -> addCondition(conditions, c));
    }

    for ( AuthenticationStatement stmt : request.getAuthenticationStatements() )
    {
      org.opensaml.saml.saml2.core.AuthnStatement authnStatement = buildSAMLObject(org.opensaml.saml.saml2.core.AuthnStatement.class);
      org.opensaml.saml.saml2.core.AuthnContext actx = buildSAMLObject(org.opensaml.saml.saml2.core.AuthnContext.class);
      org.opensaml.saml.saml2.core.AuthnContextClassRef aref = buildSAMLObject(org.opensaml.saml.saml2.core.AuthnContextClassRef.class);
      AuthenticationContext authenticationContext = stmt.getAuthenticationContext();
      aref.setURI(authenticationContext.getClassReference().toString());
      actx.setAuthnContextClassRef(aref);
      if (!CollectionUtils.isEmpty(authenticationContext.getAuthenticatingAuthorities()))
      {
        actx.getAuthenticatingAuthorities()
            .addAll(authenticationContext.getAuthenticatingAuthorities().stream().map(uri -> {
              AuthenticatingAuthority authenticatingAuthority = buildSAMLObject(AuthenticatingAuthority.class);
              authenticatingAuthority.setURI(uri);
              return authenticatingAuthority;
            }).collect(Collectors.toList()));
      }
      authnStatement.setAuthnContext(actx);
      a.getAuthnStatements().add(authnStatement);
      authnStatement.setSessionIndex(stmt.getSessionIndex());
      authnStatement.setSessionNotOnOrAfter(stmt.getSessionNotOnOrAfter());
      authnStatement.setAuthnInstant(stmt.getAuthInstant());
    }

    org.opensaml.saml.saml2.core.AttributeStatement astmt = buildSAMLObject(org.opensaml.saml.saml2.core.AttributeStatement.class);
    for ( Attribute attr : request.getAttributes() )
    {
      org.opensaml.saml.saml2.core.Attribute attribute = buildSAMLObject(org.opensaml.saml.saml2.core.Attribute.class);
      attribute.setName(attr.getName());
      attribute.setFriendlyName(attr.getFriendlyName());
      attribute.setNameFormat(attr.getNameFormat().toString());
      attr.getValues().stream().forEach(av -> attribute.getAttributeValues().add(objectToXmlObject(av)));
      astmt.getAttributes().add(attribute);
    }
    a.getAttributeStatements().add(astmt);

    if (request.getSigningKey() != null)
    {
      signObject(a, request.getSigningKey(), request.getAlgorithm(), request.getDigest());
    }

    return a;
  }

  protected void addCondition(org.opensaml.saml.saml2.core.Conditions conditions, AssertionCondition<?, ?> c)
  {
    if (c instanceof AudienceRestriction)
    {
      org.opensaml.saml.saml2.core.AudienceRestriction ar = buildSAMLObject(org.opensaml.saml.saml2.core.AudienceRestriction.class);
      for ( String audience : ((AudienceRestriction)c).getAudiences() )
      {
        Audience aud = buildSAMLObject(Audience.class);
        aud.setURI(audience);
        ar.getAudiences().add(aud);
      }
      conditions.getAudienceRestrictions().add(ar);
    }
    else if (c instanceof OneTimeUse)
    {
      org.opensaml.saml.saml2.core.OneTimeUse otu = buildSAMLObject(org.opensaml.saml.saml2.core.OneTimeUse.class);
      conditions.getConditions().add(otu);
    }
  }

  protected AuthnRequest internalToXml(AuthenticationRequest request)
  {
    AuthnRequest auth = buildSAMLObject(AuthnRequest.class);
    auth.setID(request.getId());
    auth.setVersion(SAMLVersion.VERSION_20);
    auth.setIssueInstant(request.getIssueInstant());
    auth.setForceAuthn(request.isForceAuth());
    auth.setIsPassive(request.isPassive());
    auth.setProtocolBinding(request.getBinding().toString());
    // Azure AD as IdP will not accept index if protocol binding or AssertationCustomerServiceURL is set.
    // auth.setAssertionConsumerServiceIndex(request.getAssertionConsumerService().getIndex());
    auth.setAssertionConsumerServiceURL(request.getAssertionConsumerService().getLocation());
    auth.setDestination(request.getDestination().getLocation());
    auth.setNameIDPolicy(getNameIDPolicy(request.getNameIdPolicy()));
    auth.setRequestedAuthnContext(getRequestedAuthenticationContext(request));
    auth.setIssuer(toIssuer(request.getIssuer()));
    auth.setScoping(getScoping(request.getScoping()));
    if (!CollectionUtils.isEmpty(request.getExtensions()))
    {
      org.opensaml.saml.saml2.core.Extensions extensions = buildSAMLObject(org.opensaml.saml.saml2.core.Extensions.class);
      extensions.getUnknownXMLObjects()
                .addAll(request.getExtensions()
                               .stream()
                               .filter(XMLObject.class::isInstance)
                               .map(XMLObject.class::cast)
                               .collect(Collectors.toList()));
      auth.setExtensions(extensions);
    }
    if (request.getSigningKey() != null)
    {
      signObject(auth, request.getSigningKey(), request.getAlgorithm(), request.getDigest());
    }
    return auth;
  }

  protected String marshallToXml(XMLObject auth)
  {
    Element element = marshall(auth);
    return SerializeSupport.nodeToString(element);
  }

  protected Element marshall(XMLObject auth)
  {
    try
    {
      return getMarshallerFactory().getMarshaller(auth).marshall(auth);
    }
    catch (MarshallingException e)
    {
      throw new SamlException(e);
    }
  }

  protected RequestedAuthnContext getRequestedAuthenticationContext(AuthenticationRequest request)
  {
    RequestedAuthnContext result = null;
    if (request.getRequestedAuthenticationContext() != null)
    {
      result = buildSAMLObject(RequestedAuthnContext.class);
      switch (request.getRequestedAuthenticationContext())
      {
        case exact:
          result.setComparison(EXACT);
          break;
        case better:
          result.setComparison(AuthnContextComparisonTypeEnumeration.BETTER);
          break;
        case maximum:
          result.setComparison(AuthnContextComparisonTypeEnumeration.MAXIMUM);
          break;
        case minimum:
          result.setComparison(AuthnContextComparisonTypeEnumeration.MINIMUM);
          break;
        default:
          result.setComparison(EXACT);
          break;
      }
      if (request.getAuthenticationContextClassReferences() != null)
      {
        List<AuthnContextClassRef> authnContextClassRefs = request.getAuthenticationContextClassReferences()
                                                                  .stream()
                                                                  .map(authenticationContextClassReference -> {
                                                                    AuthnContextClassRef authnContextClassRef = buildSAMLObject(AuthnContextClassRef.class);
                                                                    authnContextClassRef.setURI(authenticationContextClassReference.getValue());
                                                                    return authnContextClassRef;
                                                                  })
                                                                  .collect(Collectors.toList());
        result.getAuthnContextClassRefs().addAll(authnContextClassRefs);
      }
    }
    return result;
  }

  protected NameIDPolicy getNameIDPolicy(NameIdPolicy<?> nameIdPolicy)
  {
    NameIDPolicy result = null;
    if (nameIdPolicy != null)
    {
      result = buildSAMLObject(NameIDPolicy.class);
      result.setAllowCreate(nameIdPolicy.getAllowCreate());
      result.setFormat(nameIdPolicy.getFormat().toString());
      result.setSPNameQualifier(nameIdPolicy.getSpNameQualifier());
    }
    return result;
  }

  protected NameIdPolicy<?> fromNameIDPolicy(NameIDPolicy nameIDPolicy)
  {
    NameIdPolicy<?> result = null;
    if (nameIDPolicy != null)
    {
      result = new NameIdPolicy<>().setAllowCreate(nameIDPolicy.getAllowCreate())
                                   .setFormat(NameId.fromUrn(nameIDPolicy.getFormat()))
                                   .setSpNameQualifier(nameIDPolicy.getSPNameQualifier());
    }
    return result;
  }

  protected org.opensaml.saml.saml2.core.Scoping getScoping(Scoping saml2Scoping)
  {
    org.opensaml.saml.saml2.core.Scoping scoping = null;
    if (saml2Scoping != null)
    {
      scoping = buildSAMLObject(org.opensaml.saml.saml2.core.Scoping.class);
      List<String> idpListValues = saml2Scoping.getIdpList();
      if (!CollectionUtils.isEmpty(idpListValues))
      {
        IDPList idpList = buildSAMLObject(IDPList.class);
        List<IDPEntry> idpEntries = idpListValues.stream().map(idpId -> {
          IDPEntry idpEntry = buildSAMLObject(IDPEntry.class);
          idpEntry.setProviderID(idpId);
          return idpEntry;
        }).collect(Collectors.toList());
        idpList.getIDPEntrys().addAll(idpEntries);
        scoping.setIDPList(idpList);
      }
      scoping.setProxyCount(saml2Scoping.getProxyCount());
      List<String> requesterIDs = saml2Scoping.getRequesterIds();
      if (!CollectionUtils.isEmpty(requesterIDs))
      {
        List<RequesterID> requesterIDList = requesterIDs.stream().map(id -> {
          RequesterID requesterID = buildSAMLObject(RequesterID.class);
          requesterID.setURI(id);
          return requesterID;
        }).collect(Collectors.toList());
        scoping.getRequesterIDs().addAll(requesterIDList);
      }
    }
    return scoping;
  }

  protected Scoping fromScoping(org.opensaml.saml.saml2.core.Scoping scoping)
  {
    Scoping result = null;
    if (scoping != null)
    {
      IDPList idpList = scoping.getIDPList();
      List<RequesterID> requesterIDs = scoping.getRequesterIDs();
      result = new Scoping(idpList != null
        ? idpList.getIDPEntrys().stream().map(IDPEntry::getProviderID).collect(Collectors.toList())
        : Collections.emptyList(),
                           requesterIDs != null
                             ? requesterIDs.stream().map(RequesterID::getURI).collect(Collectors.toList())
                             : Collections.emptyList(),
                           scoping.getProxyCount());
    }
    return result;
  }

  protected Response resolveResponse(org.opensaml.saml.saml2.core.Response parsed,
                                     List<SigningKey> verificationKeys,
                                     List<EncryptionKey> localKeys)
  {
    Response result = new Response().setConsent(parsed.getConsent())
                                    .setDestination(parsed.getDestination())
                                    .setId(parsed.getID())
                                    .setInResponseTo(parsed.getInResponseTo())
                                    .setIssueInstant(parsed.getIssueInstant())
                                    .setIssuer(getIssuer(parsed.getIssuer()))
                                    .setVersion(parsed.getVersion().toString())
                                    .setStatus(getStatus(parsed.getStatus()))
                                    .setAssertions(parsed.getAssertions()
                                                         .stream()
                                                         .map(a -> resolveAssertion(a, verificationKeys, localKeys))
                                                         .collect(Collectors.toList()));
    if (parsed.getEncryptedAssertions() != null && !parsed.getEncryptedAssertions().isEmpty())
    {
      parsed.getEncryptedAssertions()
            .stream()
            .forEach(a -> result.addAssertion(resolveAssertion((org.opensaml.saml.saml2.core.Assertion)decrypt(a,
                                                                                                               localKeys),
                                                               verificationKeys,
                                                               localKeys)));
    }

    return result;

  }

  protected LogoutResponse resolveLogoutResponse(org.opensaml.saml.saml2.core.LogoutResponse response,
                                                 List<SigningKey> verificationKeys,
                                                 List<EncryptionKey> localKeys)
  {
    return new LogoutResponse().setId(response.getID())
                               .setInResponseTo(response.getInResponseTo())
                               .setConsent(response.getConsent())
                               .setVersion(response.getVersion().toString())
                               .setIssueInstant(response.getIssueInstant())
                               .setIssuer(getIssuer(response.getIssuer()))
                               .setDestination(response.getDestination())
                               .setStatus(getStatus(response.getStatus()));
  }

  protected LogoutRequest resolveLogoutRequest(org.opensaml.saml.saml2.core.LogoutRequest request,
                                               List<SigningKey> verificationKeys,
                                               List<EncryptionKey> localKeys)
  {
    LogoutRequest result = new LogoutRequest().setId(request.getID())
                                              .setConsent(request.getConsent())
                                              .setVersion(request.getVersion().toString())
                                              .setNotOnOrAfter(request.getNotOnOrAfter())
                                              .setIssueInstant(request.getIssueInstant())
                                              .setReason(LogoutReason.fromUrn(request.getReason()))
                                              .setIssuer(getIssuer(request.getIssuer()))
                                              .setDestination(new Endpoint().setLocation(request.getDestination()));
    NameID nameID = getNameID(request.getNameID(), request.getEncryptedID(), localKeys);
    result.setNameId(getNameIdPrincipal(nameID));
    return result;
  }

  protected ManageNameIDResponse resolveManageNameIDResponse(org.opensaml.saml.saml2.core.ManageNameIDResponse response)
  {
    ManageNameIDResponse result = new ManageNameIDResponse();
    result.setId(response.getID());
    result.setInResponseTo(response.getInResponseTo());
    result.setVersion(response.getVersion().toString());
    result.setIssueInstant(response.getIssueInstant());
    result.setDestination(response.getDestination());

    result.setIssuer(getIssuer(response.getIssuer()));
    result.setStatus(getStatus(response.getStatus()));
    return result;
  }

  protected ManageNameIDRequest resolveManageNameIDRequest(org.opensaml.saml.saml2.core.ManageNameIDRequest request,
                                                           List<EncryptionKey> localKeys)
  {
    ManageNameIDRequest result = new ManageNameIDRequest();
    result.setId(request.getID());
    result.setVersion(request.getVersion().toString());
    result.setIssueInstant(request.getIssueInstant());

    result.setDestination(new Endpoint().setLocation(request.getDestination()));
    result.setIssuer(getIssuer(request.getIssuer()));

    NameID nameID = getNameID(request.getNameID(), request.getEncryptedID(), localKeys);
    result.setNameId(getNameIdPrincipal(nameID));

    return result;
  }

  protected Status getStatus(org.opensaml.saml.saml2.core.Status status)
  {
    return new Status().setCode(StatusCode.fromUrn(status.getStatusCode().getValue()))
                       .setMinorCode(status.getStatusCode().getStatusCode() == null ? null
                         : StatusCode.fromUrn(status.getStatusCode().getStatusCode().getValue()))
                       .setMessage(status.getStatusMessage() != null ? status.getStatusMessage().getValue() : null);
  }

  protected Assertion resolveAssertion(org.opensaml.saml.saml2.core.Assertion parsed,
                                       List<SigningKey> verificationKeys,
                                       List<EncryptionKey> localKeys)
  {
    Signature signature = validateSignature(parsed, verificationKeys);
    return new Assertion().setSignature(signature)
                          .setId(parsed.getID())
                          .setIssueInstant(parsed.getIssueInstant())
                          .setVersion(parsed.getVersion().toString())
                          .setIssuer(getIssuer(parsed.getIssuer()))
                          .setSubject(getSubject(parsed.getSubject(), localKeys))
                          .setConditions(getConditions(parsed.getConditions()))
                          .setAuthenticationStatements(getAuthenticationStatements(parsed.getAuthnStatements()))
                          .setAttributes(getAttributes(parsed.getAttributeStatements(), localKeys));
  }

  protected List<Attribute> getRequestedAttributes(List<RequestedAttribute> attributes)
  {
    List<Attribute> result = new LinkedList<>();
    for ( RequestedAttribute a : ofNullable(attributes).orElse(emptyList()) )
    {
      result.add(resolveAttribute(a).setRequired(a.isRequired()));
    }
    return result;
  }

  protected List<Attribute> getAttributes(List<AttributeStatement> attributeStatements, List<EncryptionKey> localKeys)
  {
    List<Attribute> result = new LinkedList<>();
    for ( AttributeStatement stmt : ofNullable(attributeStatements).orElse(emptyList()) )
    {
      for ( org.opensaml.saml.saml2.core.Attribute a : ofNullable(stmt.getAttributes()).orElse(emptyList()) )
      {
        result.add(resolveAttribute(a));
      }
      for ( EncryptedAttribute encryptedAttribute : ofNullable(stmt.getEncryptedAttributes()).orElse(emptyList()) )
      {
        org.opensaml.saml.saml2.core.Attribute a = (org.opensaml.saml.saml2.core.Attribute)decrypt(encryptedAttribute,
                                                                                                   localKeys);
        result.add(resolveAttribute(a));
      }
    }
    return result;
  }

  protected Attribute resolveAttribute(org.opensaml.saml.saml2.core.Attribute attribute)
  {
    return new Attribute().setFriendlyName(attribute.getFriendlyName())
                          .setName(attribute.getName())
                          .setNameFormat(AttributeNameFormat.fromUrn(attribute.getNameFormat()))
                          .setValues(getJavaValues(attribute.getAttributeValues()));
  }

  protected List<Object> getJavaValues(List<XMLObject> attributeValues)
  {
    List<Object> result = new LinkedList<>();
    for ( XMLObject o : ofNullable(attributeValues).orElse(emptyList()) )
    {
      if (o == null)
      {

      }
      else if (o instanceof XSString)
      {
        result.add(((XSString)o).getValue());
      }
      else if (o instanceof XSURI)
      {
        try
        {
          result.add(new URI(((XSURI)o).getURI()));
        }
        catch (URISyntaxException e)
        {
          result.add(((XSURI)o).getURI());
        }
      }
      else if (o instanceof XSBoolean)
      {
        result.add(((XSBoolean)o).getValue().getValue());
      }
      else if (o instanceof XSDateTime)
      {
        result.add(((XSDateTime)o).getValue());
      }
      else if (o instanceof XSInteger)
      {
        result.add(((XSInteger)o).getValue());
      }
      else if (o instanceof XSAny)
      {
        XSAny xsAny = (XSAny)o;
        String textContent = xsAny.getTextContent();
        if (ObjectUtils.isEmpty(textContent) && !CollectionUtils.isEmpty(xsAny.getUnknownXMLObjects()))
        {
          XMLObject xmlObject = xsAny.getUnknownXMLObjects().get(0);
          if (xmlObject instanceof NameIDType)
          {
            result.add(((NameIDType)xmlObject).getValue());
          }
        }
        else
        {
          result.add(textContent);
        }
      }
      else
      {
        // we don't know the type.
        result.add(o);
      }
    }

    return result;
  }

  protected List<AuthenticationStatement> getAuthenticationStatements(List<AuthnStatement> authnStatements)
  {
    List<AuthenticationStatement> result = new LinkedList<>();

    for ( AuthnStatement s : ofNullable(authnStatements).orElse(emptyList()) )
    {
      AuthnContext authnContext = s.getAuthnContext();
      AuthnContextClassRef authnContextClassRef = authnContext.getAuthnContextClassRef();
      String ref = null;
      if (authnContextClassRef.getURI() != null)
      {
        ref = authnContextClassRef.getURI();
      }
      List<AuthenticatingAuthority> authenticatingAuthorities = authnContext.getAuthenticatingAuthorities();
      List<String> authenticatingAuthoritiesUrns = authenticatingAuthorities != null
        ? authenticatingAuthorities.stream().map(AuthenticatingAuthority::getURI).collect(Collectors.toList()) : null;
      result.add(new AuthenticationStatement().setSessionIndex(s.getSessionIndex())
                                              .setAuthInstant(s.getAuthnInstant())
                                              .setSessionNotOnOrAfter(s.getSessionNotOnOrAfter())
                                              .setAuthenticationContext(new AuthenticationContext().setClassReference(AuthenticationContextClassReference.fromUrn(ref))
                                                                                                   .setAuthenticatingAuthorities(authenticatingAuthoritiesUrns)));
    }
    return result;
  }

  protected Conditions getConditions(org.opensaml.saml.saml2.core.Conditions conditions)
  {
    if (conditions == null)
    {
      return new Conditions();
    }

    return new Conditions().setNotBefore(conditions.getNotBefore())
                           .setNotOnOrAfter(conditions.getNotOnOrAfter())
                           .setCriteria(getCriteria(conditions.getConditions()));
  }

  protected List<AssertionCondition<?, ?>> getCriteria(List<org.opensaml.saml.saml2.core.Condition> conditions)
  {
    List<AssertionCondition<?, ?>> result = new LinkedList<>();
    for ( Condition c : conditions )
    {
      if (c instanceof org.opensaml.saml.saml2.core.AudienceRestriction)
      {
        org.opensaml.saml.saml2.core.AudienceRestriction aud = (org.opensaml.saml.saml2.core.AudienceRestriction)c;
        if (aud.getAudiences() != null)
        {
          result.add(new AudienceRestriction().setAudiences(aud.getAudiences()
                                                               .stream()
                                                               .map(Audience::getURI)
                                                               .collect(Collectors.toList())));
        }
      }
      else if (c instanceof org.opensaml.saml.saml2.core.OneTimeUse)
      {
        result.add(new OneTimeUse());
      }
    }
    return result;
  }

  protected Subject getSubject(org.opensaml.saml.saml2.core.Subject subject, List<EncryptionKey> localKeys)
  {

    return new Subject().setPrincipal(getPrincipal(subject, localKeys))
                        .setConfirmations(getConfirmations(subject.getSubjectConfirmations(), localKeys));
  }

  protected List<SubjectConfirmation> getConfirmations(List<org.opensaml.saml.saml2.core.SubjectConfirmation> subjectConfirmations,
                                                       List<EncryptionKey> localKeys)
  {
    List<SubjectConfirmation> result = new LinkedList<>();
    for ( org.opensaml.saml.saml2.core.SubjectConfirmation s : subjectConfirmations )
    {
      NameID nameID = getNameID(s.getNameID(), s.getEncryptedID(), localKeys);
      result.add(new SubjectConfirmation().setNameId(nameID != null ? nameID.getValue() : null)
                                          .setFormat(nameID != null ? NameId.fromUrn(nameID.getFormat()) : null)
                                          .setMethod(SubjectConfirmationMethod.fromUrn(s.getMethod()))
                                          .setConfirmationData(new SubjectConfirmationData().setRecipient(s.getSubjectConfirmationData()
                                                                                                           .getRecipient())
                                                                                            .setNotOnOrAfter(s.getSubjectConfirmationData()
                                                                                                              .getNotOnOrAfter())
                                                                                            .setNotBefore(s.getSubjectConfirmationData()
                                                                                                           .getNotBefore())
                                                                                            .setInResponseTo(s.getSubjectConfirmationData()
                                                                                                              .getInResponseTo())));
    }
    return result;
  }

  protected NameID getNameID(NameID id, EncryptedID eid, List<EncryptionKey> localKeys)
  {
    NameID result = id;
    if (result == null && eid != null && eid.getEncryptedData() != null)
    {
      result = (NameID)decrypt(eid, localKeys);
    }
    return result;
  }

  protected NameIdPrincipal getPrincipal(org.opensaml.saml.saml2.core.Subject subject, List<EncryptionKey> localKeys)
  {
    NameID p = getNameID(subject.getNameID(), subject.getEncryptedID(), localKeys);
    if (p != null)
    {
      return getNameIdPrincipal(p);
    }
    else
    {
      throw new UnsupportedOperationException("Currently only supporting NameID subject principals");
    }
  }

  protected NameIdPrincipal getNameIdPrincipal(NameID p)
  {
    return new NameIdPrincipal().setSpNameQualifier(p.getSPNameQualifier())
                                .setNameQualifier(p.getNameQualifier())
                                .setFormat(NameId.fromUrn(p.getFormat()))
                                .setSpProvidedId(p.getSPProvidedID())
                                .setValue(p.getValue());
  }

  protected org.opensaml.saml.saml2.core.Issuer toIssuer(Issuer issuer)
  {
    org.opensaml.saml.saml2.core.Issuer result = buildSAMLObject(org.opensaml.saml.saml2.core.Issuer.class);
    result.setValue(issuer.getValue());
    if (issuer.getFormat() != null)
    {
      result.setFormat(issuer.getFormat().toString());
    }
    result.setSPNameQualifier(issuer.getSpNameQualifier());
    result.setNameQualifier(issuer.getNameQualifier());
    return result;
  }

  protected Issuer getIssuer(org.opensaml.saml.saml2.core.Issuer issuer)
  {
    return issuer == null ? null
      : new Issuer().setValue(issuer.getValue())
                    .setFormat(NameId.fromUrn(issuer.getFormat()))
                    .setSpNameQualifier(issuer.getSPNameQualifier())
                    .setNameQualifier(issuer.getNameQualifier());
  }

  protected List<Object> getExtension(org.opensaml.saml.saml2.core.Extensions extensions)
  {
    if (extensions == null)
    {
      return Collections.emptyList();
    }
    return extensions.getUnknownXMLObjects().stream().map(Object.class::cast).collect(Collectors.toList());
  }

  protected AuthenticationRequest resolveAuthenticationRequest(AuthnRequest parsed)
  {
    AuthnRequest request = parsed;
    return new AuthenticationRequest().setBinding(Binding.fromUrn(request.getProtocolBinding()))
                                      .setAssertionConsumerService(getEndpoint(request.getAssertionConsumerServiceURL(),
                                                                               Binding.fromUrn(request.getProtocolBinding()),
                                                                               ofNullable(request.getAssertionConsumerServiceIndex()).orElse(-1),
                                                                               false))
                                      .setDestination(getEndpoint(request.getDestination(),
                                                                  Binding.fromUrn(request.getProtocolBinding()),
                                                                  -1,
                                                                  false))
                                      .setIssuer(getIssuer(request.getIssuer()))
                                      .setForceAuth(request.isForceAuthn())
                                      .setPassive(request.isPassive())
                                      .setId(request.getID())
                                      .setIssueInstant(request.getIssueInstant())
                                      .setVersion(request.getVersion().toString())
                                      .setRequestedAuthenticationContext(getRequestedAuthenticationContext(request))
                                      .setAuthenticationContextClassReferences(getAuthenticationContextClassReferences(request))
                                      .setNameIdPolicy(fromNameIDPolicy(request.getNameIDPolicy()))
                                      .setScoping(fromScoping(request.getScoping()))
                                      .setExtensions(getExtension(request.getExtensions()));
  }

  protected List<AuthenticationContextClassReference> getAuthenticationContextClassReferences(AuthnRequest request)
  {
    List<AuthenticationContextClassReference> result = null;
    final RequestedAuthnContext context = request.getRequestedAuthnContext();
    if (context != null && !CollectionUtils.isEmpty(context.getAuthnContextClassRefs()))
    {
      result = context.getAuthnContextClassRefs()
                      .stream()
                      .map(ref -> AuthenticationContextClassReference.fromUrn(ref.getURI()))
                      .collect(Collectors.toList());
    }
    return result;
  }

  protected RequestedAuthenticationContext getRequestedAuthenticationContext(AuthnRequest request)
  {
    RequestedAuthenticationContext result = null;

    if (request.getRequestedAuthnContext() != null)
    {
      AuthnContextComparisonTypeEnumeration comparison = request.getRequestedAuthnContext().getComparison();
      if (null != comparison)
      {
        result = RequestedAuthenticationContext.valueOf(comparison.toString());
      }
    }
    return result;
  }

  protected Metadata resolveMetadata(EntitiesDescriptor parsed,
                                     List<SigningKey> verificationKeys,
                                     List<EncryptionKey> localKeys)
  {
    Metadata result = null;
    Metadata current = null;
    for ( EntityDescriptor desc : parsed.getEntityDescriptors() )
    {
      if (result == null)
      {
        result = resolveMetadata(desc);
        current = result;
      }
      else
      {
        Metadata m = resolveMetadata(desc);
        current.setNext(m);
        current = m;
      }
      Signature signature = validateSignature(parsed, verificationKeys);
      current.setSignature(signature);
    }
    return result;
  }

  protected Metadata resolveMetadata(EntityDescriptor parsed)
  {
    EntityDescriptor descriptor = parsed;
    List<? extends Provider<?>> ssoProviders = getSsoProviders(descriptor);
    Metadata desc = getMetadata(ssoProviders);
    desc.setCacheDuration(toJavaXmlDuration(descriptor.getCacheDuration()));
    desc.setEntityId(descriptor.getEntityID());
    desc.setEntityAlias(descriptor.getEntityID());
    desc.setId(descriptor.getID());
    desc.setValidUntil(descriptor.getValidUntil());

    Organization organization = parsed.getOrganization();
    if (organization != null)
    {
      List<OrganizationName> organizationNames = organization.getOrganizationNames();
      desc.organizationName(organizationNames.isEmpty() ? null : organizationNames.get(0).getValue());
      desc.organizationNameLang(organizationNames.isEmpty() ? null : organizationNames.get(0).getXMLLang());

      List<OrganizationDisplayName> displayNames = organization.getDisplayNames();
      desc.organizationDisplayName(displayNames.isEmpty() ? null : displayNames.get(0).getValue());
      desc.organizationDisplayNameLang(displayNames.isEmpty() ? null : displayNames.get(0).getXMLLang());

      List<OrganizationURL> urLs = organization.getURLs();
      desc.organizationURL(urLs.isEmpty() ? null : urLs.get(0).getURI());
      desc.organizationURLLang(urLs.isEmpty() ? null : urLs.get(0).getXMLLang());
    }
    return desc;
  }

  protected Metadata getMetadata(List<? extends Provider<?>> ssoProviders)
  {
    Metadata result = determineMetadataType(ssoProviders);
    result.setProviders(ssoProviders);
    return result;
  }

  private Metadata determineMetadataType(List<? extends Provider<?>> ssoProviders)
  {
    Metadata result = new Metadata();
    long sps = ssoProviders.stream().filter(ServiceProvider.class::isInstance).count();
    long idps = ssoProviders.stream().filter(IdentityProvider.class::isInstance).count();

    if (ssoProviders.size() == sps)
    {
      result = new ServiceProviderMetadata();
    }
    else if (ssoProviders.size() == idps)
    {
      result = new IdentityProviderMetadata();
    }
    result.setProviders(ssoProviders);
    return result;
  }

  protected XMLObject objectToXmlObject(Object o)
  {
    if (o == null)
    {
      return null;
    }
    else if (o instanceof String)
    {
      XSStringBuilder builder = (XSStringBuilder)getBuilderFactory().getBuilder(XSString.TYPE_NAME);
      XSString s = builder.buildObject(AttributeValue.DEFAULT_ELEMENT_NAME, XSString.TYPE_NAME);
      s.setValue((String)o);
      return s;
    }
    else if (o instanceof URI || o instanceof URL)
    {
      XSURIBuilder builder = (XSURIBuilder)getBuilderFactory().getBuilder(XSURI.TYPE_NAME);
      XSURI uri = builder.buildObject(AttributeValue.DEFAULT_ELEMENT_NAME, XSURI.TYPE_NAME);
      uri.setURI(o.toString());
      return uri;
    }
    else if (o instanceof Boolean)
    {
      XSBooleanBuilder builder = (XSBooleanBuilder)getBuilderFactory().getBuilder(XSBoolean.TYPE_NAME);
      XSBoolean b = builder.buildObject(AttributeValue.DEFAULT_ELEMENT_NAME, XSBoolean.TYPE_NAME);
      XSBooleanValue v = XSBooleanValue.valueOf(o.toString());
      b.setValue(v);
      return b;
    }
    else if (o instanceof Instant)
    {
      XSDateTimeBuilder builder = (XSDateTimeBuilder)getBuilderFactory().getBuilder(XSDateTime.TYPE_NAME);
      XSDateTime dt = builder.buildObject(AttributeValue.DEFAULT_ELEMENT_NAME, XSDateTime.TYPE_NAME);
      dt.setValue((Instant)o);
      return dt;
    }
    else if (o instanceof Integer)
    {
      XSIntegerBuilder builder = (XSIntegerBuilder)getBuilderFactory().getBuilder(XSInteger.TYPE_NAME);
      XSInteger i = builder.buildObject(AttributeValue.DEFAULT_ELEMENT_NAME, XSInteger.TYPE_NAME);
      i.setValue((Integer)o);
      return i;
    }
    else
    {
      XSAnyBuilder builder = (XSAnyBuilder)getBuilderFactory().getBuilder(XSAny.TYPE_NAME);
      XSAny any = builder.buildObject(AttributeValue.DEFAULT_ELEMENT_NAME, XSAny.TYPE_NAME);
      any.setTextContent(o.toString());
      return any;
    }
  }

  protected String xmlObjectToString(XMLObject o)
  {
    String toMatch = null;
    if (o instanceof XSString)
    {
      toMatch = ((XSString)o).getValue();
    }
    else if (o instanceof XSURI)
    {
      toMatch = ((XSURI)o).getURI();
    }
    else if (o instanceof XSBoolean)
    {
      toMatch = Boolean.TRUE.equals(((XSBoolean)o).getValue().getValue()) ? "1" : "0";
    }
    else if (o instanceof XSInteger)
    {
      toMatch = ((XSInteger)o).getValue().toString();
    }
    else if (o instanceof XSDateTime)
    {
        toMatch = ((XSDateTime)o).getValue().toString();
    }
    else if (o instanceof XSBase64Binary)
    {
      toMatch = ((XSBase64Binary)o).getValue();
    }
    else if (o instanceof XSAny)
    {
      final XSAny wc = (XSAny)o;
      if (wc.getUnknownAttributes().isEmpty() && wc.getUnknownXMLObjects().isEmpty())
      {
        toMatch = wc.getTextContent();
      }
    }
    if (toMatch != null)
    {
      return toMatch;
    }
    return null;
  }

  protected Endpoint getEndpoint(String url, Binding binding, int index, boolean isDefault)
  {
    return new Endpoint().setIndex(index).setBinding(binding).setLocation(url).setDefault(isDefault).setIndex(index);
  }

  public NameIDFormat getNameIDFormat(NameId nameId)
  {
    SAMLObjectBuilder<NameIDFormat> builder = (SAMLObjectBuilder<NameIDFormat>)getBuilderFactory().getBuilder(NameIDFormat.DEFAULT_ELEMENT_NAME);
    NameIDFormat format = builder.buildObject();
    format.setURI(nameId.toString());
    return format;
  }

  public SingleSignOnService getSingleSignOnService(Endpoint endpoint, int index)
  {
    SAMLObjectBuilder<SingleSignOnService> builder = (SAMLObjectBuilder<SingleSignOnService>)getBuilderFactory().getBuilder(SingleSignOnService.DEFAULT_ELEMENT_NAME);
    SingleSignOnService sso = builder.buildObject();
    sso.setLocation(endpoint.getLocation());
    sso.setBinding(endpoint.getBinding().toString());
    return sso;
  }

  public AssertionConsumerService getAssertionConsumerService(Endpoint endpoint, int index)
  {
    SAMLObjectBuilder<AssertionConsumerService> builder = (SAMLObjectBuilder<AssertionConsumerService>)getBuilderFactory().getBuilder(AssertionConsumerService.DEFAULT_ELEMENT_NAME);
    AssertionConsumerService consumer = builder.buildObject();
    consumer.setLocation(endpoint.getLocation());
    consumer.setBinding(endpoint.getBinding().toString());
    consumer.setIsDefault(endpoint.isDefault());
    consumer.setIndex(index);
    return consumer;
  }

  public SingleLogoutService getSingleLogoutService(Endpoint endpoint)
  {
    SAMLObjectBuilder<SingleLogoutService> builder = (SAMLObjectBuilder<SingleLogoutService>)getBuilderFactory().getBuilder(SingleLogoutService.DEFAULT_ELEMENT_NAME);
    SingleLogoutService service = builder.buildObject();
    service.setBinding(endpoint.getBinding().toString());
    service.setLocation(endpoint.getLocation());
    return service;
  }

  public <K extends SimpleKey<K>> KeyDescriptor getKeyDescriptor(K key)
  {
    SAMLObjectBuilder<KeyDescriptor> builder = (SAMLObjectBuilder<KeyDescriptor>)getBuilderFactory().getBuilder(KeyDescriptor.DEFAULT_ELEMENT_NAME);
    KeyDescriptor descriptor = builder.buildObject();

    KeyStoreCredentialResolver resolver = getCredentialsResolver(key);
    Credential credential = getCredential(key, resolver);
    try
    {
      KeyInfo info = getKeyInfoGenerator(credential).generate(credential);
      descriptor.setKeyInfo(info);
      if (key instanceof SigningKey)
      {
        descriptor.setUse(UsageType.SIGNING);
      }
      else if (key instanceof EncryptionKey)
      {
        descriptor.setUse(UsageType.ENCRYPTION);
        EncryptionKey encryptionKey = (EncryptionKey)key;
        if (encryptionKey.getDataEncryptionMethod() != null)
        {
          DataEncryptionMethod dataEncryptionMethod = encryptionKey.getDataEncryptionMethod();
          EncryptionMethod encryptionMethod = ((EncryptionMethodBuilder)getBuilderFactory().getBuilder(EncryptionMethod.DEFAULT_ELEMENT_NAME)).buildObject();
          encryptionMethod.setAlgorithm(dataEncryptionMethod.toString());
          if (dataEncryptionMethod.getKeySize() != null)
          {
            KeySize keySize = ((KeySizeBuilder)getBuilderFactory().getBuilder(KeySize.DEFAULT_ELEMENT_NAME)).buildObject();
            keySize.setValue(dataEncryptionMethod.getKeySize());
            encryptionMethod.setKeySize(keySize);
          }
          descriptor.getEncryptionMethods().add(encryptionMethod);
        }
      }
      return descriptor;
    }
    catch (SecurityException e)
    {
      throw new SamlKeyException(e);
    }
  }

  public KeyInfoGenerator getKeyInfoGenerator(Credential credential)
  {
    NamedKeyInfoGeneratorManager manager = DefaultSecurityConfigurationBootstrap.buildBasicKeyInfoGeneratorManager();
    return manager.getDefaultManager().getFactory(credential).newInstance();
  }

  public void signObject(SignableSAMLObject signable, SigningKey key, AlgorithmMethod algorithm, DigestMethod digest)
  {

    KeyStoreCredentialResolver resolver = getCredentialsResolver(key);
    Credential credential = getCredential(key, resolver);

    XMLObjectBuilder<org.opensaml.xmlsec.signature.Signature> signatureBuilder = (XMLObjectBuilder<org.opensaml.xmlsec.signature.Signature>)getBuilderFactory().getBuilder(org.opensaml.xmlsec.signature.Signature.DEFAULT_ELEMENT_NAME);
    org.opensaml.xmlsec.signature.Signature signature = signatureBuilder.buildObject(org.opensaml.xmlsec.signature.Signature.DEFAULT_ELEMENT_NAME);

    signable.setSignature(signature);

    SignatureSigningParameters parameters = new SignatureSigningParameters();
    parameters.setSigningCredential(credential);
    parameters.setKeyInfoGenerator(getKeyInfoGenerator(credential));
    parameters.setSignatureAlgorithm(algorithm.toString());
    parameters.setSignatureReferenceDigestMethod(digest.toString());
    parameters.setSignatureCanonicalizationAlgorithm(CanonicalizationMethod.ALGO_ID_C14N_EXCL_OMIT_COMMENTS.toString());

    try
    {
      SignatureSupport.prepareSignatureParams(signature, parameters);
      Marshaller marshaller = XMLObjectProviderRegistrySupport.getMarshallerFactory().getMarshaller(signable);
      marshaller.marshall(signable);
      Signer.signObject(signature);
    }
    catch (SecurityException | MarshallingException | SignatureException e)
    {
      throw new SamlKeyException(e);
    }
  }

  @SuppressWarnings("unchecked")
  public <T> T buildSAMLObject(final Class<T> clazz)
  {
    T object = null;
    try
    {
      QName defaultElementName = (QName)clazz.getDeclaredField("DEFAULT_ELEMENT_NAME").get(null);
      object = (T)getBuilderFactory().getBuilder(defaultElementName).buildObject(defaultElementName);
    }
    catch (IllegalAccessException | NoSuchFieldException e)
    {
      throw new SamlException("Could not create SAML object", e);
    }

    return object;
  }

}
