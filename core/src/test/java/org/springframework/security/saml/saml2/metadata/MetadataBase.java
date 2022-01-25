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
package org.springframework.security.saml.saml2.metadata;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.security.saml.spi.ExamplePemKey.IDP_RSA_KEY;
import static org.springframework.security.saml.spi.ExamplePemKey.SP_RSA_KEY;

import java.io.IOException;
import java.time.Clock;
import java.util.Arrays;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.springframework.core.io.ClassPathResource;
import org.springframework.security.saml.SamlTransformer;
import org.springframework.security.saml.helper.SamlTestObjectHelper;
import org.springframework.security.saml.key.EncryptionKey;
import org.springframework.security.saml.key.SigningKey;
import org.springframework.security.saml.saml2.signature.AlgorithmMethod;
import org.springframework.security.saml.saml2.signature.DigestMethod;
import org.springframework.security.saml.spi.DefaultSamlTransformer;
import org.springframework.security.saml.spi.opensaml.OpenSamlImplementation;
import org.springframework.util.StreamUtils;


public abstract class MetadataBase
{

  protected static SamlTransformer config;

  protected static Clock time;

  protected SigningKey spSigning;

  protected SigningKey idpSigning;

  protected SigningKey spVerifying;

  protected SigningKey idpVerifying;

  protected EncryptionKey spEncryption;

  protected EncryptionKey idpEncryption;

  protected String spBaseUrl;

  protected String idpBaseUrl;

  protected ServiceProviderMetadata serviceProviderMetadata;

  protected IdentityProviderMetadata identityProviderMetadata;

  protected SamlTestObjectHelper helper;

  @BeforeAll
  public static void init()
  {
    time = Clock.systemUTC();
    config = new DefaultSamlTransformer(new OpenSamlImplementation(time).init());
    ((DefaultSamlTransformer)config).afterPropertiesSet();
  }

  protected byte[] getFileBytes(String path) throws IOException
  {
    ClassPathResource resource = new ClassPathResource(path);
    assertTrue(resource.exists(), path + " must exist.");
    return StreamUtils.copyToByteArray(resource.getInputStream());
  }

  @BeforeEach
  public void setup()
  {
    idpSigning = IDP_RSA_KEY.getSigningKey("idp");
    idpEncryption = IDP_RSA_KEY.getEncryptionKey("idp");
    idpVerifying = new SigningKey("idp-verify", SP_RSA_KEY.getPublic());
    spSigning = SP_RSA_KEY.getSigningKey("sp");
    spEncryption = SP_RSA_KEY.getEncryptionKey("sp");
    spVerifying = new SigningKey("sp-verify", IDP_RSA_KEY.getPublic());
    spBaseUrl = "http://sp.localhost:8080/uaa";
    idpBaseUrl = "http://idp.localhost:8080/uaa";
    helper = new SamlTestObjectHelper(time);

    serviceProviderMetadata = helper.serviceProviderMetadata(spBaseUrl,
                                                             spSigning,
                                                             Arrays.asList(spEncryption),
                                                             "saml/sp/",
                                                             "sp-alias",
                                                             AlgorithmMethod.RSA_SHA1,
                                                             DigestMethod.SHA1);
    identityProviderMetadata = helper.identityProviderMetadata(idpBaseUrl,
                                                               idpSigning,
                                                               Arrays.asList(idpEncryption),
                                                               "saml/idp/",
                                                               "idp-alias",
                                                               AlgorithmMethod.RSA_SHA1,
                                                               DigestMethod.SHA1);
  }


}
