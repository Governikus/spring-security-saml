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
package org.springframework.security.saml.saml2.authentication;

import org.springframework.security.saml.key.SigningKey;
import org.springframework.security.saml.saml2.signature.AlgorithmMethod;
import org.springframework.security.saml.saml2.signature.DigestMethod;

/**
 * Implementation samlp:ManageNameIDRequestType as defined by "Describes as Assertions and Protocols for the OASIS
 * Security Assertion Markup Language (SAML) V2.0" Page 58, Line 2439
 */
public class ManageNameIDRequest extends Request<ManageNameIDRequest>
{

  /**
   * BaseID, NameID or EncryptedID
   */
  private NameIdPrincipal nameId;

  private SigningKey signingKey;

  private AlgorithmMethod algorithm;

  private DigestMethod digest;

  public NameIdPrincipal getNameId()
  {
    return nameId;
  }

  public ManageNameIDRequest setNameId(NameIdPrincipal nameId)
  {
    this.nameId = nameId;
    return this;
  }

  public ManageNameIDRequest setSigningKey(SigningKey signingKey, AlgorithmMethod algorithm, DigestMethod digest)
  {
    this.signingKey = signingKey;
    this.algorithm = algorithm;
    this.digest = digest;
    return this;
  }

  public SigningKey getSigningKey()
  {
    return signingKey;
  }

  public AlgorithmMethod getAlgorithm()
  {
    return algorithm;
  }

  public DigestMethod getDigest()
  {
    return digest;
  }

}
