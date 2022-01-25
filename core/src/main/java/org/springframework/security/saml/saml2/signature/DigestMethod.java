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
package org.springframework.security.saml.saml2.signature;

import java.util.Arrays;
import java.util.List;


public final class DigestMethod
{

  /**
   * The <a href="https://www.w3.org/2000/09/xmldsig#sha1"> SHA1</a> digest method algorithm URI.
   */
  public static final DigestMethod SHA1 = new DigestMethod(javax.xml.crypto.dsig.DigestMethod.SHA1);

  /**
   * The <a href="http://www.w3.org/2001/04/xmldsig-more#sha224"> SHA224</a> digest method algorithm URI.
   */
  public static final DigestMethod SHA224 = new DigestMethod(javax.xml.crypto.dsig.DigestMethod.SHA224);

  /**
   * The <a href="https://www.w3.org/2001/04/xmlenc#sha256"> SHA256</a> digest method algorithm URI.
   */
  public static final DigestMethod SHA256 = new DigestMethod(javax.xml.crypto.dsig.DigestMethod.SHA256);

  /**
   * The <a href="http://www.w3.org/2001/04/xmldsig-more#sha384"> SHA384</a> digest method algorithm URI.
   */
  public static final DigestMethod SHA384 = new DigestMethod(javax.xml.crypto.dsig.DigestMethod.SHA384);

  /**
   * The <a href="https://www.w3.org/2001/04/xmlenc#sha512"> SHA512</a> digest method algorithm URI.
   */
  public static final DigestMethod SHA512 = new DigestMethod(javax.xml.crypto.dsig.DigestMethod.SHA512);

  /**
   * The <a href="https://www.w3.org/2001/04/xmlenc#ripemd160"> RIPEMD-160</a> digest method algorithm URI.
   */
  public static final DigestMethod RIPEMD160 = new DigestMethod(javax.xml.crypto.dsig.DigestMethod.RIPEMD160);

  /**
   * The <a href="http://www.w3.org/2007/05/xmldsig-more#sha3-224"> SHA3-224</a> digest method algorithm URI.
   */
  public static final DigestMethod SHA3_224 = new DigestMethod(javax.xml.crypto.dsig.DigestMethod.SHA3_224);

  /**
   * The <a href="http://www.w3.org/2007/05/xmldsig-more#sha3-256"> SHA3-256</a> digest method algorithm URI.
   */
  public static final DigestMethod SHA3_256 = new DigestMethod(javax.xml.crypto.dsig.DigestMethod.SHA3_256);

  /**
   * The <a href="http://www.w3.org/2007/05/xmldsig-more#sha3-384"> SHA3-384</a> digest method algorithm URI.
   */
  public static final DigestMethod SHA3_384 = new DigestMethod(javax.xml.crypto.dsig.DigestMethod.SHA3_384);

  /**
   * The <a href="http://www.w3.org/2007/05/xmldsig-more#sha3-512"> SHA3-512</a> digest method algorithm URI.
   */
  public static final DigestMethod SHA3_512 = new DigestMethod(javax.xml.crypto.dsig.DigestMethod.SHA3_512);

  private static final List<DigestMethod> VALUES = Arrays.asList(SHA1,
                                                                 SHA224,
                                                                 SHA256,
                                                                 SHA384,
                                                                 SHA512,
                                                                 RIPEMD160,
                                                                 SHA3_224,
                                                                 SHA3_256,
                                                                 SHA3_384,
                                                                 SHA3_512);

  private final String urn;

  DigestMethod(String urn)
  {
    this.urn = urn;
  }

  public static DigestMethod fromUrn(String digestAlgorithm)
  {
    for ( DigestMethod m : VALUES )
    {
      if (m.urn.equalsIgnoreCase(digestAlgorithm))
      {
        return m;
      }
    }
    return new DigestMethod(digestAlgorithm);
  }

  @Override
  public String toString()
  {
    return urn;
  }
}
