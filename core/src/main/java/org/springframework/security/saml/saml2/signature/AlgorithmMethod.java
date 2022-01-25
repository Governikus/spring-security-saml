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


public final class AlgorithmMethod
{

  public static final AlgorithmMethod NOT_RECOMMENDED_RSA_MD5 = new AlgorithmMethod("http://www.w3.org/2001/04/xmldsig-more#rsa-md5",
                                                                                    "MD5WithRSA");

  public static final AlgorithmMethod RSA_SHA1 = new AlgorithmMethod("http://www.w3.org/2000/09/xmldsig#rsa-sha1",
                                                                     "SHA1WithRSA");

  public static final AlgorithmMethod RSA_SHA224 = new AlgorithmMethod("http://www.w3.org/2001/04/xmldsig-more#rsa-sha224",
                                                                       "SHA224WithRSA");

  public static final AlgorithmMethod RSA_SHA256 = new AlgorithmMethod("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
                                                                       "SHA256WithRSA");

  public static final AlgorithmMethod RSA_SHA384 = new AlgorithmMethod("http://www.w3.org/2001/04/xmldsig-more#rsa-sha384",
                                                                       "SHA384WithRSA");

  public static final AlgorithmMethod RSA_SHA512 = new AlgorithmMethod("http://www.w3.org/2001/04/xmldsig-more#rsa-sha512",
                                                                       "SHA512WithRSA");

  public static final AlgorithmMethod RSA_RIPEMD160 = new AlgorithmMethod("http://www.w3.org/2001/04/xmldsig-more#rsa-ripemd160",
                                                                          "RIPEMD160WithRSA");

  public static final AlgorithmMethod DSA_SHA1 = new AlgorithmMethod("http://www.w3.org/2000/09/xmldsig#dsa-sha1",
                                                                     "SHA1withDSA");

  public static final AlgorithmMethod DSA_SHA256 = new AlgorithmMethod("http://www.w3.org/2009/xmldsig11#dsa-sha256",
                                                                       "SHA256withDSA");

  public static final AlgorithmMethod ECDSA_SHA1 = new AlgorithmMethod("http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha1",
                                                                       "SHA1WithECDSA");

  public static final AlgorithmMethod ECDSA_SHA224 = new AlgorithmMethod("http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha224",
                                                                         "SHA224WithECDSA");

  public static final AlgorithmMethod ECDSA_SHA256 = new AlgorithmMethod("http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256",
                                                                         "SHA256WithECDSA");

  public static final AlgorithmMethod ECDSA_SHA384 = new AlgorithmMethod("http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384",
                                                                         "SHA384WithECDSA");

  public static final AlgorithmMethod ECDSA_SHA512 = new AlgorithmMethod("http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512",
                                                                         "SHA512WithECDSA");

  private static final List<AlgorithmMethod> VALUES = Arrays.asList(NOT_RECOMMENDED_RSA_MD5,
                                                                    RSA_SHA1,
                                                                    RSA_SHA224,
                                                                    RSA_SHA256,
                                                                    RSA_SHA384,
                                                                    RSA_SHA512,
                                                                    RSA_RIPEMD160,
                                                                    DSA_SHA1,
                                                                    DSA_SHA256,
                                                                    ECDSA_SHA1,
                                                                    ECDSA_SHA224,
                                                                    ECDSA_SHA256,
                                                                    ECDSA_SHA384,
                                                                    ECDSA_SHA512);

  private final String urn;

  private final String javaStandardAlgorithmName;

  AlgorithmMethod(String urn, String securityProviderName)
  {
    this.urn = urn;
    this.javaStandardAlgorithmName = securityProviderName;
  }

  public static AlgorithmMethod fromUrn(String urn)
  {
    for ( AlgorithmMethod m : VALUES )
    {
      if (m.urn.equalsIgnoreCase(urn))
      {
        return m;
      }
    }
    return new AlgorithmMethod(urn, null);
  }

  public String getJavaStandardAlgorithmName()
  {
    return javaStandardAlgorithmName;
  }

  @Override
  public String toString()
  {
    return urn;
  }
}
