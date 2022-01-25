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

package org.springframework.security.saml.saml2.encrypt;

import java.util.Arrays;
import java.util.List;

import javax.annotation.Nonnull;


public final class DataEncryptionMethod
{

  public static final DataEncryptionMethod TRIPLEDES_CBS = new DataEncryptionMethod("http://www.w3.org/2001/04/xmlenc#tripledes-cbc",
                                                                                    null);

  public static final DataEncryptionMethod AES128_CBC = new DataEncryptionMethod("http://www.w3.org/2001/04/xmlenc#aes128-cbc",
                                                                                 128);

  public static final DataEncryptionMethod AES192_CBC = new DataEncryptionMethod("http://www.w3.org/2001/04/xmlenc#aes192-cbc",
                                                                                 192);

  public static final DataEncryptionMethod AES256_CBC = new DataEncryptionMethod("http://www.w3.org/2001/04/xmlenc#aes256-cbc",
                                                                                 256);

  public static final DataEncryptionMethod AES128_GCM = new DataEncryptionMethod("http://www.w3.org/2009/xmlenc11#aes128-gcm",
                                                                                 128);

  public static final DataEncryptionMethod AES192_GCM = new DataEncryptionMethod("http://www.w3.org/2009/xmlenc11#aes192-gcm",
                                                                                 192);

  public static final DataEncryptionMethod AES256_GCM = new DataEncryptionMethod("http://www.w3.org/2009/xmlenc11#aes256-gcm",
                                                                                 256);

  private static final List<DataEncryptionMethod> VALUES = Arrays.asList(TRIPLEDES_CBS,
                                                                         AES128_CBC,
                                                                         AES192_CBC,
                                                                         AES256_CBC,
                                                                         AES128_GCM,
                                                                         AES192_GCM,
                                                                         AES256_GCM);

  private final String urn;

  private final Integer keySize;

  DataEncryptionMethod(@Nonnull String urn, Integer keySize)
  {
    this.urn = urn;
    this.keySize = keySize;
  }

  public static DataEncryptionMethod fromUrn(String urn, Integer keySize)
  {
    for ( DataEncryptionMethod dataEncryptionMethod : VALUES )
    {
      if (dataEncryptionMethod.urn.equalsIgnoreCase(urn))
      {
        return dataEncryptionMethod;
      }
    }
    return new DataEncryptionMethod(urn, keySize);
  }

  public static DataEncryptionMethod fromUrn(String urn)
  {
    return fromUrn(urn, 0);
  }

  @Override
  public String toString()
  {
    return urn;
  }

  public Integer getKeySize()
  {
    return keySize;
  }
}
