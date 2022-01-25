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


public final class KeyEncryptionMethod
{

  public static final KeyEncryptionMethod RSA_1_5 = new KeyEncryptionMethod("http://www.w3.org/2001/04/xmlenc#rsa-1_5");

  public static final KeyEncryptionMethod RSA_OAEP_MGF1P = new KeyEncryptionMethod("http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p");

  private static final List<KeyEncryptionMethod> VALUES = Arrays.asList(RSA_1_5, RSA_OAEP_MGF1P);

  private final String urn;

  KeyEncryptionMethod(@Nonnull String urn)
  {
    this.urn = urn;
  }

  public static KeyEncryptionMethod fromUrn(String urn)
  {
    for ( KeyEncryptionMethod keyEncryptionMethod : VALUES )
    {
      if (keyEncryptionMethod.urn.equalsIgnoreCase(urn))
      {
        return keyEncryptionMethod;
      }
    }
    return new KeyEncryptionMethod(urn);
  }

  @Override
  public String toString()
  {
    return urn;
  }
}
