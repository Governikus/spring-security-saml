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


public final class CanonicalizationMethod
{

  public static final CanonicalizationMethod ALGO_ID_C14N_OMIT_COMMENTS = new CanonicalizationMethod("http://www.w3.org/TR/2001/REC-xml-c14n-20010315");

  public static final CanonicalizationMethod ALGO_ID_C14N_WITH_COMMENTS = new CanonicalizationMethod(ALGO_ID_C14N_OMIT_COMMENTS.toString()
                                                                                                     + "#WithComments");

  public static final CanonicalizationMethod ALGO_ID_C14N11_OMIT_COMMENTS = new CanonicalizationMethod("http://www.w3.org/2006/12/xml-c14n11");

  public static final CanonicalizationMethod ALGO_ID_C14N11_WITH_COMMENTS = new CanonicalizationMethod(ALGO_ID_C14N11_OMIT_COMMENTS.toString()
                                                                                                       + "#WithComments");

  public static final CanonicalizationMethod ALGO_ID_C14N_EXCL_OMIT_COMMENTS = new CanonicalizationMethod("http://www.w3.org/2001/10/xml-exc-c14n#");

  public static final CanonicalizationMethod ALGO_ID_C14N_EXCL_WITH_COMMENTS = new CanonicalizationMethod(ALGO_ID_C14N_EXCL_OMIT_COMMENTS
                                                                                                          + "WithComments");

  private static final List<CanonicalizationMethod> VALUES = Arrays.asList(ALGO_ID_C14N_OMIT_COMMENTS,
                                                                           ALGO_ID_C14N_WITH_COMMENTS,
                                                                           ALGO_ID_C14N11_OMIT_COMMENTS,
                                                                           ALGO_ID_C14N11_WITH_COMMENTS,
                                                                           ALGO_ID_C14N_EXCL_OMIT_COMMENTS,
                                                                           ALGO_ID_C14N_EXCL_WITH_COMMENTS);

  private final String urn;

  CanonicalizationMethod(String urn)
  {
    this.urn = urn;
  }

  public static CanonicalizationMethod fromUrn(String urn)
  {
    for ( CanonicalizationMethod m : VALUES )
    {
      if (m.urn.equalsIgnoreCase(urn))
      {
        return m;
      }
    }
    return new CanonicalizationMethod(urn);
  }

  @Override
  public String toString()
  {
    return urn;
  }
}
