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
package org.springframework.security.saml;

import java.util.List;

import org.springframework.security.saml.key.SigningKey;
import org.springframework.security.saml.saml2.signature.AlgorithmMethod;
import org.springframework.security.saml.saml2.signature.SignatureException;

import jakarta.servlet.http.HttpServletRequest;


public interface SamlRedirectBindingSigner
{

  /**
   * Create signature value for HTTP Redirect Binding requests. Calculate
   * <code>base64(SigAlg("[SAMLRequest|SAMLResponse]=value&RelayState=value&SigAlg=value"))</code>
   *
   * @param isSamlRequest boolean flag indicating whether this is a SAMLRequest or a SAMLResponse
   * @param encoded the uri-encoded saml request
   * @param encodedRelayState the uri-encoded relay state
   * @param encodedSigAlg the uri-encoded signature algorithm
   * @param sigAlg the signature algorithm
   * @param key the key to be used for signing
   * @return base64(SigAlg("[SAMLRequest|SAMLResponse]={encoded}&RelayState={relayState}&SigAlg={encodedSigAlg}"))
   */
  String createSignature(boolean isSamlRequest,
                         String encoded,
                         String encodedRelayState,
                         String encodedSigAlg,
                         AlgorithmMethod sigAlg,
                         SigningKey key);

  /**
   * validate HTTP Redirect Binding signature
   *
   * @param isSamlRequest boolean flag indicating whether this is a SAMLRequest or a SAMLResponse
   * @param request the HttpServletRequest containing the Redirect-Binding-request
   * @param verificationKeys a list containing all keys to check the signature with
   * @throws SignatureException if object failed signature validation
   */
  void validateSignature(boolean isSamlRequest, HttpServletRequest request, List<SigningKey> verificationKeys);

}
