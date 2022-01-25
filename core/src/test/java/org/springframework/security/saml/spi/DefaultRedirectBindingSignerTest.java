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
package org.springframework.security.saml.spi;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.charset.StandardCharsets;
import java.security.Security;
import java.util.Collections;
import java.util.List;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.saml.SamlRedirectBindingSigner;
import org.springframework.security.saml.key.SigningKey;
import org.springframework.security.saml.saml2.signature.AlgorithmMethod;
import org.springframework.security.saml.saml2.signature.SignatureException;
import org.springframework.web.util.UriUtils;


class DefaultRedirectBindingSignerTest
{

  private static final SigningKey SIGNATURE_KEY = new SigningKey("signature-key",
                                                               "-----BEGIN RSA PRIVATE KEY-----\n"
                                                                                + "Proc-Type: 4,ENCRYPTED\n"
                                                                                + "DEK-Info: DES-EDE3-CBC,7C8510E4CED17A9F\n"
                                                                                + "\n"
                                                                                + "SRYezKuY+AgM+gdiklVDBQ1ljeCFKnW3c5BM9sEyEOfkQm0zZx6fLr0afup0ToE4\n"
                                                                                + "iJGLxKw8swAnUAIjYda9wxqIEBb9mILyuRPevyfzmio2lE9KnARDEYRBqbwD9Lpd\n"
                                                                                + "vwZKNGHHJbZAgcUNfhXiYakmx0cUyp8HeO3Vqa/0XMiI/HAdlJ/ruYeT4e2DSrz9\n"
                                                                                + "ORZA2S5OvNpRQeCVf26l6ODKXnkDL0t5fDVY4lAhaiyhZtoT0sADlPIERBw73kHm\n"
                                                                                + "fGCTniY9qT0DT+R5Rqukk42mN2ij/cAr+kdV5colBi1fuN6d9gawCiH4zSb3LzHQ\n"
                                                                                + "9ccSlz6iQV1Ty2cRuTkB3zWC6Oy4q0BRlXnVRFOnOfYJztO6c2hD3Q9NxkDAbcgR\n"
                                                                                + "YWJWHpd0/HI8GyBpOG7hAS1l6aoleH30QCDOo7N2rFrTAaPC6g84oZOFSqkqvx4R\n"
                                                                                + "KTbWRwgJsqVxM6GqV6H9x1LNn2CpBizdGnp8VvnIiYcEvItMJbT1C1yeIUPoDDU2\n"
                                                                                + "Ct0Jofw/dquXStHWftPFjpIqB+5Ou//HQ2VNzjbyThNWVGtjnEKwSiHacQLS1sB3\n"
                                                                                + "iqFtSN/VCpdOcRujEBba+x5vlc8XCV1qr6x1PbvfPZVjyFdSM6JQidr0uEeDGDW3\n"
                                                                                + "TuYC1YgURN8zh0QF2lJIMX3xgbhr8HHNXv60ulcjeqYmna6VCS8AKJQgRTr4DGWt\n"
                                                                                + "Afv9BFV943Yp3nHwPC7nYC4FvMxOn4qW4KrHRJl57zcY6VDL4J030CfmvLjqUbuT\n"
                                                                                + "LYiQp/YgFlmoE4bcGuCiaRfUJZCwooPK2dQMoIvMZeVl9ExUGdXVMg==\n"
                                                                                + "-----END RSA PRIVATE KEY-----",
                                                               "-----BEGIN CERTIFICATE-----\n" + "MIICgTCCAeoCCQCuVzyqFgMSyDANBgkqhkiG9w0BAQsFADCBhDELMAkGA1UEBhMC\n"
                                                                                                                   + "VVMxEzARBgNVBAgMCldhc2hpbmd0b24xEjAQBgNVBAcMCVZhbmNvdXZlcjEdMBsG\n"
                                                                                                                   + "A1UECgwUU3ByaW5nIFNlY3VyaXR5IFNBTUwxCzAJBgNVBAsMAnNwMSAwHgYDVQQD\n"
                                                                                                                   + "DBdzcC5zcHJpbmcuc2VjdXJpdHkuc2FtbDAeFw0xODA1MTQxNDMwNDRaFw0yODA1\n"
                                                                                                                   + "MTExNDMwNDRaMIGEMQswCQYDVQQGEwJVUzETMBEGA1UECAwKV2FzaGluZ3RvbjES\n"
                                                                                                                   + "MBAGA1UEBwwJVmFuY291dmVyMR0wGwYDVQQKDBRTcHJpbmcgU2VjdXJpdHkgU0FN\n"
                                                                                                                   + "TDELMAkGA1UECwwCc3AxIDAeBgNVBAMMF3NwLnNwcmluZy5zZWN1cml0eS5zYW1s\n"
                                                                                                                   + "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDRu7/EI0BlNzMEBFVAcbx+lLos\n"
                                                                                                                   + "vzIWU+01dGTY8gBdhMQNYKZ92lMceo2CuVJ66cUURPym3i7nGGzoSnAxAre+0YIM\n"
                                                                                                                   + "+U0razrWtAUE735bkcqELZkOTZLelaoOztmWqRbe5OuEmpewH7cx+kNgcVjdctOG\n"
                                                                                                                   + "y3Q6x+I4qakY/9qhBQIDAQABMA0GCSqGSIb3DQEBCwUAA4GBAAeViTvHOyQopWEi\n"
                                                                                                                   + "XOfI2Z9eukwrSknDwq/zscR0YxwwqDBMt/QdAODfSwAfnciiYLkmEjlozWRtOeN+\n"
                                                                                                                   + "qK7UFgP1bRl5qksrYX5S0z2iGJh0GvonLUt3e20Ssfl5tTEDDnAEUMLfBkyaxEHD\n"
                                                                                                                   + "RZ/nbTJ7VTeZOSyRoVn5XHhpuJ0B\n"
                                                                                                                   + "-----END CERTIFICATE-----",
                                                               "sppassword");

  private static final AlgorithmMethod SIG_ALG = AlgorithmMethod.RSA_SHA256;

  private static final String ENCODED = "encoded_request";

  private SamlRedirectBindingSigner laxSigner = new DefaultRedirectBindingSigner();

  private SamlRedirectBindingSigner restrictiveSigner = new DefaultRedirectBindingSigner().setAllowMissingSignature(false)
                                                                                          .setAllowMissingSignatureKeys(false);

  @BeforeAll
  public static void init()
  {
    if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) != null)
    {
      Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME);
    }
    Security.addProvider(new BouncyCastleProvider());
  }

  /**
   * test if HttpRedirectBindingSignatureService.createRequestSignature() and
   * HttpRedirectBindingSignatureService.validateRequestSignature() match with each other
   */
  @Test
  void testRedirectBindingRequest()
  {
    String relayState = "relay_state";
    String encodedSigAlg = UriUtils.encode(SIG_ALG.toString(), StandardCharsets.UTF_8);

    String signature = restrictiveSigner.createSignature(true,
                                                         ENCODED,
                                                         relayState,
                                                         encodedSigAlg,
                                                         SIG_ALG,
                                                         SIGNATURE_KEY);

    MockHttpServletRequest mockRequest = createRequestWithRelayState(ENCODED, relayState, encodedSigAlg, signature);

    assertDoesNotThrow(() -> restrictiveSigner.validateSignature(true, mockRequest, validKey()));
  }

  /**
   * test if HttpRedirectBindingSignatureService.createRequestSignature() and
   * HttpRedirectBindingSignatureService.validateRequestSignature() match with each other
   */
  @Test
  void testRedirectBindingResponse()
  {
    String relayState = "relay_state";
    String encodedSigAlg = UriUtils.encode(SIG_ALG.toString(), StandardCharsets.UTF_8);

    String signature = restrictiveSigner.createSignature(false,
                                                         ENCODED,
                                                         relayState,
                                                         encodedSigAlg,
                                                         SIG_ALG,
                                                         SIGNATURE_KEY);

    MockHttpServletRequest mockRequest = new MockHttpServletRequest();
    mockRequest.setQueryString("SAMLResponse=" + ENCODED + "&RelayState=" + relayState + "&SigAlg=" + encodedSigAlg
                               + "&Signature=" + signature);

    assertDoesNotThrow(() -> restrictiveSigner.validateSignature(false, mockRequest, validKey()));
  }

  @Test
  void testRedirectBindingRequestWithoutRelayState()
  {
    String encodedSigAlg = UriUtils.encode(SIG_ALG.toString(), StandardCharsets.UTF_8);

    String signature = restrictiveSigner.createSignature(true, ENCODED, null, encodedSigAlg, SIG_ALG, SIGNATURE_KEY);

    MockHttpServletRequest mockRequest = createRequestWithoutRelayState(ENCODED, encodedSigAlg, signature);

    assertDoesNotThrow(() -> restrictiveSigner.validateSignature(true, mockRequest, validKey()));
  }

  @Test
  void testRedirectBindingResponseWithoutRelayState()
  {
    String encodedSigAlg = UriUtils.encode(SIG_ALG.toString(), StandardCharsets.UTF_8);

    String signature = restrictiveSigner.createSignature(false, ENCODED, null, encodedSigAlg, SIG_ALG, SIGNATURE_KEY);

    MockHttpServletRequest mockRequest = new MockHttpServletRequest();
    mockRequest.setQueryString("SAMLResponse=" + ENCODED + "&SigAlg=" + encodedSigAlg + "&Signature=" + signature);

    assertDoesNotThrow(() -> restrictiveSigner.validateSignature(false, mockRequest, validKey()));
  }

  @Test
  void validateWrongSignatureRedirect()
  {
    String relayState = "relay_state";
    String encodedSigAlg = UriUtils.encode(SIG_ALG.toString(), StandardCharsets.UTF_8);

    MockHttpServletRequest mockRequest = createRequestWithRelayState(ENCODED,
                                                                     relayState,
                                                                     encodedSigAlg,
                                                                     "WrongSignature");

    assertThrows(SignatureException.class, () -> restrictiveSigner.validateSignature(true, mockRequest, validKey()));
  }

  @Test
  void validateWrongRelayStateRedirect()
  {
    String relayState = "relay_state";
    String encodedSigAlg = UriUtils.encode(SIG_ALG.toString(), StandardCharsets.UTF_8);

    String signature = restrictiveSigner.createSignature(true,
                                                         ENCODED,
                                                         relayState,
                                                         encodedSigAlg,
                                                         SIG_ALG,
                                                         SIGNATURE_KEY);

    MockHttpServletRequest mockRequest = createRequestWithRelayState(ENCODED, "relayState", encodedSigAlg, signature);

    assertThrows(SignatureException.class, () -> restrictiveSigner.validateSignature(true, mockRequest, validKey()));
  }

  @Test
  void validateNoRelayStateRedirect()
  {
    String encodedSigAlg = UriUtils.encode(SIG_ALG.toString(), StandardCharsets.UTF_8);

    String signature = restrictiveSigner.createSignature(true, ENCODED, null, encodedSigAlg, SIG_ALG, SIGNATURE_KEY);

    MockHttpServletRequest mockRequest = createRequestWithRelayState(ENCODED, "relayState", encodedSigAlg, signature);

    assertThrows(SignatureException.class, () -> restrictiveSigner.validateSignature(true, mockRequest, validKey()));
  }

  @Test
  void testCreateSignatureForInvalidKeys()
  {
    SigningKey invalidSigningKey = null;

    String encodedSigAlg = UriUtils.encode(SIG_ALG.toString(), StandardCharsets.UTF_8);

    String signature = restrictiveSigner.createSignature(true,
                                                         ENCODED,
                                                         null,
                                                         encodedSigAlg,
                                                         SIG_ALG,
                                                         invalidSigningKey);
    Assertions.assertNull(signature);

    signature = restrictiveSigner.createSignature(true, ENCODED, null, encodedSigAlg, SIG_ALG, null);
    Assertions.assertNull(signature);
  }

  @Test
  void testValidateSignatureForInvalidKeys()
  {
    String encodedSigAlg = UriUtils.encode(SIG_ALG.toString(), StandardCharsets.UTF_8);

    String signature = restrictiveSigner.createSignature(true, ENCODED, null, encodedSigAlg, SIG_ALG, SIGNATURE_KEY);

    MockHttpServletRequest mockRequest = createRequestWithoutRelayState(ENCODED, encodedSigAlg, signature);

    SigningKey invalidSigningKey = null;

    assertThrows(SignatureException.class,
                 () -> restrictiveSigner.validateSignature(true,
                                                           mockRequest,
                                                           Collections.singletonList(invalidSigningKey)));
    assertThrows(SignatureException.class,
                 () -> restrictiveSigner.validateSignature(true, mockRequest, Collections.emptyList()));
    assertDoesNotThrow(() -> laxSigner.validateSignature(true, mockRequest, Collections.emptyList()));
  }

  @Test
  void testValidateSignatureWithoutSignatureQueryParam()
  {
    String encodedSigAlg = UriUtils.encode(SIG_ALG.toString(), StandardCharsets.UTF_8);

    MockHttpServletRequest mockRequest = new MockHttpServletRequest();
    mockRequest.setQueryString("SAMLRequest=encoded&RelayState=relayState&SigAlg=" + encodedSigAlg);

    assertThrows(SignatureException.class, () -> restrictiveSigner.validateSignature(true, mockRequest, validKey()));
    assertDoesNotThrow(() -> laxSigner.validateSignature(true, mockRequest, validKey()));
  }

  private MockHttpServletRequest createRequestWithRelayState(String encoded,
                                                             String relayState,
                                                             String encodedSigAlg,
                                                             String signature)
  {
    MockHttpServletRequest mockRequest = new MockHttpServletRequest();
    mockRequest.setQueryString("SAMLRequest=" + encoded + "&RelayState=" + relayState + "&SigAlg=" + encodedSigAlg
                               + "&Signature=" + signature);
    return mockRequest;
  }

  private MockHttpServletRequest createRequestWithoutRelayState(String encoded, String encodedSigAlg, String signature)
  {
    MockHttpServletRequest mockRequest = new MockHttpServletRequest();
    mockRequest.setQueryString("SAMLRequest=" + encoded + "&SigAlg=" + encodedSigAlg + "&Signature=" + signature);
    return mockRequest;
  }

  private List<SigningKey> validKey()
  {
    return Collections.singletonList(SIGNATURE_KEY);
  }
}
