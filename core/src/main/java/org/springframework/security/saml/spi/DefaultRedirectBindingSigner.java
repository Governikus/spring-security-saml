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

import static org.springframework.util.StringUtils.hasText;

import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.saml.SamlException;
import org.springframework.security.saml.SamlRedirectBindingSigner;
import org.springframework.security.saml.key.SigningKey;
import org.springframework.security.saml.saml2.signature.AlgorithmMethod;
import org.springframework.security.saml.saml2.signature.SignatureException;
import org.springframework.security.saml.util.X509Utilities;
import org.springframework.web.util.UriUtils;

import jakarta.servlet.http.HttpServletRequest;


public class DefaultRedirectBindingSigner implements SamlRedirectBindingSigner
{

  private static final Log LOG = LogFactory.getLog(DefaultRedirectBindingSigner.class);

  private boolean allowMissingSignature = true;

  private boolean allowMissingSignatureKeys = true;

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
  @Override
  public String createSignature(boolean isSamlRequest,
                                String encoded,
                                String encodedRelayState,
                                String encodedSigAlg,
                                AlgorithmMethod sigAlg,
                                SigningKey key)
  {
    if (key == null)
    {
      LOG.info("No key for signing HTTP Redirect-Binding request found.");
      return null;
    }

    String parameterName = isSamlRequest ? "SAMLRequest" : "SAMLResponse";
    String signatureInput = signatureInput(parameterName, encoded, encodedRelayState, encodedSigAlg);

    Signature sig;
    try
    {
      sig = Signature.getInstance(algorithm(sigAlg));
      PrivateKey pkey = X509Utilities.readPrivateKey(key.getPrivateKey(), key.getPassphrase());
      sig.initSign(pkey);
      sig.update(signatureInput.getBytes(StandardCharsets.UTF_8));
      byte[] signatureValue = sig.sign();
      return Base64.getEncoder().encodeToString(signatureValue);
    }
    catch (NoSuchAlgorithmException | InvalidKeyException | java.security.SignatureException e)
    {
      if (LOG.isErrorEnabled())
      {
        LOG.error(e.getMessage(), e);
      }
      return null;
    }
  }

  @Override
  public void validateSignature(boolean isSamlRequest, HttpServletRequest request, List<SigningKey> verificationKeys)
  {
    Map<String, String> queryParameters = getQueryParameters(request);

    String encodedSignature = queryParameters.get("Signature");
    if (!hasText(encodedSignature))
    {
      LOG.info("Signature parameter is missing from HTTP Redirect Binding request.");
      if (isAllowMissingSignature())
      {
        LOG.info("Continue because signature is not mandatory on HTTP Redirect Binding requests.");
        return;
      }
      throw new SignatureException("Signature parameter is missing from HTTP Redirect Binding request.");
    }

    List<SigningKey> signatureVerificationKeys = verificationKeys.stream()
                                                                 .filter(Objects::nonNull)
                                                                 .collect(Collectors.toList());
    if (signatureVerificationKeys.isEmpty())
    {
      LOG.info("No key for validating the signature on a HTTP Redirect-Binding request found.");
      if (isAllowMissingSignatureKeys())
      {
        LOG.info("Continue because signature validation is not mandatory on HTTP Redirect-Binding requests.");
        return;
      }
      throw new SignatureException("No key for validating the signature on a HTTP Redirect-Binding request found.");
    }

    String encodedSigAlg = queryParameters.get("SigAlg");
    AlgorithmMethod sigAlg = parseEncodedSigAlg(encodedSigAlg);

    Signature signatureInstance;
    try
    {
      signatureInstance = Signature.getInstance(algorithm(sigAlg));
    }
    catch (NoSuchAlgorithmException e)
    {
      throw new SignatureException("SigAlg parameter value is not supported: " + e.getMessage(), e);
    }

    String parameterName = isSamlRequest ? "SAMLRequest" : "SAMLResponse";
    String encoded = queryParameters.get(parameterName);
    String encodedRelayState = queryParameters.get("RelayState");
    String signatureInput = signatureInput(parameterName, encoded, encodedRelayState, encodedSigAlg);

    String signaturebase64 = UriUtils.decode(encodedSignature, StandardCharsets.UTF_8);
    byte[] signatureValue = Base64.getDecoder().decode(signaturebase64);

    checkSignatureForKeys(signatureVerificationKeys, signatureInput, signatureInstance, signatureValue);
  }

  private void checkSignatureForKeys(List<SigningKey> signatureVerificationKeys,
                                     String signatureInput,
                                     Signature signatureInstance,
                                     byte[] signatureValue)
  {
    for ( SigningKey key : signatureVerificationKeys )
    {
      byte[] certBytes = X509Utilities.getDER(key.getCertificate());

      try
      {
        X509Certificate certificate = X509Utilities.getCertificate(certBytes);
        signatureInstance.initVerify(certificate);
        signatureInstance.update(signatureInput.getBytes(StandardCharsets.UTF_8));
        boolean isValid = signatureInstance.verify(signatureValue);
        if (isValid)
        {
          if (LOG.isDebugEnabled())
          {
            LOG.debug("Signature verification for key '" + key.getName() + "' was successful.");
          }
          return;
        }
        else
        {
          if (LOG.isDebugEnabled())
          {
            LOG.debug("Signature verification for key '" + key.getName() + "' failed. Try next key.");
          }
        }
      }
      catch (CertificateException | InvalidKeyException | java.security.SignatureException e)
      {
        if (LOG.isDebugEnabled())
        {
          LOG.debug("Signature verification for key '" + key.getName() + "' failed because '" + e.getMessage()
                    + "'. Try next key.",
                    e);
        }
      }
    }

    throw new SignatureException("Signature verification failed for all keys. Signature is not valid.");
  }

  private AlgorithmMethod parseEncodedSigAlg(String sigAlgEncoded)
  {
    String sigAlg = UriUtils.decode(sigAlgEncoded, StandardCharsets.UTF_8);
    return AlgorithmMethod.fromUrn(sigAlg);
  }

  /**
   * {@link HttpServletRequest#getParameter(String)} decodes the url-encoding. To check the signature we need the
   * original url-encoded values, therefore we have to fetch the parameters from the original query string.
   */
  private Map<String, String> getQueryParameters(HttpServletRequest request)
  {
    String queryString = request.getQueryString();
    if (!hasText(queryString))
    {
      throw new SamlException("Received request via Redirect-Binding without any query parameters.");
    }

    Map<String, String> queryParameters = new HashMap<>();

    String[] parameters = queryString.split("&");
    for ( String parameter : parameters )
    {
      String[] keyValuePair = parameter.split("=");
      if (keyValuePair.length == 2)
      {
        queryParameters.put(keyValuePair[0], keyValuePair[1]);
      }
      else if (LOG.isWarnEnabled())
      {
        LOG.warn("Invalid query parameter found: " + parameter);
      }
    }
    return queryParameters;
  }

  /**
   * create signature input in one of the following ways:
   * "<code>{parameterName}=value&RelayState=value&SigAlg=value</code>" or
   * "<code>{parameterName}=value&SigAlg=value</code>"
   */
  private String signatureInput(String parameterName,
                                String encodedParameterValue,
                                String encodedRelayState,
                                String encodedSigAlg)
  {
    StringBuilder builder = new StringBuilder();
    builder.append(parameterName).append('=').append(encodedParameterValue);
    if (hasText(encodedRelayState))
    {
      builder.append("&RelayState=").append(encodedRelayState);
    }
    builder.append("&SigAlg=").append(encodedSigAlg);
    return builder.toString();
  }

  protected String algorithm(AlgorithmMethod sigAlg) throws NoSuchAlgorithmException
  {
    String securityProviderName = sigAlg.getJavaStandardAlgorithmName();
    if (securityProviderName == null)
    {
      throw new NoSuchAlgorithmException(sigAlg + " has no mapping to signature instance value.");
    }
    return securityProviderName;
  }

  public boolean isAllowMissingSignature()
  {
    return allowMissingSignature;
  }

  public DefaultRedirectBindingSigner setAllowMissingSignature(boolean allowMissingSignature)
  {
    this.allowMissingSignature = allowMissingSignature;
    return this;
  }

  public boolean isAllowMissingSignatureKeys()
  {
    return allowMissingSignatureKeys;
  }

  public DefaultRedirectBindingSigner setAllowMissingSignatureKeys(boolean allowMissingSignatureKeys)
  {
    this.allowMissingSignatureKeys = allowMissingSignatureKeys;
    return this;
  }

}
