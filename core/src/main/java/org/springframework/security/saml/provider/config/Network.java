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
package org.springframework.security.saml.provider.config;

import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;

import javax.net.ssl.SSLContext;

import org.apache.hc.client5.http.config.RequestConfig;
import org.apache.hc.client5.http.impl.DefaultRedirectStrategy;
import org.apache.hc.client5.http.impl.classic.HttpClientBuilder;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManager;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManagerBuilder;
import org.apache.hc.client5.http.ssl.SSLConnectionSocketFactoryBuilder;
import org.apache.hc.client5.http.ssl.TrustSelfSignedStrategy;
import org.apache.hc.core5.http.ConnectionReuseStrategy;
import org.apache.hc.core5.ssl.SSLContextBuilder;
import org.apache.hc.core5.util.Timeout;
import org.springframework.http.client.ClientHttpRequestFactory;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.security.saml.SamlKeyException;
import org.springframework.web.client.RestOperations;
import org.springframework.web.client.RestTemplate;


class Network
{

  private final Timeout connectTimeoutMillis;

  private final Timeout readTimeoutMillis;

  Network(Timeout connectTimeoutMillis, Timeout readTimeoutMillis)
  {
    this.connectTimeoutMillis = connectTimeoutMillis;
    this.readTimeoutMillis = readTimeoutMillis;
  }

  public RestOperations get(boolean skipSslValidation)
  {
    return new RestTemplate(createRequestFactory(skipSslValidation));
  }

  private ClientHttpRequestFactory createRequestFactory(boolean skipSslValidation)
  {
    return createRequestFactory(getClientBuilder(skipSslValidation));
  }

  private ClientHttpRequestFactory createRequestFactory(HttpClientBuilder builder)
  {
    return new HttpComponentsClientHttpRequestFactory(builder.build());
  }

  private HttpClientBuilder getClientBuilder(boolean skipSslValidation)
  {
    HttpClientBuilder builder = HttpClients.custom()
                                           .useSystemProperties()
                                           .setRedirectStrategy(new DefaultRedirectStrategy());
    if (skipSslValidation)
    {
      builder.setConnectionManager(createHttpClientConnectionManager());
    }
    ConnectionReuseStrategy noConnectionReuseStrategy = (request, response, context) -> false;
    builder.setConnectionReuseStrategy(noConnectionReuseStrategy);
    RequestConfig config = RequestConfig.custom()
                                        .setConnectTimeout(connectTimeoutMillis)
                                        .setConnectionRequestTimeout(connectTimeoutMillis)
                                        .setResponseTimeout(readTimeoutMillis)
                                        .build();
    builder.setDefaultRequestConfig(config);
    return builder;
  }

  private SSLContext getNonValidatingSslContext()
  {
    try
    {
      return new SSLContextBuilder().loadTrustMaterial(null, new TrustSelfSignedStrategy()).build();
    }
    catch (KeyManagementException | NoSuchAlgorithmException | KeyStoreException e)
    {
      throw new SamlKeyException(e);
    }
  }

  private PoolingHttpClientConnectionManager createHttpClientConnectionManager()
  {
    return PoolingHttpClientConnectionManagerBuilder.create()
                                                    .setSSLSocketFactory(SSLConnectionSocketFactoryBuilder.create()
                                                                                                          .setSslContext(getNonValidatingSslContext())
                                                                                                          .build())
                                                    .build();
  }
}
