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
package org.springframework.security.saml.provider.service.cache;

import java.io.Serializable;
import java.util.Arrays;
import java.util.List;

import org.springframework.lang.Nullable;
import org.springframework.security.saml.saml2.authentication.AuthenticationRequest;

import jakarta.servlet.http.HttpServletRequest;


public interface RequestContextCache
{

  RequestContext createRequestContext(HttpServletRequest request, AuthenticationRequest... authenticationRequests);

  RequestContext getRequestContext(HttpServletRequest request, @Nullable String relayState);

  void removeRequestContext(HttpServletRequest request, @Nullable String relayState);

  public class RequestContext implements Serializable
  {

    private static final long serialVersionUID = 1L;

    private static final String[] EMPTY_STRING_ARRAY = new String[0];

    private final String relayState;

    private List<String> authenticationRequestIds;

    public RequestContext(String relayState)
    {
      this(relayState, EMPTY_STRING_ARRAY);
    }

    public RequestContext(String relayState, String... authenticationRequestIds)
    {
      this.relayState = relayState;
      setAuthenticationRequestIds(authenticationRequestIds);
    }

    public String getRelayState()
    {
      return relayState;
    }

    public List<String> getAuthenticationRequestIds()
    {
      return authenticationRequestIds;
    }

    public void setAuthenticationRequestIds(String... authenticationRequestIds)
    {
      this.authenticationRequestIds = Arrays.asList(authenticationRequestIds);
    }

  }

}
