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

import java.util.Arrays;
import java.util.UUID;

import javax.servlet.http.HttpServletRequest;

import org.apache.commons.lang3.StringUtils;
import org.springframework.lang.Nullable;
import org.springframework.security.saml.saml2.authentication.AuthenticationRequest;


public class DefaultRequestContextCache implements RequestContextCache
{

  static final String REQUEST_CONTEXT = "SPRING_SECURITY_SAML_SP_REQUEST_CONTEXT";

  private String sessionAttrName = REQUEST_CONTEXT;

  public void setSessionAttrName(String sessionAttrName)
  {
    this.sessionAttrName = sessionAttrName;
  }

  protected String genRelayStateValue()
  {
    return UUID.randomUUID().toString();
  }

  @Override
  public RequestContext createRequestContext(HttpServletRequest request,
                                             AuthenticationRequest... authenticationRequests)
  {
    RequestContext requestContext = new RequestContext(genRelayStateValue(),
                                                       Arrays.stream(authenticationRequests)
                                                             .map(AuthenticationRequest::getId)
                                                             .toArray(String[]::new));

    request.getSession().setAttribute(sessionAttrName, requestContext);

    return requestContext;
  }

  @Override
  public RequestContext getRequestContext(HttpServletRequest request, @Nullable String relayState)
  {
    if (request != null)
    {
      RequestContext requestContext = (RequestContext)request.getSession().getAttribute(sessionAttrName);
      if (requestContext != null && StringUtils.equals(requestContext.getRelayState(), relayState))
      {
        return requestContext;
      }
      return null;
    }
    return null;
  }

  @Override
  public void removeRequestContext(HttpServletRequest request, @Nullable String relayState)
  {
    request.getSession().removeAttribute(sessionAttrName);
  }

}
