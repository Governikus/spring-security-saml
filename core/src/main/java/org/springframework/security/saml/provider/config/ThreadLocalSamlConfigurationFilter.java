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
package org.springframework.security.saml.provider.config;

import static java.util.Arrays.asList;
import static org.springframework.util.StringUtils.hasText;

import java.io.IOException;

import org.springframework.security.saml.provider.SamlServerConfiguration;
import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;


public class ThreadLocalSamlConfigurationFilter extends OncePerRequestFilter
{

  private final ThreadLocalSamlConfigurationRepository repository;

  private boolean includeStandardPortsInUrl = false;

  public ThreadLocalSamlConfigurationFilter(ThreadLocalSamlConfigurationRepository repository)
  {
    this.repository = repository;
  }

  @Override
  protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
    throws ServletException, IOException
  {
    SamlServerConfiguration configuration = getConfiguration(request);
    // allow for dynamic host paths
    if (configuration != null)
    {
      for ( LocalProviderConfiguration<?, ?> config : asList(configuration.getIdentityProvider(),
                                                             configuration.getServiceProvider()) )
      {
        if (config != null && !hasText(config.getBasePath()))
        {
          config.setBasePath(getBasePath(request));
        }
      }
    }
    try
    {
      repository.setServerConfiguration(configuration);
      filterChain.doFilter(request, response);
    }
    finally
    {
      repository.reset();
    }
  }

  protected SamlServerConfiguration getConfiguration(HttpServletRequest request)
  {
    return repository.getServerConfiguration();
  }

  protected String getBasePath(HttpServletRequest request)
  {
    boolean includePort = true;
    if (443 == request.getServerPort() && "https".equals(request.getScheme()))
    {
      includePort = isIncludeStandardPortsInUrl();
    }
    else if (80 == request.getServerPort() && "http".equals(request.getScheme()))
    {
      includePort = isIncludeStandardPortsInUrl();
    }
    return request.getScheme() + "://" + request.getServerName() + (includePort ? ":" + request.getServerPort() : "")
           + request.getContextPath();
  }

  public boolean isIncludeStandardPortsInUrl()
  {
    return includeStandardPortsInUrl;
  }

  public ThreadLocalSamlConfigurationFilter setIncludeStandardPortsInUrl(boolean includeStandardPortsInUrl)
  {
    this.includeStandardPortsInUrl = includeStandardPortsInUrl;
    return this;
  }
}
