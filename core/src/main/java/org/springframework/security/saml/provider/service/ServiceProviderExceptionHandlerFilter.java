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
package org.springframework.security.saml.provider.service;

import java.io.IOException;
import java.util.Collections;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.saml.provider.SamlFilter;
import org.springframework.security.saml.provider.provisioning.SamlProviderProvisioning;
import org.springframework.security.saml.provider.service.config.ExternalIdentityProviderConfiguration;
import org.springframework.security.saml.provider.service.config.LocalServiceProviderConfiguration;
import org.springframework.security.saml.saml2.metadata.IdentityProviderMetadata;
import org.springframework.security.saml.saml2.metadata.ServiceProviderMetadata;


/**
 * this filter catches uncaught exceptions and prevents display of exceptions in browser
 */
public class ServiceProviderExceptionHandlerFilter extends SamlFilter
{

  private static final Log LOG = LogFactory.getLog(ServiceProviderExceptionHandlerFilter.class);

  public ServiceProviderExceptionHandlerFilter(SamlProviderProvisioning<HostedServiceProviderService, LocalServiceProviderConfiguration, ServiceProviderMetadata, IdentityProviderMetadata, ExternalIdentityProviderConfiguration> provisioning)
  {
    super(provisioning);
  }

  /**
   * handle unexpected exceptions during the filter chain
   */
  @Override
  protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
    throws ServletException, IOException
  {
    try
    {
      filterChain.doFilter(request, response);
    }
    catch (Exception e)
    {
      if (LOG.isErrorEnabled())
      {
        LOG.error("An unexpected error occured during the filter chain:");
        LOG.error(e.getMessage(), e);
      }
      displayErrorTemplate(request, response, e);
    }
  }

  protected void displayErrorTemplate(HttpServletRequest request, HttpServletResponse response, Exception e)
  {
    if (LOG.isErrorEnabled())
    {
      LOG.error(e.getMessage());
    }
    processHtml(request, response, getErrorTemplate(), Collections.singletonMap("message", e.getMessage()));
  }

}
