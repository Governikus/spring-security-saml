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

package org.springframework.security.saml.spi.opensaml;

import static java.nio.charset.StandardCharsets.UTF_8;

import java.io.Writer;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;

import org.apache.velocity.VelocityContext;
import org.springframework.security.saml.SamlTemplateEngine;

import net.shibboleth.utilities.java.support.velocity.VelocityEngine;


public class OpenSamlVelocityEngine implements SamlTemplateEngine
{

  @Override
  public void process(HttpServletRequest request, String templateId, Map<String, Object> model, Writer out)
  {
    org.apache.velocity.app.VelocityEngine velocityEngine = VelocityEngine.newVelocityEngine();
    initializeVelocityEngine(velocityEngine);
    VelocityContext context = new VelocityContext();
    model.entrySet().stream().forEach(e -> context.put(e.getKey(), e.getValue()));

    velocityEngine.mergeTemplate(templateId, UTF_8.name(), context, out);
  }

  protected void initializeVelocityEngine(org.apache.velocity.app.VelocityEngine velocityEngine)
  {
    velocityEngine.init();
  }

}
