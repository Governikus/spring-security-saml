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
/*
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

package org.springframework.security.saml.impl;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;

import java.time.Clock;
import java.util.UUID;

import org.junit.jupiter.api.Test;
import org.springframework.security.saml.spi.SpringSecuritySaml;
import org.springframework.security.saml.spi.opensaml.OpenSamlImplementation;


class SpringSecuritySamlTests
{

  private SpringSecuritySaml<OpenSamlImplementation> instance = new OpenSamlImplementation(Clock.systemUTC());

  @Test
  void init_works()
  {
    instance.init();
  }

  @Test
  void multipe_calls_to_init_works()
  {
    instance.init();
    instance.init();
  }

  @Test
  void deflate_inflate()
  {
    SpringSecuritySaml<OpenSamlImplementation> saml = instance.init();
    String s = "inflate_deflate_tests_" + UUID.randomUUID().toString();
    String deflated = saml.encode(saml.deflate(s));
    String inflated = saml.inflate(saml.decode(deflated));
    assertThat(inflated, equalTo(s));
  }
}
