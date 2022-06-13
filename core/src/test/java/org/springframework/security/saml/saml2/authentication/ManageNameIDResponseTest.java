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
package org.springframework.security.saml.saml2.authentication;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.hamcrest.core.IsNull.notNullValue;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.security.saml.util.XmlTestUtil.assertNodeAttribute;
import static org.springframework.security.saml.util.XmlTestUtil.assertNodeCount;
import static org.springframework.security.saml.util.XmlTestUtil.getNodes;

import java.time.Instant;
import java.util.Collections;
import java.util.UUID;

import org.junit.jupiter.api.Test;
import org.springframework.security.saml.saml2.metadata.IdentityProviderMetadata;
import org.springframework.security.saml.saml2.metadata.MetadataBase;
import org.springframework.security.saml.saml2.metadata.ServiceProviderMetadata;
import org.w3c.dom.Node;


class ManageNameIDResponseTest extends MetadataBase
{

  @Test
  void createWithDefaults()
  {
    ManageNameIDResponse response = createManageNameIDResponse(serviceProviderMetadata, identityProviderMetadata);

    String xml = config.toXml(response);

    assertNodeCount(xml, "//samlp:ManageNameIDResponse", 1);
    Iterable<Node> nodes = getNodes(xml, "//samlp:ManageNameIDResponse");
    assertNodeAttribute(nodes.iterator().next(), "Version", equalTo("2.0"));
    assertNodeAttribute(nodes.iterator().next(), "IssueInstant", notNullValue(String.class));

    assertNodeCount(xml, "//saml:Issuer", 1);
    assertNodeCount(xml, "//samlp:Status", 1);
  }

  @Test
  void parseWithDefaults()
  {
    ManageNameIDResponse response = createManageNameIDResponse(serviceProviderMetadata, identityProviderMetadata);
    String xml = config.toXml(response);
    ManageNameIDResponse data = (ManageNameIDResponse)config.fromXml(xml,
                                                                     Collections.singletonList(idpVerifying),
                                                                     null);

    assertNotNull(data);
    assertNotNull(data.getImplementation());
    assertNotNull(data.getSignature());
    assertTrue(data.getSignature().isValidated());

    assertNotNull(data.getId());
    assertNotNull(data.getIssueInstant());

    assertThat(data.getVersion(), equalTo("2.0"));
    assertThat(data.getInResponseTo(), equalTo("in-response-to-value"));

    assertNotNull(data.getIssuer());
    assertThat(data.getIssuer().getValue(), equalTo("http://idp.localhost:8080/uaa"));

    assertNotNull(data.getStatus());
    assertThat(data.getStatus().getCode(), equalTo(StatusCode.SUCCESS));
  }

  private ManageNameIDResponse createManageNameIDResponse(ServiceProviderMetadata sp, IdentityProviderMetadata idp)
  {
    ManageNameIDResponse response = new ManageNameIDResponse();
    response.setId("MNIR" + UUID.randomUUID());
    response.setIssueInstant(Instant.now());
    response.setInResponseTo("in-response-to-value");
    response.setIssuer(new Issuer().setValue(idp.getEntityId()));
    response.setSigningKey(sp.getSigningKey(), sp.getAlgorithm(), sp.getDigest());
    response.setStatus(new Status().setCode(StatusCode.SUCCESS));
    return response;
  }

}
