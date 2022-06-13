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
import org.opensaml.saml.saml2.core.NameIDType;
import org.springframework.security.saml.saml2.metadata.IdentityProviderMetadata;
import org.springframework.security.saml.saml2.metadata.MetadataBase;
import org.springframework.security.saml.saml2.metadata.NameId;
import org.springframework.security.saml.saml2.metadata.ServiceProviderMetadata;
import org.w3c.dom.Node;


class ManageNameIDRequestTest extends MetadataBase
{

  @Test
  void createWithDefaults()
  {
    ManageNameIDRequest request = createManageNameIDRequest(serviceProviderMetadata, identityProviderMetadata);

    String xml = config.toXml(request);

    assertNodeCount(xml, "//samlp:ManageNameIDRequest", 1);
    Iterable<Node> nodes = getNodes(xml, "//saml2p:ManageNameIDRequest");
    assertNodeAttribute(nodes.iterator().next(), "Version", equalTo("2.0"));
    assertNodeAttribute(nodes.iterator().next(), "IssueInstant", notNullValue(String.class));
    assertNodeAttribute(nodes.iterator().next(),
                        "Destination",
                        equalTo("http://sp.localhost:8080/uaa/saml/sp/mni/alias/sp-alias"));

    assertNodeCount(xml, "//saml:NameID", 1);
    nodes = getNodes(xml, "//saml:NameID");
    assertNodeAttribute(nodes.iterator().next(), "Format", equalTo(NameIDType.PERSISTENT));
  }

  @Test
  void parseWithDefaults()
  {
    ManageNameIDRequest request = createManageNameIDRequest(serviceProviderMetadata, identityProviderMetadata);
    String xml = config.toXml(request);
    ManageNameIDRequest data = (ManageNameIDRequest)config.fromXml(xml, Collections.singletonList(spVerifying), null);

    assertNotNull(data);
    assertNotNull(data.getImplementation());
    assertNotNull(data.getSignature());
    assertTrue(data.getSignature().isValidated());

    assertNotNull(data.getId());
    assertNotNull(data.getIssueInstant());
    assertThat(data.getVersion(), equalTo("2.0"));
    assertThat(data.getDestination().getLocation(), equalTo("http://sp.localhost:8080/uaa/saml/sp/mni/alias/sp-alias"));

    assertNotNull(data.getIssuer());
    assertThat(data.getIssuer().getValue(), equalTo("http://idp.localhost:8080/uaa"));

    assertNotNull(data.getNameId());
    assertThat(data.getNameId().getFormat(), equalTo(NameId.PERSISTENT));
    assertThat(data.getNameId().getNameQualifier(), equalTo("http://idp.localhost:8080/uaa"));
    assertThat(data.getNameId().getSpNameQualifier(), equalTo("http://sp.localhost:8080/uaa"));
  }

  private ManageNameIDRequest createManageNameIDRequest(ServiceProviderMetadata sp, IdentityProviderMetadata idp)
  {
    ManageNameIDRequest request = new ManageNameIDRequest();
    request.setId("MNIRQ" + UUID.randomUUID());
    request.setIssueInstant(Instant.now());
    request.setDestination(sp.getServiceProvider().getManageNameIDService().get(0));
    request.setIssuer(new Issuer().setValue(idp.getEntityId()));
    request.setSigningKey(idp.getSigningKey(), idp.getAlgorithm(), idp.getDigest());
    request.setNameId(new NameIdPrincipal().setSpNameQualifier(sp.getEntityId())
                                           .setNameQualifier(idp.getEntityId())
                                           .setFormat(NameId.PERSISTENT)
                                           .setValue(UUID.randomUUID().toString()));
    return request;
  }

}
