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

package org.springframework.security.saml.saml2.authentication;

import java.time.Instant;


/**
 * Implementation saml:SubjectConfirmationDataType as defined by
 * https://www.oasis-open.org/committees/download.php/35711/sstc-saml-core-errata-2.0-wd-06-diff.pdf Page 20, Line 810
 */
public class SubjectConfirmationData
{

  private Instant notBefore;

  private Instant notOnOrAfter;

  private String recipient;

  private String inResponseTo;

  public Instant getNotBefore()
  {
    return notBefore;
  }

  public SubjectConfirmationData setNotBefore(Instant notBefore)
  {
    this.notBefore = notBefore;
    return this;
  }

  public Instant getNotOnOrAfter()
  {
    return notOnOrAfter;
  }

  public SubjectConfirmationData setNotOnOrAfter(Instant notOnOrAfter)
  {
    this.notOnOrAfter = notOnOrAfter;
    return this;
  }

  public String getRecipient()
  {
    return recipient;
  }

  public SubjectConfirmationData setRecipient(String recipient)
  {
    this.recipient = recipient;
    return this;
  }

  public String getInResponseTo()
  {
    return inResponseTo;
  }

  public SubjectConfirmationData setInResponseTo(String inResponseTo)
  {
    this.inResponseTo = inResponseTo;
    return this;
  }
}
