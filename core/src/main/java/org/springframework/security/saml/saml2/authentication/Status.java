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

import static org.springframework.util.StringUtils.hasText;

import java.io.Serializable;

/**
 * Implementation samlp:StatusType as defined by
 * https://www.oasis-open.org/committees/download.php/35711/sstc-saml-core-errata-2.0-wd-06-diff.pdf
 * Page 39, Line 1675
 */
public class Status implements Serializable
{

  private static final long serialVersionUID = 1L;

  private StatusCode code;

  private StatusCode minorCode;

  private String message;

  private String detail;

  public StatusCode getCode()
  {
    return code;
  }

  public Status setCode(StatusCode code)
  {
    this.code = code;
    return this;
  }

  public StatusCode getMinorCode()
  {
    return minorCode;
  }

  public Status setMinorCode(StatusCode minorCode)
  {
    this.minorCode = minorCode;
    return this;
  }

  public String getMessage()
  {
    return message;
  }

  public Status setMessage(String message)
  {
    this.message = message;
    return this;
  }

  public Status setMessage(StatusCode message)
  {
    this.message = message == null ? null : message.toString();
    return this;
  }

  public String getDetail()
  {
    return detail;
  }

  public Status setDetail(String detail)
  {
    this.detail = detail;
    return this;
  }

  @Override
  public String toString()
  {
    StringBuilder sb = new StringBuilder("Status: ").append(code);
    if (minorCode != null)
    {
      sb.append("\n minor: ").append(minorCode);
    }
    if (hasText(message))
    {
      sb.append("\n message: ").append(message);
    }
    if (hasText(detail))
    {
      sb.append("\n detail: ").append(detail);
    }
    return sb.toString();
  }
}
