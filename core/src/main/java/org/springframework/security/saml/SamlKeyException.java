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

package org.springframework.security.saml;

public class SamlKeyException extends SamlException
{

  private static final long serialVersionUID = 1L;

  public SamlKeyException(String message)
  {
    super(message);
  }

  public SamlKeyException(String message, Throwable cause)
  {
    super(message, cause);
  }

  public SamlKeyException(Throwable cause)
  {
    super(cause);
  }
}
