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
package org.springframework.security.saml.validation;

import java.util.Arrays;

import org.springframework.security.saml.SamlException;


public class ValidationException extends SamlException
{

  private static final long serialVersionUID = 1L;

  private final ValidationResult errors;

  public ValidationException(String message, ValidationResult errors)
  {
    super(message);
    this.errors = errors;
  }

  public ValidationResult getErrors()
  {
    return errors;
  }

  @Override
  public String getMessage()
  {
    return errors == null ? super.getMessage() : errors.toString();
  }

  @Override
  public String toString()
  {
    String errorText = errors == null ? "none" : Arrays.toString(errors.getErrors().toArray());
    return "ValidationException{errors=" + errorText + '}';
  }
}
