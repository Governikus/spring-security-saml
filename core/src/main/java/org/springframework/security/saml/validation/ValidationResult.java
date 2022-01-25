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

import java.io.Serializable;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;

import org.springframework.security.saml.saml2.Saml2Object;
import org.springframework.security.saml.saml2.authentication.Status;


public class ValidationResult implements Serializable
{

  private static final long serialVersionUID = 1L;

  private final transient Saml2Object saml2Object;

  private Status errorStatus;

  private final List<ValidationError> errors = new LinkedList<>();

  public ValidationResult(Saml2Object saml2Object)
  {
    this.saml2Object = saml2Object;
  }

  public Saml2Object getSaml2Object()
  {
    return saml2Object;
  }

  public static class ValidationError implements Serializable
  {

    private static final long serialVersionUID = 1L;

    private final String message;

    public ValidationError(String message)
    {
      this.message = message;
    }

    public String getMessage()
    {
      return message;
    }

    @Override
    public String toString()
    {
      return message;
    }
  }

  @Override
  public String toString()
  {
    final StringBuilder sb = new StringBuilder("Validation Errors: ");
    if (hasErrors())
    {
      for ( int i = 0 ; i < getErrors().size() ; i++ )
      {
        sb.append("\n");
        ValidationError error = getErrors().get(i);
        sb.append(i + 1);
        sb.append(". ");
        sb.append(error.getMessage());
      }
    }
    else
    {
      sb.append("None");
    }

    return sb.toString();
  }

  public ValidationResult addError(String error)
  {
    errors.add(new ValidationError(error));
    return this;
  }

  public ValidationResult addError(ValidationError error)
  {
    errors.add(error);
    return this;
  }

  public List<ValidationError> getErrors()
  {
    return Collections.unmodifiableList(errors);
  }

  public boolean hasErrors()
  {
    return !errors.isEmpty();
  }

  public ValidationResult setErrorStatus(Status errorStatus)
  {
    this.errorStatus = errorStatus;
    return this;
  }

  public Status getErrorStatus()
  {
    return errorStatus;
  }

}
