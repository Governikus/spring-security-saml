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

import java.time.Clock;

import org.joda.time.DateTime;


public abstract class AssertionCondition<T extends AssertionCondition<T, E>, E>
{

  private boolean valid = false;

  private boolean evaluated = false;

  private DateTime evaluationTime = null;

  private E evaluationCriteria = null;

  public boolean isValid()
  {
    return valid;
  }

  public DateTime getEvaluationTime()
  {
    return evaluationTime;
  }

  public E getEvaluationCriteria()
  {
    return evaluationCriteria;
  }

  @SuppressWarnings("unchecked")
  protected T _this()
  {
    return (T)this;
  }

  public boolean evaluate(E evaluationCriteria, Clock time)
  {
    this.valid = internalEvaluate(evaluationCriteria);
    this.evaluated = true;
    this.evaluationCriteria = evaluationCriteria;
    this.evaluationTime = new DateTime(time.millis());
    return valid;
  }

  protected abstract boolean internalEvaluate(E evaluationCriteria);

  public boolean wasEvaluated()
  {
    return evaluated;
  }

}
