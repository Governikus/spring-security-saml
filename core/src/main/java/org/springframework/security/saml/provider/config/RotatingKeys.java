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

package org.springframework.security.saml.provider.config;

import static org.springframework.util.StringUtils.hasText;

import java.util.LinkedList;
import java.util.List;

import org.springframework.security.saml.key.SimpleKey;


public abstract class RotatingKeys<T extends RotatingKeys<T, K>, K extends SimpleKey<K>>
{

  private K active = null;

  private List<K> standBy = new LinkedList<>();

  public List<K> toList()
  {
    LinkedList<K> result = new LinkedList<>();
    result.add(getActive());
    result.addAll(getStandBy());
    return result;
  }

  public K getActive()
  {
    return active;
  }

  public T setActive(K active)
  {
    this.active = active;
    if (!hasText(active.getName()))
    {
      active.setName("active-signing-key");
    }
    return _this();
  }

  public List<K> getStandBy()
  {
    return standBy;
  }

  public T setStandBy(List<K> standBy)
  {
    this.standBy = standBy;
    return _this();
  }

  abstract T _this();
}
