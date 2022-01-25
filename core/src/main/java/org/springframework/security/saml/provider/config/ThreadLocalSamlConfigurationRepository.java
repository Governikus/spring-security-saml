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
package org.springframework.security.saml.provider.config;

import java.time.Clock;
import java.util.concurrent.TimeUnit;

import org.springframework.security.saml.SamlException;
import org.springframework.security.saml.provider.SamlServerConfiguration;


public class ThreadLocalSamlConfigurationRepository implements SamlConfigurationRepository
{

  private static InheritableThreadLocal<ExpiringEntry> threadLocal = new InheritableThreadLocal<>();

  private final SamlConfigurationRepository initialValueProvider;

  private final Clock clock;

  private long expirationMillis = TimeUnit.SECONDS.toMillis(10);

  public ThreadLocalSamlConfigurationRepository(SamlConfigurationRepository initialValueProvider)
  {
    this(initialValueProvider, Clock.systemUTC());
  }

  public ThreadLocalSamlConfigurationRepository(SamlConfigurationRepository initialValueProvider, Clock clock)
  {
    this.initialValueProvider = initialValueProvider;
    this.clock = clock;
  }

  @Override
  public SamlServerConfiguration getServerConfiguration()
  {
    ExpiringEntry expiringEntry = threadLocal.get();
    SamlServerConfiguration result = null;
    if (expiringEntry != null)
    {
      result = expiringEntry.getConfiguration(getExpirationMillis());
      if (result == null)
      {
        reset();
      }
    }
    if (result == null)
    {
      try
      {
        result = initialValueProvider.getServerConfiguration().clone();
      }
      catch (CloneNotSupportedException e)
      {
        throw new SamlException(e);
      }
    }
    return result;
  }

  protected void setServerConfiguration(SamlServerConfiguration configuration)
  {
    if (configuration == null)
    {
      reset();
    }
    else
    {
      threadLocal.set(new ExpiringEntry(clock, configuration));
    }
  }

  public void reset()
  {
    threadLocal.remove();
  }

  public long getExpirationMillis()
  {
    return expirationMillis;
  }

  public ThreadLocalSamlConfigurationRepository setExpirationMillis(long expirationMillis)
  {
    this.expirationMillis = expirationMillis;
    return this;
  }

  private static class ExpiringEntry
  {

    private Clock clock;

    private long created;

    private SamlServerConfiguration configuration;

    public ExpiringEntry(Clock clock, SamlServerConfiguration configuration)
    {
      this.clock = clock;
      setConfiguration(configuration);
    }

    public long getCreated()
    {
      return created;
    }

    public void setConfiguration(SamlServerConfiguration configuration)
    {
      this.configuration = configuration;
      created = configuration == null ? 0 : clock.millis();
    }

    public SamlServerConfiguration getConfiguration(long expiration)
    {
      if (created + expiration > clock.millis())
      {
        return configuration;
      }
      else
      {
        return null;
      }
    }
  }
}
