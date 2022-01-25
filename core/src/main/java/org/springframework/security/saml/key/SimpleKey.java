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

package org.springframework.security.saml.key;

public abstract class SimpleKey<T extends SimpleKey<T>>
{

  private String name;

  private String privateKey;

  private String certificate;

  private String passphrase;

  protected SimpleKey()
  {}

  protected SimpleKey(String name, String privateKey, String certificate, String passphrase)
  {
    this.name = name;
    this.privateKey = privateKey;
    this.certificate = certificate;
    this.passphrase = passphrase;
  }

  public String getName()
  {
    return name;
  }

  public T setName(String name)
  {
    this.name = name;
    return _this();
  }

  public String getPrivateKey()
  {
    return privateKey;
  }

  public String getCertificate()
  {
    return certificate;
  }

  public String getPassphrase()
  {
    return passphrase;
  }

  public T setPassphrase(String passphrase)
  {
    this.passphrase = passphrase;
    return _this();
  }

  public T setCertificate(String certificate)
  {
    this.certificate = certificate;
    return _this();
  }

  public T setPrivateKey(String privateKey)
  {
    this.privateKey = privateKey;
    return _this();
  }

  abstract T _this();
}
