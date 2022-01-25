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
package org.springframework.security.saml.key;

import org.springframework.security.saml.saml2.encrypt.DataEncryptionMethod;


public class EncryptionKey extends SimpleKey<EncryptionKey>
{

  private DataEncryptionMethod dataEncryptionMethod;

  public EncryptionKey()
  {
    super();
  }

  public EncryptionKey(String name, String certificate)
  {
    this(name, null, certificate, null);
  }

  public EncryptionKey(String name, String privateKey, String certificate, String passphrase)
  {
    super(name, privateKey, certificate, passphrase);
  }

  public DataEncryptionMethod getDataEncryptionMethod()
  {
    return dataEncryptionMethod;
  }

  public EncryptionKey setDataEncryptionMethod(DataEncryptionMethod dataEncryptionMethod)
  {
    this.dataEncryptionMethod = dataEncryptionMethod;
    return _this();
  }

  @Override
  EncryptionKey _this()
  {
    return this;
  }

}
