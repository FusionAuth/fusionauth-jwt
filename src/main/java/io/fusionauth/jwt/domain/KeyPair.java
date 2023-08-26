/*
 * Copyright (c) 2016-2019, FusionAuth, All Rights Reserved
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied. See the License for the specific
 * language governing permissions and limitations under the License.
 */

package io.fusionauth.jwt.domain;

import java.util.Objects;

import io.fusionauth.domain.Buildable;
import io.fusionauth.jwt.json.Mapper;
import io.fusionauth.pem.domain.PEM;

/**
 * @author Daniel DeGroff
 */
public class KeyPair implements Buildable<KeyPair> {
  public PEM pem;

  public String privateKey;

  public String publicKey;

  public KeyPair(String privateKey, String publicKey) {
    this.privateKey = privateKey;
    this.publicKey = publicKey;
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    KeyPair that = (KeyPair) o;
    return Objects.equals(pem, that.pem) &&
           Objects.equals(privateKey, that.privateKey) &&
           Objects.equals(publicKey, that.publicKey);
  }

  @Override
  public int hashCode() {
    return Objects.hash(pem, privateKey, publicKey);
  }

  @Override
  public String toString() {
    return new String(Mapper.prettyPrint(this));
  }
}
