/*
 * Copyright (c) 2017, Inversoft Inc., All Rights Reserved
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

package org.primeframework.jwt.domain;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.Objects;

/**
 * A JSON Web Key as defined by <a href="https://tools.ietf.org/html/rfc7517#section-4">RFC 7517 Section 4</a>
 *
 * @author Daniel DeGroff
 */
public class JSONWebKey {
  @JsonProperty("alg")
  public Algorithm algorithm;

  /**
   * The "e" (exponent) parameter contains the exponent value for the RSA public key.  It is represented as a
   * Base64urlUInt-encoded value.
   */
  @JsonProperty("e")
  public String exponent;

  @JsonProperty("kid")
  public String keyId;

  @JsonProperty("kty")
  public KeyType keyType;

  /**
   * The "n" (modulus) parameter contains the modulus value for the RSA public key.  It is represented as a
   * Base64urlUInt-encoded value.
   */
  @JsonProperty("n")
  public String modulus;

  public String use;

  @Override
  public boolean equals(Object o) {
    if (this == o) return true;
    if (!(o instanceof JSONWebKey)) return false;
    JSONWebKey that = (JSONWebKey) o;
    return algorithm == that.algorithm &&
        Objects.equals(exponent, that.exponent) &&
        Objects.equals(keyId, that.keyId) &&
        keyType == that.keyType &&
        Objects.equals(modulus, that.modulus) &&
        Objects.equals(use, that.use);
  }

  @Override
  public int hashCode() {
    return Objects.hash(algorithm, exponent, keyId, keyType, modulus, use);
  }
}
