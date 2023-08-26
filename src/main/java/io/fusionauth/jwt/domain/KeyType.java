/*
 * Copyright (c) 2016-2023, FusionAuth, All Rights Reserved
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
import java.util.ServiceLoader;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;
import io.fusionauth.der.ObjectIdentifier;
import io.fusionauth.jwt.UnsupportedKeyTypeException;
import io.fusionauth.jwt.UnsupportedObjectIdentifierException;
import io.fusionauth.jwt.json.Mapper;
import io.fusionauth.jwt.spi.KeyTypeProvider;

/**
 * Available Cryptographic Algorithms for Keys as described in <a href="https://tools.ietf.org/html/rfc7518#section-6.1">RFC
 * 7518 Section 6.1</a>.
 *
 * <ul> <li>ES Elliptic Curve [DDS]</li> <li>RSA as defined by  <a href="https://tools.ietf.org/html/rfc3447">RFC
 * 3447</a></li> <li>oct: Octet Sequence (used to represent symmetric keys)</li> </ul>
 * <p>
 * Currently only the RSA and EC Key Types is implemented and supported in this library.
 * </p>
 *
 * @author Daniel DeGroff
 */
public class KeyType {
  public static final KeyType EC = new KeyType("EC", "EC", ObjectIdentifier.EC_ENCRYPTION);

  public static final KeyType RSA = new KeyType("RSA", "RSA", ObjectIdentifier.RSA_ENCRYPTION);

  private static final ServiceLoader<KeyTypeProvider> loader = ServiceLoader.load(KeyTypeProvider.class);

  public final String algorithm;

  @JsonValue
  public final String name;

  public final String oid;

  public KeyType(String name, String algorithm, String oid) {
    this.name = name;
    this.algorithm = algorithm;
    this.oid = oid;
  }

  @JsonCreator
  public static KeyType lookupByName(String name) {
    Objects.requireNonNull(name);
    for (KeyTypeProvider provider : loader) {
      KeyType keyType = provider.get();
      if (provider.get().name.equals(name)) {
        return keyType;
      }
    }

    throw new UnsupportedKeyTypeException("No KeyType has been registered for type [" + name + "].");
  }

  public static KeyType lookupByOID(String oid) {
    Objects.requireNonNull(oid);
    for (KeyTypeProvider provider : loader) {
      KeyType keyType = provider.get();
      if (provider.get().oid.equals(oid)) {
        return keyType;
      }
    }

    throw new UnsupportedObjectIdentifierException("No KeyType has been registered for OID [" + oid + "].");
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    KeyType keyType = (KeyType) o;
    return Objects.equals(algorithm, keyType.algorithm) && Objects.equals(name, keyType.name) && Objects.equals(oid, keyType.oid);
  }

  @Override
  public int hashCode() {
    return Objects.hash(algorithm, name, oid);
  }

  @Override
  public String toString() {
    return new String(Mapper.prettyPrint(this));
  }
}
